// Package main implements the PR database cleanup Lambda.
// Runs inside VPC to access private RDS instance.
// Invoked by GitHub Actions workflow when PR is closed.
//
// Expected event:
//
//	{"pr_number": 123, "action": "drop"}
//
// Response:
//
//	{"statusCode": 200, "body": {"message": "...", "database": "pr_123", "action": "dropped|skipped|error"}}
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Request is the expected Lambda event format
type Request struct {
	PRNumber int    `json:"pr_number"`
	Action   string `json:"action"`
}

// ResponseBody is the body of the Lambda response
type ResponseBody struct {
	Message  string `json:"message"`
	Database string `json:"database"`
	Action   string `json:"action"`
}

// Response is the Lambda response format
type Response struct {
	StatusCode int          `json:"statusCode"`
	Body       ResponseBody `json:"body"`
}

// DBCredentials from Secrets Manager
type DBCredentials struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// SecretsManagerClient interface for testing
type SecretsManagerClient interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// DBConnector interface for testing
type DBConnector interface {
	Connect(ctx context.Context, connString string) (DBConn, error)
}

// DBConn interface for testing database connections
type DBConn interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Close(ctx context.Context) error
}

// PgxConnector implements DBConnector using real pgx
type PgxConnector struct{}

// PgxConn wraps *pgx.Conn to implement DBConn
type PgxConn struct {
	conn *pgx.Conn
}

func (c *PgxConnector) Connect(ctx context.Context, connString string) (DBConn, error) {
	conn, err := pgx.Connect(ctx, connString)
	if err != nil {
		return nil, err
	}
	return &PgxConn{conn: conn}, nil
}

func (c *PgxConn) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return c.conn.Query(ctx, sql, args...)
}

func (c *PgxConn) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return c.conn.Exec(ctx, sql, args...)
}

func (c *PgxConn) Close(ctx context.Context) error {
	return c.conn.Close(ctx)
}

var (
	smClient    SecretsManagerClient
	dbConnector DBConnector = &PgxConnector{}
)

func getDBCredentials(ctx context.Context) (*DBCredentials, error) {
	secretName := os.Getenv("DB_SECRET_NAME")
	if secretName == "" {
		return nil, fmt.Errorf("DB_SECRET_NAME environment variable not set")
	}

	output, err := smClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &secretName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	var creds DBCredentials
	if err := json.Unmarshal([]byte(*output.SecretString), &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials: %w", err)
	}

	return &creds, nil
}

func handler(ctx context.Context, event Request) (Response, error) {
	eventJSON, _ := json.Marshal(event)
	log.Printf("Received event: %s", string(eventJSON))

	// Initialize AWS client if not set (allows injection for testing)
	if smClient == nil {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return Response{
				StatusCode: 500,
				Body: ResponseBody{
					Message: fmt.Sprintf("failed to load AWS config: %v", err),
					Action:  "error",
				},
			}, nil
		}
		smClient = secretsmanager.NewFromConfig(cfg)
	}

	// Validate input
	if event.PRNumber == 0 {
		return Response{
			StatusCode: 400,
			Body: ResponseBody{
				Message: "pr_number is required",
				Action:  "error",
			},
		}, nil
	}

	dbName := fmt.Sprintf("pr_%d", event.PRNumber)
	action := event.Action
	if action == "" {
		action = "drop"
	}

	if action != "drop" {
		return Response{
			StatusCode: 400,
			Body: ResponseBody{
				Message:  fmt.Sprintf("Unknown action: %s", action),
				Database: dbName,
				Action:   "error",
			},
		}, nil
	}

	// Get credentials
	creds, err := getDBCredentials(ctx)
	if err != nil {
		log.Printf("Error getting credentials: %v", err)
		return Response{
			StatusCode: 500,
			Body: ResponseBody{
				Message:  fmt.Sprintf("Error: %v", err),
				Database: dbName,
				Action:   "error",
			},
		}, nil
	}

	// Connect to postgres database (not the PR database)
	connString := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=require",
		creds.Host, creds.Port, creds.Username, creds.Password)

	conn, err := dbConnector.Connect(ctx, connString)
	if err != nil {
		log.Printf("Error connecting to database: %v", err)
		return Response{
			StatusCode: 500,
			Body: ResponseBody{
				Message:  fmt.Sprintf("Error connecting to database: %v", err),
				Database: dbName,
				Action:   "error",
			},
		}, nil
	}
	defer conn.Close(ctx)

	// Check if database exists
	rows, err := conn.Query(ctx, "SELECT 1 FROM pg_database WHERE datname = $1", dbName)
	if err != nil {
		log.Printf("Error checking database existence: %v", err)
		return Response{
			StatusCode: 500,
			Body: ResponseBody{
				Message:  fmt.Sprintf("Error: %v", err),
				Database: dbName,
				Action:   "error",
			},
		}, nil
	}

	exists := rows.Next()
	rows.Close()

	if !exists {
		log.Printf("Database %s does not exist, skipping", dbName)
		return Response{
			StatusCode: 200,
			Body: ResponseBody{
				Message:  fmt.Sprintf("Database %s does not exist", dbName),
				Database: dbName,
				Action:   "skipped",
			},
		}, nil
	}

	// Terminate existing connections to the database
	log.Printf("Terminating connections to %s", dbName)
	_, err = conn.Exec(ctx, `
		SELECT pg_terminate_backend(pid)
		FROM pg_stat_activity
		WHERE datname = $1 AND pid <> pg_backend_pid()
	`, dbName)
	if err != nil {
		log.Printf("Warning: error terminating connections: %v", err)
	}

	// Validate pr_number contains only digits (sanitization for DROP DATABASE)
	prStr := strconv.Itoa(event.PRNumber)
	for _, c := range prStr {
		if c < '0' || c > '9' {
			return Response{
				StatusCode: 400,
				Body: ResponseBody{
					Message:  fmt.Sprintf("Invalid pr_number: %d", event.PRNumber),
					Database: dbName,
					Action:   "error",
				},
			}, nil
		}
	}

	// Drop the database
	// Note: Can't use parameters for database names in DROP DATABASE
	// dbName is safe because it's "pr_" + validated integer (validated above)
	// Using quoted identifier for defense-in-depth: DROP DATABASE IF EXISTS "pr_123"
	log.Printf("Dropping database %s", dbName)

	_, err = conn.Exec(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS \"%s\"", dbName))
	if err != nil {
		log.Printf("Error dropping database: %v", err)
		return Response{
			StatusCode: 500,
			Body: ResponseBody{
				Message:  fmt.Sprintf("Error dropping database: %v", err),
				Database: dbName,
				Action:   "error",
			},
		}, nil
	}

	log.Printf("Successfully dropped database %s", dbName)
	return Response{
		StatusCode: 200,
		Body: ResponseBody{
			Message:  fmt.Sprintf("Successfully dropped database %s", dbName),
			Database: dbName,
			Action:   "dropped",
		},
	}, nil
}

func main() {
	lambda.Start(handler)
}
