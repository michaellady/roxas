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
	"strings"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
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

// EC2Client interface for testing
type EC2Client interface {
	DescribeNetworkInterfaces(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	DeleteNetworkInterface(ctx context.Context, params *ec2.DeleteNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error)
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DeleteSecurityGroup(ctx context.Context, params *ec2.DeleteSecurityGroupInput, optFns ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error)
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
	ec2Client   EC2Client
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

	action := event.Action
	if action == "" {
		action = "drop"
	}

	// Initialize AWS config for clients
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

	// Initialize clients if not set (allows injection for testing)
	if smClient == nil {
		smClient = secretsmanager.NewFromConfig(cfg)
	}
	if ec2Client == nil {
		ec2Client = ec2.NewFromConfig(cfg)
	}

	// Dispatch based on action
	switch action {
	case "drop":
		return handleDropDatabase(ctx, event.PRNumber)
	case "cleanup_enis":
		return handleCleanupENIs(ctx, event.PRNumber)
	case "cleanup_sgs":
		return handleCleanupSGs(ctx, event.PRNumber)
	case "cleanup_all":
		return handleCleanupAll(ctx, event.PRNumber)
	default:
		return Response{
			StatusCode: 400,
			Body: ResponseBody{
				Message: fmt.Sprintf("Unknown action: %s", action),
				Action:  "error",
			},
		}, nil
	}
}

// handleDropDatabase drops the PR database from shared RDS
func handleDropDatabase(ctx context.Context, prNumber int) (Response, error) {
	dbName := fmt.Sprintf("pr_%d", prNumber)

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
	prStr := strconv.Itoa(prNumber)
	for _, c := range prStr {
		if c < '0' || c > '9' {
			return Response{
				StatusCode: 400,
				Body: ResponseBody{
					Message:  fmt.Sprintf("Invalid pr_number: %d", prNumber),
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

// handleCleanupENIs deletes orphaned ENIs for a PR
func handleCleanupENIs(ctx context.Context, prNumber int) (Response, error) {
	pattern := fmt.Sprintf("*roxas*pr-%d*", prNumber)
	log.Printf("Cleaning up ENIs matching description pattern: %s", pattern)

	// Find ENIs matching the PR pattern
	describeInput := &ec2.DescribeNetworkInterfacesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("description"),
				Values: []string{pattern},
			},
		},
	}

	result, err := ec2Client.DescribeNetworkInterfaces(ctx, describeInput)
	if err != nil {
		log.Printf("Error describing ENIs: %v", err)
		return Response{
			StatusCode: 500,
			Body: ResponseBody{
				Message: fmt.Sprintf("Error describing ENIs: %v", err),
				Action:  "error",
			},
		}, nil
	}

	deletedCount := 0
	skippedCount := 0
	var deleteErrors []string

	for _, eni := range result.NetworkInterfaces {
		eniID := *eni.NetworkInterfaceId

		// Only delete ENIs that are "available" (not in-use)
		if eni.Status != types.NetworkInterfaceStatusAvailable {
			log.Printf("Skipping ENI %s - status is %s (not available)", eniID, eni.Status)
			skippedCount++
			continue
		}

		log.Printf("Deleting available ENI: %s", eniID)
		_, err := ec2Client.DeleteNetworkInterface(ctx, &ec2.DeleteNetworkInterfaceInput{
			NetworkInterfaceId: &eniID,
		})
		if err != nil {
			log.Printf("Error deleting ENI %s: %v", eniID, err)
			deleteErrors = append(deleteErrors, fmt.Sprintf("%s: %v", eniID, err))
			continue
		}
		deletedCount++
	}

	msg := fmt.Sprintf("ENI cleanup complete: %d deleted, %d skipped (in-use)", deletedCount, skippedCount)
	if len(deleteErrors) > 0 {
		msg += fmt.Sprintf(", %d errors: %s", len(deleteErrors), strings.Join(deleteErrors, "; "))
		log.Print(msg)
		return Response{
			StatusCode: 500,
			Body: ResponseBody{
				Message: msg,
				Action:  "error",
			},
		}, nil
	}

	log.Print(msg)
	return Response{
		StatusCode: 200,
		Body: ResponseBody{
			Message: msg,
			Action:  "enis_cleaned",
		},
	}, nil
}

// handleCleanupSGs deletes orphaned security groups for a PR
func handleCleanupSGs(ctx context.Context, prNumber int) (Response, error) {
	pattern := fmt.Sprintf("roxas*pr-%d*", prNumber)
	log.Printf("Cleaning up security groups matching group-name pattern: %s", pattern)

	// Find security groups matching the PR pattern
	describeInput := &ec2.DescribeSecurityGroupsInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("group-name"),
				Values: []string{pattern},
			},
		},
	}

	result, err := ec2Client.DescribeSecurityGroups(ctx, describeInput)
	if err != nil {
		log.Printf("Error describing security groups: %v", err)
		return Response{
			StatusCode: 500,
			Body: ResponseBody{
				Message: fmt.Sprintf("Error describing security groups: %v", err),
				Action:  "error",
			},
		}, nil
	}

	deletedCount := 0
	skippedCount := 0
	var deleteErrors []string

	for _, sg := range result.SecurityGroups {
		sgID := *sg.GroupId
		sgName := *sg.GroupName

		// Check if any ENIs are using this security group
		eniCheck := &ec2.DescribeNetworkInterfacesInput{
			Filters: []types.Filter{
				{
					Name:   aws.String("group-id"),
					Values: []string{sgID},
				},
			},
		}

		eniResult, err := ec2Client.DescribeNetworkInterfaces(ctx, eniCheck)
		if err != nil {
			log.Printf("Error checking ENIs for SG %s: %v", sgID, err)
			deleteErrors = append(deleteErrors, fmt.Sprintf("%s: %v", sgID, err))
			continue
		}

		if len(eniResult.NetworkInterfaces) > 0 {
			log.Printf("Skipping SG %s (%s) - %d ENI(s) still using it", sgID, sgName, len(eniResult.NetworkInterfaces))
			skippedCount++
			continue
		}

		log.Printf("Deleting orphaned security group: %s (%s)", sgID, sgName)
		_, err = ec2Client.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{
			GroupId: &sgID,
		})
		if err != nil {
			log.Printf("Error deleting SG %s: %v", sgID, err)
			deleteErrors = append(deleteErrors, fmt.Sprintf("%s: %v", sgID, err))
			continue
		}
		deletedCount++
	}

	msg := fmt.Sprintf("SG cleanup complete: %d deleted, %d skipped (in-use)", deletedCount, skippedCount)
	if len(deleteErrors) > 0 {
		msg += fmt.Sprintf(", %d errors: %s", len(deleteErrors), strings.Join(deleteErrors, "; "))
		log.Print(msg)
		return Response{
			StatusCode: 500,
			Body: ResponseBody{
				Message: msg,
				Action:  "error",
			},
		}, nil
	}

	log.Print(msg)
	return Response{
		StatusCode: 200,
		Body: ResponseBody{
			Message: msg,
			Action:  "sgs_cleaned",
		},
	}, nil
}

// handleCleanupAll cleans up both ENIs and security groups for a PR
func handleCleanupAll(ctx context.Context, prNumber int) (Response, error) {
	log.Printf("Running full cleanup for PR %d", prNumber)

	// First clean up ENIs (must be done before SGs)
	eniResp, err := handleCleanupENIs(ctx, prNumber)
	if err != nil {
		return eniResp, err
	}
	if eniResp.StatusCode != 200 {
		return eniResp, nil
	}

	// Then clean up security groups
	sgResp, err := handleCleanupSGs(ctx, prNumber)
	if err != nil {
		return sgResp, err
	}
	if sgResp.StatusCode != 200 {
		return sgResp, nil
	}

	msg := fmt.Sprintf("Full cleanup complete. ENIs: %s | SGs: %s", eniResp.Body.Message, sgResp.Body.Message)
	log.Print(msg)
	return Response{
		StatusCode: 200,
		Body: ResponseBody{
			Message: msg,
			Action:  "all_cleaned",
		},
	}, nil
}

func main() {
	lambda.Start(handler)
}
