package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	"github.com/mikelady/roxas/internal/clients"
	"github.com/mikelady/roxas/internal/database"
	"github.com/mikelady/roxas/internal/models"
	"github.com/mikelady/roxas/internal/orchestrator"
	"github.com/mikelady/roxas/internal/services"
)

// Global database pool (reused across Lambda invocations)
var dbPool *database.Pool

// Config holds application configuration from environment variables
type Config struct {
	OpenAIAPIKey        string
	LinkedInAccessToken string
	WebhookSecret       string
	DBSecretName        string
}

// loadConfig loads configuration from environment variables
func loadConfig() Config {
	return Config{
		OpenAIAPIKey:        os.Getenv("OPENAI_API_KEY"),
		LinkedInAccessToken: os.Getenv("LINKEDIN_ACCESS_TOKEN"),
		WebhookSecret:       os.Getenv("WEBHOOK_SECRET"),
		DBSecretName:        os.Getenv("DB_SECRET_NAME"),
	}
}

// validateConfig checks if all required environment variables are set
func validateConfig(config Config) error {
	if config.WebhookSecret == "" {
		return fmt.Errorf("WEBHOOK_SECRET is required")
	}
	// OpenAI and LinkedIn tokens are optional for signature validation
	// but required for processing
	return nil
}

// Handler is the Lambda function handler
func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	log.Printf("Received webhook request: %s %s", request.HTTPMethod, request.Path)

	// Load configuration
	config := loadConfig()

	// Validate webhook secret is set
	if err := validateConfig(config); err != nil {
		log.Printf("Configuration error: %v", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf("Configuration error: %v", err),
		}, nil
	}

	// Validate webhook signature
	signature := request.Headers["X-Hub-Signature-256"]
	if signature == "" {
		// Try lowercase header name (API Gateway sometimes normalizes)
		signature = request.Headers["x-hub-signature-256"]
	}

	if signature == "" {
		log.Println("Missing signature header")
		return events.APIGatewayProxyResponse{
			StatusCode: 401,
			Body:       "Missing signature",
		}, nil
	}

	// Validate signature
	if !validateSignature([]byte(request.Body), signature, config.WebhookSecret) {
		log.Println("Invalid signature")
		return events.APIGatewayProxyResponse{
			StatusCode: 401,
			Body:       "Invalid signature",
		}, nil
	}

	// Parse webhook payload
	commit, err := extractCommitFromWebhook([]byte(request.Body))
	if err != nil {
		log.Printf("Failed to parse webhook: %v", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       fmt.Sprintf("Invalid webhook payload: %v", err),
		}, nil
	}

	// Check if we have API credentials for processing
	if config.OpenAIAPIKey == "" || config.LinkedInAccessToken == "" {
		log.Println("Missing API credentials - webhook accepted but not processed")
		return events.APIGatewayProxyResponse{
			StatusCode: 200,
			Body:       "Webhook received (credentials missing for processing)",
		}, nil
	}

	// Initialize API clients
	openAIClient := clients.NewOpenAIClient(config.OpenAIAPIKey, "")
	linkedInClient := clients.NewLinkedInClient(config.LinkedInAccessToken, "")

	// Initialize services
	summarizer := services.NewSummarizer(openAIClient)
	imageGenerator := services.NewImageGenerator(openAIClient)
	linkedInPoster := services.NewLinkedInPoster(linkedInClient, config.LinkedInAccessToken)

	// Initialize orchestrator
	orch := orchestrator.NewOrchestrator(summarizer, imageGenerator, linkedInPoster)

	// Process commit synchronously (Lambda freezes goroutines when handler returns)
	postURL, err := orch.ProcessCommit(*commit)
	if err != nil {
		log.Printf("Error processing commit: %v", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Body: fmt.Sprintf(`{"error": "Failed to process commit: %v"}`, err),
		}, nil
	}

	log.Printf("Successfully posted to LinkedIn: %s", postURL)

	// Return 200 with success
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: fmt.Sprintf(`{"message": "Webhook processed successfully", "linkedin_url": "%s"}`, postURL),
	}, nil
}

// validateSignature verifies the GitHub webhook HMAC signature
func validateSignature(payload []byte, signature string, secret string) bool {
	// Remove "sha256=" prefix if present
	signature = strings.TrimPrefix(signature, "sha256=")

	// Compute expected signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	// Compare
	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

// GitHubWebhookPayload represents the GitHub webhook JSON structure
type GitHubWebhookPayload struct {
	Repository struct {
		HTMLURL string `json:"html_url"`
	} `json:"repository"`
	Commits []struct {
		ID      string `json:"id"`
		Message string `json:"message"`
		Author  struct {
			Name string `json:"name"`
		} `json:"author"`
	} `json:"commits"`
}

// extractCommitFromWebhook parses GitHub webhook payload and extracts commit info
func extractCommitFromWebhook(payload []byte) (*models.Commit, error) {
	var webhook GitHubWebhookPayload

	err := json.Unmarshal(payload, &webhook)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	if len(webhook.Commits) == 0 {
		return nil, fmt.Errorf("no commits in webhook payload")
	}

	// Get the first commit (most recent)
	firstCommit := webhook.Commits[0]

	commit := &models.Commit{
		Message: firstCommit.Message,
		Author:  firstCommit.Author.Name,
		RepoURL: webhook.Repository.HTMLURL,
		Diff:    "", // Not fetching diff for MVP
	}

	return commit, nil
}

func main() {
	ctx := context.Background()

	// Load configuration
	config := loadConfig()

	// Initialize database connection if secret name is provided
	if config.DBSecretName != "" {
		log.Printf("Loading database credentials from Secrets Manager: %s", config.DBSecretName)

		dbConfig, err := database.LoadConfigFromSecretsManager(ctx, config.DBSecretName)
		if err != nil {
			log.Printf("Warning: Failed to load database config: %v", err)
			log.Println("Continuing without database connection")
		} else {
			pool, err := database.NewPool(ctx, dbConfig)
			if err != nil {
				log.Printf("Warning: Failed to create database pool: %v", err)
				log.Println("Continuing without database connection")
			} else {
				dbPool = pool
				log.Println("Database connection pool initialized successfully")

				// Run database migrations
				log.Println("Running database migrations...")
				if err := database.RunMigrations(pool); err != nil {
					log.Printf("FATAL: Database migration failed: %v", err)
					log.Println("Lambda will not start with migration failures")
					os.Exit(1)
				}
				log.Println("Database migrations completed successfully")

				// Ensure cleanup on Lambda shutdown (best-effort)
				defer dbPool.Close()
			}
		}
	} else {
		log.Println("DB_SECRET_NAME not set, skipping database initialization")
	}

	// Start Lambda handler
	lambda.Start(Handler)
}
