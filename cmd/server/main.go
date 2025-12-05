package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"

	"github.com/mikelady/roxas/internal/clients"
	"github.com/mikelady/roxas/internal/database"
	"github.com/mikelady/roxas/internal/models"
	"github.com/mikelady/roxas/internal/orchestrator"
	"github.com/mikelady/roxas/internal/services"
	"github.com/mikelady/roxas/internal/web"
)

// Global database pool (reused across Lambda invocations)
var dbPool *database.Pool

// Config holds application configuration from environment variables
type Config struct {
	OpenAIAPIKey        string
	OpenAIChatModel     string
	OpenAIImageModel    string
	LinkedInAccessToken string
	WebhookSecret       string
	DBSecretName        string
}

// loadConfig loads configuration from environment variables
func loadConfig() Config {
	return Config{
		OpenAIAPIKey:        os.Getenv("OPENAI_API_KEY"),
		OpenAIChatModel:     os.Getenv("OPENAI_CHAT_MODEL"),  // defaults to gpt-4o-mini if empty
		OpenAIImageModel:    os.Getenv("OPENAI_IMAGE_MODEL"), // defaults to dall-e-2 if empty
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

// webhookHandler handles GitHub webhook requests at /webhook
func webhookHandler(config Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received webhook request: %s %s", r.Method, r.URL.Path)

		// Read request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Failed to read request body: %v", err)
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		// Validate webhook signature
		signature := r.Header.Get("X-Hub-Signature-256")
		if signature == "" {
			log.Println("Missing signature header")
			http.Error(w, "Missing signature", http.StatusUnauthorized)
			return
		}

		// Validate signature
		if !validateSignature(body, signature, config.WebhookSecret) {
			log.Println("Invalid signature")
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}

		// Parse webhook payload
		commit, err := extractCommitFromWebhook(body)
		if err != nil {
			log.Printf("Failed to parse webhook: %v", err)
			http.Error(w, fmt.Sprintf("Invalid webhook payload: %v", err), http.StatusBadRequest)
			return
		}

		// Check if we have API credentials for processing
		if config.OpenAIAPIKey == "" || config.LinkedInAccessToken == "" {
			log.Println("Missing API credentials - webhook accepted but not processed")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Webhook received (credentials missing for processing)"))
			return
		}

		// Initialize API clients
		openAIClient := clients.NewOpenAIClient(config.OpenAIAPIKey, "", config.OpenAIChatModel, config.OpenAIImageModel)
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
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf(`{"error": "Failed to process commit: %v"}`, err)))
			return
		}

		log.Printf("Successfully posted to LinkedIn: %s", postURL)

		// Return 200 with success
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`{"message": "Webhook processed successfully", "linkedin_url": "%s"}`, postURL)))
	}
}

// createRouter builds the combined HTTP router for both web UI and webhook
func createRouter(config Config) http.Handler {
	mux := http.NewServeMux()

	// Webhook endpoint
	mux.HandleFunc("/webhook", webhookHandler(config))

	// Web UI routes (handles everything else including /, /login, /signup, /dashboard, /logout)
	webRouter := web.NewRouter()
	mux.Handle("/", webRouter)

	return mux
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

	// Validate required configuration (fail fast at startup)
	if err := validateConfig(config); err != nil {
		log.Printf("FATAL: Configuration error: %v", err)
		os.Exit(1)
	}

	// Initialize database connection if secret name is provided
	if config.DBSecretName != "" {
		log.Printf("Loading database credentials from Secrets Manager: %s", config.DBSecretName)

		dbConfig, err := database.LoadConfigFromSecretsManager(ctx, config.DBSecretName)
		if err != nil {
			log.Printf("Warning: Failed to load database config: %v", err)
			log.Println("Continuing without database connection")
		} else {
			// Ensure the database exists (creates it if needed for PR environments)
			log.Printf("Ensuring database %s exists...", dbConfig.Database)
			if err := database.EnsureDatabaseExists(ctx, dbConfig); err != nil {
				log.Printf("Warning: Failed to ensure database exists: %v", err)
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
		}
	} else {
		log.Println("DB_SECRET_NAME not set, skipping database initialization")
	}

	// Create combined router for web UI and webhook
	router := createRouter(config)

	// Wrap with aws-lambda-go-api-proxy for Lambda compatibility
	lambda.Start(httpadapter.New(router).ProxyWithContext)
}
