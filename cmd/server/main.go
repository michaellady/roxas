package main

// Test deployment trigger - webhook fix verification
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
	"github.com/mikelady/roxas/internal/handlers"
	"github.com/mikelady/roxas/internal/models"
	"github.com/mikelady/roxas/internal/oauth"
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
	WebhookBaseURL      string
	EncryptionKey       string // 32 bytes (base64 encoded or hex) for credential encryption
	ThreadsClientID     string
	ThreadsClientSecret string
	OAuthCallbackURL    string // Base URL for OAuth callbacks
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
		WebhookBaseURL:      os.Getenv("WEBHOOK_BASE_URL"),
		EncryptionKey:       os.Getenv("CREDENTIAL_ENCRYPTION_KEY"), // 32-byte key for AES-256
		ThreadsClientID:     os.Getenv("THREADS_CLIENT_ID"),
		ThreadsClientSecret: os.Getenv("THREADS_CLIENT_SECRET"),
		OAuthCallbackURL:    os.Getenv("OAUTH_CALLBACK_URL"), // e.g., https://app.example.com
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
	return webhookHandlerWithMocks(config, "", "")
}

// webhookHandlerWithMocks handles GitHub webhook requests with optional mock API URLs for testing
func webhookHandlerWithMocks(config Config, openAIBaseURL, linkedInBaseURL string) http.HandlerFunc {
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

		// Initialize API clients (use mock URLs if provided, otherwise use defaults)
		openAIClient := clients.NewOpenAIClient(config.OpenAIAPIKey, openAIBaseURL, config.OpenAIChatModel, config.OpenAIImageModel)
		linkedInClient := clients.NewLinkedInClient(config.LinkedInAccessToken, linkedInBaseURL)

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

// =============================================================================
// Adapters to bridge database stores to handlers interfaces
// =============================================================================

// commitStoreAdapter adapts database.CommitStore to handlers.CommitStore interface
type commitStoreAdapter struct {
	pool *database.Pool
}

func (a *commitStoreAdapter) StoreCommit(ctx context.Context, commit *handlers.StoredCommit) error {
	_, err := a.pool.Exec(ctx,
		`INSERT INTO commits (repository_id, commit_sha, github_url, commit_message, author, timestamp)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (repository_id, commit_sha) DO NOTHING`,
		commit.RepositoryID, commit.CommitSHA, commit.GitHubURL, commit.Message, commit.Author, commit.Timestamp,
	)
	return err
}

func (a *commitStoreAdapter) GetCommitBySHA(ctx context.Context, repoID, sha string) (*handlers.StoredCommit, error) {
	var commit handlers.StoredCommit
	err := a.pool.QueryRow(ctx,
		`SELECT id, repository_id, commit_sha, github_url, commit_message, author, timestamp
		 FROM commits
		 WHERE repository_id = $1 AND commit_sha = $2`,
		repoID, sha,
	).Scan(&commit.ID, &commit.RepositoryID, &commit.CommitSHA, &commit.GitHubURL, &commit.Message, &commit.Author, &commit.Timestamp)
	if err != nil {
		return nil, err
	}
	return &commit, nil
}

// draftWebhookStoreAdapter adapts database.DraftStore to handlers.DraftWebhookStore interface
type draftWebhookStoreAdapter struct {
	store *database.DraftStore
}

func (a *draftWebhookStoreAdapter) CreateDraftFromPush(ctx context.Context, userID, repoID, ref, beforeSHA, afterSHA string, commitSHAs []string) (*handlers.WebhookDraft, error) {
	draft, err := a.store.CreateDraftFromPush(ctx, userID, repoID, ref, beforeSHA, afterSHA, commitSHAs)
	if err != nil {
		return nil, err
	}
	return convertDraftToWebhookDraft(draft), nil
}

func (a *draftWebhookStoreAdapter) GetDraftByPushSignature(ctx context.Context, repoID, beforeSHA, afterSHA string) (*handlers.WebhookDraft, error) {
	draft, err := a.store.GetDraftByPushSignature(ctx, repoID, beforeSHA, afterSHA)
	if err != nil {
		return nil, err
	}
	if draft == nil {
		return nil, nil
	}
	return convertDraftToWebhookDraft(draft), nil
}

func convertDraftToWebhookDraft(d *database.Draft) *handlers.WebhookDraft {
	editedContent := ""
	if d.EditedContent != nil {
		editedContent = *d.EditedContent
	}
	return &handlers.WebhookDraft{
		ID:               d.ID,
		UserID:           d.UserID,
		RepositoryID:     d.RepositoryID,
		Ref:              d.Ref,
		BeforeSHA:        d.BeforeSHA,
		AfterSHA:         d.AfterSHA,
		CommitSHAs:       d.CommitSHAs,
		GeneratedContent: d.GeneratedContent,
		EditedContent:    editedContent,
		Status:           d.Status,
		CreatedAt:        d.CreatedAt,
		UpdatedAt:        d.UpdatedAt,
	}
}

// idempotencyStoreAdapter adapts database.WebhookDeliveryStore to handlers.IdempotencyStore interface
type idempotencyStoreAdapter struct {
	store *database.WebhookDeliveryStore
}

func (a *idempotencyStoreAdapter) CheckDeliveryProcessed(ctx context.Context, deliveryID string) (bool, error) {
	return a.store.CheckDeliveryProcessed(ctx, deliveryID)
}

func (a *idempotencyStoreAdapter) MarkDeliveryProcessed(ctx context.Context, deliveryID, repoID string) error {
	return a.store.MarkDeliveryProcessed(ctx, deliveryID, repoID)
}

// activityStoreAdapter adapts database.ActivityStore to handlers.ActivityStore interface
type activityStoreAdapter struct {
	store *database.ActivityStore
}

func (a *activityStoreAdapter) CreateActivity(ctx context.Context, userID, activityType string, draftID *string, message string) (*handlers.WebhookActivity, error) {
	// Database CreateActivity takes: userID, activityType, draftID, postID, platform, message (all *string for optional fields)
	// Handler CreateActivity takes: userID, activityType, draftID *string, message string
	activity, err := a.store.CreateActivity(ctx, userID, activityType, draftID, nil, nil, &message)
	if err != nil {
		return nil, err
	}
	// Convert database.Activity to handlers.WebhookActivity
	platform := ""
	if activity.Platform != nil {
		platform = *activity.Platform
	}
	msg := ""
	if activity.Message != nil {
		msg = *activity.Message
	}
	return &handlers.WebhookActivity{
		ID:        activity.ID,
		UserID:    activity.UserID,
		Type:      activity.Type,
		DraftID:   activity.DraftID,
		PostID:    activity.PostID,
		Platform:  platform,
		Message:   msg,
		CreatedAt: activity.CreatedAt,
	}, nil
}

// draftListerAdapter adapts database.DraftStore to web.DraftLister interface
type draftListerAdapter struct {
	draftStore *database.DraftStore
	repoStore  *database.RepositoryStore
}

func (a *draftListerAdapter) ListDraftsByUser(ctx context.Context, userID string) ([]*web.DraftItem, error) {
	drafts, err := a.draftStore.ListDraftsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	items := make([]*web.DraftItem, 0, len(drafts))
	for _, d := range drafts {
		// Get repo name for display
		repoName := "Unknown Repository"
		if repo, err := a.repoStore.GetRepositoryByID(ctx, d.RepositoryID); err == nil && repo != nil {
			// Extract repo name from GitHub URL (e.g., "owner/repo" from "https://github.com/owner/repo")
			repoName = extractRepoNameFromURL(repo.GitHubURL)
		}

		// Use generated content or edited content for preview
		previewText := d.GeneratedContent
		if d.EditedContent != nil && *d.EditedContent != "" {
			previewText = *d.EditedContent
		}
		// Truncate for preview
		if len(previewText) > 100 {
			previewText = previewText[:100] + "..."
		}
		if previewText == "" {
			previewText = "(Awaiting AI generation...)"
		}

		items = append(items, &web.DraftItem{
			ID:          d.ID,
			RepoName:    repoName,
			PreviewText: previewText,
			Platform:    "threads", // Default platform for now
			CreatedAt:   d.CreatedAt,
		})
	}

	return items, nil
}

func extractRepoNameFromURL(url string) string {
	// Extract "owner/repo" from "https://github.com/owner/repo"
	parts := strings.Split(url, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "/" + parts[len(parts)-1]
	}
	return url
}

// aiGeneratorAdapter implements handlers.AIGeneratorService to generate content for drafts
type aiGeneratorAdapter struct {
	draftStore    *database.DraftStore
	repoStore     *database.RepositoryStore
	postGenerator services.PostGeneratorService
}

func (a *aiGeneratorAdapter) TriggerGeneration(ctx context.Context, draftID string) error {
	// Fetch the draft
	draft, err := a.draftStore.GetDraft(ctx, draftID)
	if err != nil {
		return fmt.Errorf("failed to get draft: %w", err)
	}

	// Fetch repo info for the commit URL
	repo, err := a.repoStore.GetRepositoryByID(ctx, draft.RepositoryID)
	if err != nil {
		return fmt.Errorf("failed to get repository: %w", err)
	}

	// Build a commit-like object for the generator
	// Use the after_sha as the commit ID and combine commit messages
	commitMessage := fmt.Sprintf("Push to %s with %d commit(s)", draft.Ref, len(draft.CommitSHAs))
	if len(draft.CommitSHAs) == 1 {
		commitMessage = fmt.Sprintf("Commit %s to %s", draft.AfterSHA[:7], draft.Ref)
	}

	commit := &services.Commit{
		ID:        draft.AfterSHA,
		Message:   commitMessage,
		Author:    "developer", // Could be enhanced to fetch from commit data
		GitHubURL: fmt.Sprintf("%s/commit/%s", repo.GitHubURL, draft.AfterSHA),
	}

	// Generate content using PostGenerator
	// Use "threads" as the platform (could be made configurable)
	generated, err := a.postGenerator.Generate(ctx, "linkedin", commit)
	if err != nil {
		// Update draft status to error
		_ = a.draftStore.UpdateDraftStatus(ctx, draftID, database.DraftStatusError)
		return fmt.Errorf("failed to generate content: %w", err)
	}

	// Update draft with generated content
	_, err = a.draftStore.CreateDraft(ctx, draft.UserID, draft.RepositoryID, draft.Ref, draft.BeforeSHA, draft.AfterSHA, draft.CommitSHAs, generated.Content)
	if err != nil {
		// If duplicate, just update the content
		err = a.draftStore.UpdateDraftContent(ctx, draftID, generated.Content)
		if err != nil {
			return fmt.Errorf("failed to update draft content: %w", err)
		}
	}

	log.Printf("AI generation completed for draft %s", draftID)
	return nil
}

// draftStoreAdapter adapts database.DraftStore to web.DraftStore interface
// Required for draft preview, edit, delete, and post operations
type draftStoreAdapter struct {
	store *database.DraftStore
}

func (a *draftStoreAdapter) GetDraftByID(ctx context.Context, draftID string) (*web.Draft, error) {
	draft, err := a.store.GetDraft(ctx, draftID)
	if err != nil {
		return nil, err
	}
	// Use edited content if available, otherwise generated content
	content := draft.GeneratedContent
	if draft.EditedContent != nil && *draft.EditedContent != "" {
		content = *draft.EditedContent
	}
	return &web.Draft{
		ID:           draft.ID,
		UserID:       draft.UserID,
		RepositoryID: draft.RepositoryID,
		Content:      content,
		Status:       draft.Status,
		CharLimit:    500, // Threads character limit
		CreatedAt:    draft.CreatedAt,
	}, nil
}

func (a *draftStoreAdapter) UpdateDraftContent(ctx context.Context, draftID, content string) (*web.Draft, error) {
	err := a.store.UpdateDraftContent(ctx, draftID, content)
	if err != nil {
		return nil, err
	}
	return a.GetDraftByID(ctx, draftID)
}

func (a *draftStoreAdapter) DeleteDraft(ctx context.Context, draftID string) error {
	return a.store.DeleteDraft(ctx, draftID)
}

func (a *draftStoreAdapter) UpdateDraftStatus(ctx context.Context, draftID, status string) (*web.Draft, error) {
	err := a.store.UpdateDraftStatus(ctx, draftID, status)
	if err != nil {
		return nil, err
	}
	return a.GetDraftByID(ctx, draftID)
}

// aiRegeneratorAdapter implements web.AIRegenerator using aiGeneratorAdapter
type aiRegeneratorAdapter struct {
	generator *aiGeneratorAdapter
}

func (a *aiRegeneratorAdapter) RegenerateDraft(ctx context.Context, draftID string) error {
	return a.generator.TriggerGeneration(ctx, draftID)
}

// socialPosterAdapter implements web.SocialPoster for posting to Threads
type socialPosterAdapter struct {
	draftStore      *database.DraftStore
	credentialStore services.CredentialStore
}

func (a *socialPosterAdapter) PostDraft(ctx context.Context, userID, draftID string) (string, error) {
	// Fetch the draft
	draft, err := a.draftStore.GetDraft(ctx, draftID)
	if err != nil {
		return "", fmt.Errorf("failed to get draft: %w", err)
	}

	// Get the content to post (edited or generated)
	content := draft.GeneratedContent
	if draft.EditedContent != nil && *draft.EditedContent != "" {
		content = *draft.EditedContent
	}

	// Try Bluesky first, then fall back to Threads
	bluskyCreds, bskyErr := a.credentialStore.GetCredentials(ctx, userID, "bluesky")
	if bskyErr == nil && bluskyCreds != nil {
		// Bluesky: AccessToken = app password, RefreshToken = handle
		handle := bluskyCreds.RefreshToken
		appPassword := bluskyCreds.AccessToken
		bskyClient := clients.NewBlueskyClient(handle, appPassword, "")
		result, err := bskyClient.Post(ctx, services.PostContent{Text: content})
		if err != nil {
			return "", fmt.Errorf("failed to post to Bluesky: %w", err)
		}
		return result.PostURL, nil
	}

	// Fall back to Threads
	threadsCreds, threadsErr := a.credentialStore.GetCredentials(ctx, userID, "threads")
	if threadsErr == nil && threadsCreds != nil {
		threadsClient := clients.NewThreadsClient(threadsCreds.AccessToken, "")
		result, err := threadsClient.Post(ctx, services.PostContent{Text: content})
		if err != nil {
			return "", fmt.Errorf("failed to post to Threads: %w", err)
		}
		return result.PostURL, nil
	}

	return "", fmt.Errorf("no social platform connected - please connect Bluesky or Threads first")
}

// threadsOAuthAdapter implements web.ThreadsOAuthConnector
type threadsOAuthAdapter struct {
	provider        *oauth.ThreadsOAuthProvider
	credentialStore services.CredentialStore
}

func (a *threadsOAuthAdapter) GetAuthURL(state, redirectURL string) string {
	return a.provider.GetAuthURL(state, redirectURL)
}

func (a *threadsOAuthAdapter) ExchangeCode(ctx context.Context, userID, code, redirectURL string) (string, error) {
	// Exchange code for tokens
	tokens, err := a.provider.ExchangeCode(ctx, code, redirectURL)
	if err != nil {
		return "", fmt.Errorf("failed to exchange code: %w", err)
	}

	// Store credentials
	creds := &services.PlatformCredentials{
		UserID:         userID,
		Platform:       "threads",
		AccessToken:    tokens.AccessToken,
		RefreshToken:   tokens.RefreshToken,
		TokenExpiresAt: tokens.ExpiresAt,
		PlatformUserID: tokens.PlatformUserID,
		Scopes:         tokens.Scopes,
	}

	if err := a.credentialStore.SaveCredentials(ctx, creds); err != nil {
		return "", fmt.Errorf("failed to save credentials: %w", err)
	}

	// Return platform username (or user ID if username not available)
	username := tokens.PlatformUserID
	if username == "" {
		username = "connected"
	}
	return username, nil
}

func (a *threadsOAuthAdapter) RefreshTokens(ctx context.Context, refreshToken string) (*web.OAuthTokens, error) {
	tokens, err := a.provider.RefreshTokens(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	return &web.OAuthTokens{
		AccessToken:    tokens.AccessToken,
		RefreshToken:   tokens.RefreshToken,
		ExpiresAt:      tokens.ExpiresAt,
		PlatformUserID: tokens.PlatformUserID,
		Scopes:         tokens.Scopes,
	}, nil
}

// blueskyConnectorAdapter implements web.BlueskyConnector for app password auth
type blueskyConnectorAdapter struct {
	credentialStore services.CredentialStore
}

func (a *blueskyConnectorAdapter) Connect(ctx context.Context, userID, handle, appPassword string) (*web.BlueskyConnectResult, error) {
	// Normalize handle
	handle = strings.TrimPrefix(handle, "@")
	// Add default domain if no domain present
	if !strings.Contains(handle, ".") {
		handle = handle + ".bsky.social"
	}

	// Validate credentials by attempting to authenticate
	log.Printf("Bluesky connect: attempting auth for handle %s", handle)
	client := clients.NewBlueskyClient(handle, appPassword, "")
	if err := client.Authenticate(ctx); err != nil {
		log.Printf("Bluesky connect: auth failed for %s: %v", handle, err)
		if client.IsAuthError(err) {
			return &web.BlueskyConnectResult{
				Success: false,
				Error:   "Invalid handle or app password. Please check your credentials and try again.",
			}, nil
		}
		// Network or other error - show more details
		return &web.BlueskyConnectResult{
			Success: false,
			Error:   fmt.Sprintf("Failed to connect to Bluesky: %v", err),
		}, nil
	}
	log.Printf("Bluesky connect: auth successful for %s (DID: %s)", handle, client.GetDID())

	// Store credentials - use AccessToken for app password, RefreshToken for handle
	// (App passwords don't expire, so no expiry time)
	creds := &services.PlatformCredentials{
		UserID:         userID,
		Platform:       "bluesky",
		AccessToken:    appPassword,  // The app password
		RefreshToken:   handle,       // Store handle for later use
		TokenExpiresAt: nil,          // App passwords don't expire
		PlatformUserID: client.GetDID(),
		Scopes:         "",
	}

	if err := a.credentialStore.SaveCredentials(ctx, creds); err != nil {
		return nil, fmt.Errorf("failed to save credentials: %w", err)
	}

	return &web.BlueskyConnectResult{
		Handle:  handle,
		DID:     client.GetDID(),
		Success: true,
	}, nil
}

// createRouter builds the combined HTTP router for both web UI and webhook
func createRouter(config Config, dbPool *database.Pool) http.Handler {
	mux := http.NewServeMux()

	// Legacy webhook endpoint (single-tenant, uses global WEBHOOK_SECRET)
	mux.HandleFunc("/webhook", webhookHandler(config))

	// Multi-tenant webhook endpoint: /webhooks/github/{repo_id}
	// Each repository has its own webhook secret stored in the database
	// Uses DraftCreatingWebhookHandler to create drafts and trigger AI generation
	if dbPool != nil {
		repoStore := database.NewRepositoryStore(dbPool)
		draftStore := database.NewDraftStore(dbPool)
		deliveryStore := database.NewWebhookDeliveryStore(dbPool)
		activityStore := database.NewActivityStore(dbPool)

		// Create adapters to bridge database types to handler interfaces
		draftWebhookStore := &draftWebhookStoreAdapter{store: draftStore}
		idempotencyStore := &idempotencyStoreAdapter{store: deliveryStore}
		activityStoreForWebhook := &activityStoreAdapter{store: activityStore}

		// Create AI generator if OpenAI API key is configured
		var aiGenerator *aiGeneratorAdapter
		if config.OpenAIAPIKey != "" {
			openaiClient := clients.NewOpenAIClient(config.OpenAIAPIKey, "", config.OpenAIChatModel, config.OpenAIImageModel)
			postGenerator := services.NewPostGenerator(openaiClient)
			aiGenerator = &aiGeneratorAdapter{
				draftStore:    draftStore,
				repoStore:     repoStore,
				postGenerator: postGenerator,
			}
			log.Println("AI content generation enabled")
		} else {
			log.Println("AI content generation disabled (no OPENAI_API_KEY)")
		}

		// Use DraftCreatingWebhookHandler which creates drafts on push events
		draftHandler := handlers.NewDraftCreatingWebhookHandler(repoStore, draftWebhookStore, idempotencyStore).
			WithActivityStore(activityStoreForWebhook)

		// Add AI generator if configured
		if aiGenerator != nil {
			draftHandler = draftHandler.WithAIGenerator(aiGenerator)
		}

		mux.Handle("/webhooks/github/", draftHandler)
	}

	// Web UI routes (handles everything else including /, /login, /signup, /dashboard, /logout)
	var webRouter http.Handler
	if dbPool != nil {
		// Create database-backed stores for full functionality
		userStore := database.NewUserStore(dbPool)
		repoStore := database.NewRepositoryStore(dbPool)
		commitStore := database.NewCommitStore(dbPool)
		postStore := database.NewPostStore(dbPool)
		activityStore := database.NewActivityStore(dbPool)
		draftStore := database.NewDraftStore(dbPool)
		secretGen := handlers.NewCryptoSecretGenerator()

		// Create draft adapters
		draftLister := &draftListerAdapter{draftStore: draftStore, repoStore: repoStore}
		webDraftStore := &draftStoreAdapter{store: draftStore}

		router := web.NewRouterWithActivityLister(userStore, repoStore, commitStore, postStore, activityStore, secretGen, config.WebhookBaseURL).
			WithDraftLister(draftLister).
			WithDraftStore(webDraftStore)

		// Add social poster and Threads OAuth if encryption key is configured
		if config.EncryptionKey != "" {
			encKey, err := hex.DecodeString(config.EncryptionKey)
			if err != nil {
				log.Printf("Warning: Invalid CREDENTIAL_ENCRYPTION_KEY format (expected hex): %v", err)
			} else if len(encKey) != 32 {
				log.Printf("Warning: CREDENTIAL_ENCRYPTION_KEY must be 32 bytes (64 hex chars), got %d bytes", len(encKey))
			} else {
				credentialStore, err := database.NewCredentialStore(dbPool, encKey)
				if err != nil {
					log.Printf("Warning: Failed to create credential store: %v", err)
				} else {
					// Add social poster
					socialPoster := &socialPosterAdapter{
						draftStore:      draftStore,
						credentialStore: credentialStore,
					}
					router = router.WithSocialPoster(socialPoster)
					log.Println("Social posting enabled (Bluesky, Threads)")

					// Add Threads OAuth if configured
					if config.ThreadsClientID != "" && config.ThreadsClientSecret != "" {
						threadsProvider := oauth.NewThreadsOAuthProvider(config.ThreadsClientID, config.ThreadsClientSecret)
						threadsOAuth := &threadsOAuthAdapter{
							provider:        threadsProvider,
							credentialStore: credentialStore,
						}
						callbackURL := config.OAuthCallbackURL
						if callbackURL == "" {
							callbackURL = config.WebhookBaseURL // Fallback to webhook base URL
						}
						router = router.WithThreadsOAuth(threadsOAuth, callbackURL)
						log.Println("Threads OAuth enabled")
					} else {
						log.Println("Threads OAuth disabled (no THREADS_CLIENT_ID/THREADS_CLIENT_SECRET)")
					}

					// Add Bluesky connector (always enabled with credential store)
					blueskyConnector := &blueskyConnectorAdapter{
						credentialStore: credentialStore,
					}
					router = router.WithBlueskyConnector(blueskyConnector)
					log.Println("Bluesky connection enabled")
				}
			}
		} else {
			log.Println("Social posting disabled (no CREDENTIAL_ENCRYPTION_KEY)")
		}

		// Add AI regenerator if OpenAI is configured
		if config.OpenAIAPIKey != "" {
			openaiClient := clients.NewOpenAIClient(config.OpenAIAPIKey, "", config.OpenAIChatModel, config.OpenAIImageModel)
			postGenerator := services.NewPostGenerator(openaiClient)
			aiGen := &aiGeneratorAdapter{
				draftStore:    draftStore,
				repoStore:     repoStore,
				postGenerator: postGenerator,
			}
			router = router.WithAIRegenerator(&aiRegeneratorAdapter{generator: aiGen})
		}

		webRouter = router
	} else {
		// No database - use router without stores (auth will show "not configured")
		log.Println("WARNING: Database unavailable - web authentication disabled")
		webRouter = web.NewRouter()
	}
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
	router := createRouter(config, dbPool)

	// Wrap with aws-lambda-go-api-proxy for Lambda compatibility
	// Using V2 adapter for API Gateway HTTP API (not REST API)
	lambda.Start(httpadapter.NewV2(router).ProxyWithContext)
}
