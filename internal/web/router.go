package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mikelady/roxas/internal/auth"
	"github.com/mikelady/roxas/internal/handlers"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/*
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Templates holds parsed HTML templates per page
var pageTemplates map[string]*template.Template

// templateFuncs provides helper functions for templates
var templateFuncs = template.FuncMap{
	"percent": func(remaining, limit int) int {
		if limit == 0 {
			return 0
		}
		return (remaining * 100) / limit
	},
	"le": func(a, b int) bool {
		return a <= b
	},
	"add": func(a, b int) int {
		return a + b
	},
	"gt": func(a, b int) bool {
		return a > b
	},
	"lt": func(a, b int) bool {
		return a < b
	},
	"timeAgo": func(t time.Time) string {
		now := time.Now()
		diff := now.Sub(t)

		switch {
		case diff < time.Minute:
			return "just now"
		case diff < time.Hour:
			mins := int(diff.Minutes())
			if mins == 1 {
				return "1 minute ago"
			}
			return fmt.Sprintf("%d minutes ago", mins)
		case diff < 24*time.Hour:
			hours := int(diff.Hours())
			if hours == 1 {
				return "1 hour ago"
			}
			return fmt.Sprintf("%d hours ago", hours)
		case diff < 7*24*time.Hour:
			days := int(diff.Hours() / 24)
			if days == 1 {
				return "1 day ago"
			}
			return fmt.Sprintf("%d days ago", days)
		default:
			return t.Format("Jan 02, 2006")
		}
	},
	"truncate": func(s string, maxLen int) string {
		if len(s) <= maxLen {
			return s
		}
		return s[:maxLen-3] + "..."
	},
}

func init() {
	pageTemplates = make(map[string]*template.Template)
	pages := []string{"home.html", "login.html", "signup.html", "dashboard.html", "connections.html", "connections_new.html", "bluesky_connect.html", "repositories_new.html", "repository_success.html", "repositories_list.html", "repository_view.html", "repository_edit.html", "repository_delete.html", "webhook_regenerate.html", "webhook_deliveries.html", "connection_disconnect.html", "drafts.html", "draft_preview.html"}

	for _, page := range pages {
		// Clone the base template and parse the page with functions
		t := template.Must(template.New("").Funcs(templateFuncs).ParseFS(templatesFS,
			"templates/layouts/base.html",
			"templates/pages/"+page,
		))
		pageTemplates[page] = t
	}
}

// PageData holds data passed to templates
type PageData struct {
	Title      string
	User       *UserData
	Flash      *FlashMessage
	Error      string
	Data       interface{}
	DraftCount int    // Number of pending drafts (for navigation badge)
	CSRFToken  string // CSRF token for form submissions
}

// UserData represents authenticated user info for templates
type UserData struct {
	ID    string
	Email string
}

// FlashMessage represents a flash notification
type FlashMessage struct {
	Type    string // success, error, info
	Message string
}

// UserStore interface for user operations
type UserStore interface {
	GetUserByEmail(ctx context.Context, email string) (*handlers.User, error)
	CreateUser(ctx context.Context, email, passwordHash string) (*handlers.User, error)
}

// RepositoryStore interface for repository operations
type RepositoryStore interface {
	ListRepositoriesByUser(ctx context.Context, userID string) ([]*handlers.Repository, error)
	CreateRepository(ctx context.Context, userID, githubURL, webhookSecret string) (*handlers.Repository, error)
	GetRepositoryByID(ctx context.Context, repoID string) (*handlers.Repository, error)
	UpdateRepository(ctx context.Context, repoID, name string, isActive bool) (*handlers.Repository, error)
	UpdateWebhookSecret(ctx context.Context, repoID, newSecret string) error
	DeleteRepository(ctx context.Context, repoID string) error
}

// SecretGenerator generates webhook secrets
type SecretGenerator interface {
	Generate() (string, error)
}

// CommitLister interface for listing commits
type CommitLister interface {
	ListCommitsByUser(ctx context.Context, userID string) ([]*DashboardCommit, error)
}

// PostLister interface for listing posts
type PostLister interface {
	ListPostsByUser(ctx context.Context, userID string) ([]*DashboardPost, error)
}

// DraftCounter interface for counting draft posts
type DraftCounter interface {
	CountDraftsByUser(ctx context.Context, userID string) (int, error)
}

// DraftItem represents a draft post for the drafts list page
type DraftItem struct {
	ID          string
	RepoName    string
	PreviewText string
	Platform    string
	CreatedAt   time.Time
}

// DraftLister interface for listing user drafts
type DraftLister interface {
	ListDraftsByUser(ctx context.Context, userID string) ([]*DraftItem, error)
}

// Draft represents a draft social media post
type Draft struct {
	ID           string
	UserID       string
	RepositoryID string
	Content      string
	Status       string
	CharLimit    int
	CreatedAt    time.Time
}

// DraftStore interface for draft operations
type DraftStore interface {
	GetDraftByID(ctx context.Context, draftID string) (*Draft, error)
	UpdateDraftContent(ctx context.Context, draftID, content string) (*Draft, error)
	DeleteDraft(ctx context.Context, draftID string) error
	UpdateDraftStatus(ctx context.Context, draftID, status string) (*Draft, error)
}

// DraftPreviewData holds data for the draft preview page
type DraftPreviewData struct {
	Draft     *Draft
	CharCount int
	CharLimit int
}

// WebhookTester interface for testing webhook connectivity
type WebhookTester interface {
	TestWebhook(ctx context.Context, webhookURL, secret string) (statusCode int, err error)
}

// HTTPWebhookTester implements WebhookTester using real HTTP requests
type HTTPWebhookTester struct {
	client *http.Client
}

// NewHTTPWebhookTester creates a new HTTP webhook tester with a default client
func NewHTTPWebhookTester() *HTTPWebhookTester {
	return &HTTPWebhookTester{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// TestWebhook sends a test ping to the webhook URL
func (t *HTTPWebhookTester) TestWebhook(ctx context.Context, webhookURL, secret string) (int, error) {
	// Create a simple test payload (similar to GitHub ping event)
	payload := []byte(`{"zen": "Webhook test ping", "hook_id": 0}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, strings.NewReader(string(payload)))
	if err != nil {
		return 0, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "ping")
	req.Header.Set("X-GitHub-Delivery", "test-delivery-id")

	// Compute HMAC signature (same algorithm GitHub uses)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-Hub-Signature-256", signature)

	resp, err := t.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}

// WebhookDelivery represents a webhook delivery event for display
type WebhookDelivery struct {
	ID           string
	RepositoryID string
	DeliveryID   string
	EventType    string
	Payload      string
	StatusCode   int
	ErrorMessage *string
	ProcessedAt  *string
	CreatedAt    string
	IsSuccess    bool
	Ref          *string
	BeforeSHA    *string
	AfterSHA     *string
}

// CreateDeliveryParams contains parameters for creating a webhook delivery
type CreateDeliveryParams struct {
	RepositoryID string
	DeliveryID   string
	EventType    string
	Payload      []byte
	StatusCode   int
	ErrorMessage *string
	Ref          *string
	BeforeSHA    *string
	AfterSHA     *string
}

// WebhookDeliveryStore interface for webhook delivery operations
type WebhookDeliveryStore interface {
	ListDeliveriesByRepository(ctx context.Context, repoID string, limit int) ([]*WebhookDelivery, error)
	CreateDelivery(ctx context.Context, params CreateDeliveryParams) (*WebhookDelivery, error)
}

// ConnectionService interface for connection management operations
type ConnectionService interface {
	GetConnection(ctx context.Context, userID, platform string) (*Connection, error)
	Disconnect(ctx context.Context, userID, platform string) error
}

// BlueskyConnector handles Bluesky authentication with app passwords
type BlueskyConnector interface {
	// Connect authenticates with Bluesky and stores the connection
	// handle: Bluesky handle (e.g., "user.bsky.social" or "@user")
	// appPassword: App password from bsky.app/settings/app-passwords
	Connect(ctx context.Context, userID, handle, appPassword string) (*BlueskyConnectResult, error)
}

// ThreadsOAuthConnector handles Threads OAuth flow
type ThreadsOAuthConnector interface {
	// GetAuthURL generates the OAuth authorization URL for Threads
	// state: Random string for CSRF protection
	// redirectURL: Where Threads will redirect after authorization
	GetAuthURL(state, redirectURL string) string

	// ExchangeCode exchanges the authorization code for tokens and stores credentials
	// Returns the platform username for display
	ExchangeCode(ctx context.Context, userID, code, redirectURL string) (platformUsername string, err error)

	// RefreshTokens refreshes the access token using the refresh token
	RefreshTokens(ctx context.Context, refreshToken string) (*OAuthTokens, error)
}

// BlueskyConnectResult contains the result of connecting a Bluesky account
type BlueskyConnectResult struct {
	Handle      string
	DID         string
	DisplayName string
	Success     bool
	Error       string
}

// Connection represents a user's connection to a social platform
type Connection struct {
	Platform    string
	Status      string
	DisplayName string
	ProfileURL  string
}

// Connection status constants
const (
	ConnectionStatusConnected    = "connected"
	ConnectionStatusDisconnected = "disconnected"
)

// DashboardCommit represents a commit for the dashboard
type DashboardCommit struct {
	ID      string
	SHA     string
	Message string
	Author  string
}

// DashboardPost represents a post for the dashboard
type DashboardPost struct {
	ID       string
	Platform string
	Content  string
	Status   string
}

// DashboardActivity represents an activity for the dashboard
type DashboardActivity struct {
	ID        string
	Type      string
	DraftID   *string
	PostID    *string
	Platform  *string
	Message   *string
	CreatedAt time.Time
}

// ActivityLister interface for listing activities
type ActivityLister interface {
	ListActivitiesByUser(ctx context.Context, userID string, limit, offset int) ([]*DashboardActivity, error)
	CountActivitiesByUser(ctx context.Context, userID string) (int, error)
}

// ConnectionLister retrieves connections with rate limits for a user
type ConnectionLister interface {
	ListConnectionsWithRateLimits(ctx context.Context, userID string) ([]*ConnectionData, error)
}

// ConnectionData represents connection with rate limit for templates
type ConnectionData struct {
	Platform    string
	Status      string
	DisplayName string
	IsHealthy   bool
	ExpiresSoon bool
	RateLimit   *RateLimitData
}

// RateLimitData represents rate limit info for templates
type RateLimitData struct {
	Limit     int
	Remaining int
	ResetAt   time.Time
}

// GitHubOAuthProvider handles GitHub OAuth flow
type GitHubOAuthProvider interface {
	GetAuthURL(state, redirectURL string) string
	ExchangeCode(ctx context.Context, code, redirectURL string) (*OAuthTokens, error)
}

// OAuthTokens represents the tokens returned from OAuth authentication
type OAuthTokens struct {
	AccessToken    string
	RefreshToken   string
	ExpiresAt      *time.Time
	PlatformUserID string
	Scopes         string
}

// CredentialStore interface for storing platform credentials
type CredentialStore interface {
	SaveCredentials(ctx context.Context, creds *PlatformCredentials) error
	GetCredentials(ctx context.Context, userID, platform string) (*PlatformCredentials, error)
}

// GitHubRepoLister interface for listing user's GitHub repositories
type GitHubRepoLister interface {
	ListUserRepos(ctx context.Context, accessToken string) ([]GitHubRepo, error)
}

// GitHubRepo represents a repository from GitHub API
type GitHubRepo struct {
	ID          int64
	Name        string
	FullName    string
	HTMLURL     string
	Description string
	Private     bool
}

// PlatformCredentials represents OAuth credentials for a platform
type PlatformCredentials struct {
	UserID         string
	Platform       string
	AccessToken    string
	RefreshToken   string
	TokenExpiresAt *time.Time
	PlatformUserID string
	Scopes         string
}

// AIRegenerator interface for regenerating AI content for drafts
type AIRegenerator interface {
	// RegenerateDraft regenerates the AI content for a draft and updates it
	RegenerateDraft(ctx context.Context, draftID string) error
}

// SocialPoster interface for posting content to social media platforms
type SocialPoster interface {
	// PostDraft posts the draft content to the configured social platform
	// Returns the URL of the created post
	PostDraft(ctx context.Context, userID, draftID string) (postURL string, err error)
}

// Router is the main HTTP router for the web UI
type Router struct {
	mux                  *http.ServeMux
	userStore            UserStore
	repoStore            RepositoryStore
	commitLister         CommitLister
	postLister           PostLister
	activityLister       ActivityLister
	secretGen            SecretGenerator
	webhookURL           string
	webhookTester        WebhookTester
	webhookDeliveryStore WebhookDeliveryStore
	connectionLister     ConnectionLister
	connectionService    ConnectionService
	blueskyConnector     BlueskyConnector
	draftCounter         DraftCounter
	draftLister          DraftLister
	draftStore           DraftStore
	githubOAuthProvider  GitHubOAuthProvider
	credentialStore      CredentialStore
	baseURL              string // Base URL for constructing redirect URIs
	githubRepoLister     GitHubRepoLister
	threadsOAuth         ThreadsOAuthConnector
	oauthCallbackURL     string // Base URL for OAuth callbacks (e.g., "https://app.example.com")
	aiRegenerator        AIRegenerator
	socialPoster         SocialPoster
	authRateLimiter      *auth.RateLimiter // Rate limiter for auth endpoints (login, signup)
	githubAppSetup       http.Handler      // GitHub App setup callback handler
	githubAppURL         string            // URL for installing the GitHub App (e.g., "https://github.com/apps/roxas/installations/new")
}

// NewRouter creates a new web router with all routes configured (no user store)
func NewRouter() *Router {
	r := &Router{
		mux: http.NewServeMux(),
	}
	r.setupRoutes()
	return r
}

// NewRouterWithStores creates a new web router with stores for auth
func NewRouterWithStores(userStore UserStore) *Router {
	r := &Router{
		mux:       http.NewServeMux(),
		userStore: userStore,
	}
	r.setupRoutes()
	return r
}

// NewRouterWithAllStores creates a new web router with all stores
func NewRouterWithAllStores(userStore UserStore, repoStore RepositoryStore, commitLister CommitLister, postLister PostLister, secretGen SecretGenerator, webhookURL string) *Router {
	r := &Router{
		mux:          http.NewServeMux(),
		userStore:    userStore,
		repoStore:    repoStore,
		commitLister: commitLister,
		postLister:   postLister,
		secretGen:    secretGen,
		webhookURL:   webhookURL,
	}
	r.setupRoutes()
	return r
}

// NewRouterWithActivityLister creates a new web router with activity lister support
func NewRouterWithActivityLister(userStore UserStore, repoStore RepositoryStore, commitLister CommitLister, postLister PostLister, activityLister ActivityLister, secretGen SecretGenerator, webhookURL string) *Router {
	r := &Router{
		mux:            http.NewServeMux(),
		userStore:      userStore,
		repoStore:      repoStore,
		commitLister:   commitLister,
		postLister:     postLister,
		activityLister: activityLister,
		secretGen:      secretGen,
		webhookURL:     webhookURL,
	}
	r.setupRoutes()
	return r
}

// WithDraftLister adds a draft lister to the router (builder pattern)
func (r *Router) WithDraftLister(draftLister DraftLister) *Router {
	r.draftLister = draftLister
	return r
}

// WithDraftStore adds a draft store to the router (builder pattern)
// Required for draft preview, edit, delete, regenerate, and post operations
func (r *Router) WithDraftStore(draftStore DraftStore) *Router {
	r.draftStore = draftStore
	return r
}

// WithAIRegenerator adds an AI regenerator to the router (builder pattern)
// Required for regenerating draft content
func (r *Router) WithAIRegenerator(aiRegenerator AIRegenerator) *Router {
	r.aiRegenerator = aiRegenerator
	return r
}

// WithSocialPoster adds a social poster to the router (builder pattern)
// Required for posting drafts to social media platforms
func (r *Router) WithSocialPoster(socialPoster SocialPoster) *Router {
	r.socialPoster = socialPoster
	return r
}

// WithThreadsOAuth adds Threads OAuth support to the router (builder pattern)
// Required for connecting Threads accounts
func (r *Router) WithThreadsOAuth(threadsOAuth ThreadsOAuthConnector, callbackURL string) *Router {
	r.threadsOAuth = threadsOAuth
	r.oauthCallbackURL = callbackURL
	return r
}

// WithBlueskyConnector configures the router with a Bluesky connector for app password auth
func (r *Router) WithBlueskyConnector(connector BlueskyConnector) *Router {
	r.blueskyConnector = connector
	return r
}

// WithConnectionLister configures the router with a connection lister for displaying user connections
func (r *Router) WithConnectionLister(lister ConnectionLister) *Router {
	r.connectionLister = lister
	return r
}

// WithConnectionService configures the router with a connection service for disconnect operations
func (r *Router) WithConnectionService(service ConnectionService) *Router {
	r.connectionService = service
	return r
}

// WithAuthRateLimiter configures the router with a rate limiter for auth endpoints.
// This helps prevent brute force attacks on login and signup endpoints.
func (r *Router) WithAuthRateLimiter(limiter *auth.RateLimiter) *Router {
	r.authRateLimiter = limiter
	return r
}

// WithGitHubAppSetup configures the router with a GitHub App setup handler and install URL.
func (r *Router) WithGitHubAppSetup(setupHandler http.Handler, appURL string) *Router {
	r.githubAppSetup = setupHandler
	r.githubAppURL = appURL
	return r
}

// NewRouterWithWebhookTester creates a new web router with webhook tester support
func NewRouterWithWebhookTester(userStore UserStore, repoStore RepositoryStore, commitLister CommitLister, postLister PostLister, secretGen SecretGenerator, webhookURL string, webhookTester WebhookTester) *Router {
	r := &Router{
		mux:           http.NewServeMux(),
		userStore:     userStore,
		repoStore:     repoStore,
		commitLister:  commitLister,
		postLister:    postLister,
		secretGen:     secretGen,
		webhookURL:    webhookURL,
		webhookTester: webhookTester,
	}
	r.setupRoutes()
	return r
}

// NewRouterWithWebhookDeliveries creates a new web router with webhook delivery store
func NewRouterWithWebhookDeliveries(userStore UserStore, repoStore RepositoryStore, commitLister CommitLister, postLister PostLister, secretGen SecretGenerator, webhookURL string, webhookDeliveryStore WebhookDeliveryStore) *Router {
	r := &Router{
		mux:                  http.NewServeMux(),
		userStore:            userStore,
		repoStore:            repoStore,
		commitLister:         commitLister,
		postLister:           postLister,
		secretGen:            secretGen,
		webhookURL:           webhookURL,
		webhookDeliveryStore: webhookDeliveryStore,
	}
	r.setupRoutes()
	return r
}

// NewRouterWithConnectionLister creates a new web router with connection lister for rate limits (hq-w12c)
func NewRouterWithConnectionLister(userStore UserStore, connectionLister ConnectionLister) *Router {
	r := &Router{
		mux:              http.NewServeMux(),
		userStore:        userStore,
		connectionLister: connectionLister,
	}
	r.setupRoutes()
	return r
}

// NewRouterWithConnectionService creates a new web router with connection service
func NewRouterWithConnectionService(userStore UserStore, connectionService ConnectionService) *Router {
	r := &Router{
		mux:               http.NewServeMux(),
		userStore:         userStore,
		connectionService: connectionService,
	}
	r.setupRoutes()
	return r
}

// NewRouterWithBlueskyConnector creates a new web router with Bluesky connector
func NewRouterWithBlueskyConnector(userStore UserStore, blueskyConnector BlueskyConnector) *Router {
	r := &Router{
		mux:              http.NewServeMux(),
		userStore:        userStore,
		blueskyConnector: blueskyConnector,
	}
	r.setupRoutes()
	return r
}

// NewRouterWithGitHubOAuth creates a new web router with GitHub OAuth support
func NewRouterWithGitHubOAuth(userStore UserStore, githubOAuth GitHubOAuthProvider, credStore CredentialStore, baseURL string) *Router {
	r := &Router{
		mux:                 http.NewServeMux(),
		userStore:           userStore,
		githubOAuthProvider: githubOAuth,
		credentialStore:     credStore,
		baseURL:             baseURL,
	}
	r.setupRoutes()
	return r
}

// NewRouterWithThreadsOAuth creates a new web router with Threads OAuth support
func NewRouterWithThreadsOAuth(userStore UserStore, threadsOAuth ThreadsOAuthConnector, callbackURL string) *Router {
	r := &Router{
		mux:              http.NewServeMux(),
		userStore:        userStore,
		threadsOAuth:     threadsOAuth,
		oauthCallbackURL: callbackURL,
	}
	r.setupRoutes()
	return r
}

// NewRouterWithDraftLister creates a new web router with draft lister
func NewRouterWithDraftLister(userStore UserStore, draftLister DraftLister) *Router {
	r := &Router{
		mux:         http.NewServeMux(),
		userStore:   userStore,
		draftLister: draftLister,
	}
	r.setupRoutes()
	return r
}

// NewRouterWithWebhookTesterAndDeliveries creates a new web router with both webhook tester and delivery store
func NewRouterWithWebhookTesterAndDeliveries(userStore UserStore, repoStore RepositoryStore, commitLister CommitLister, postLister PostLister, secretGen SecretGenerator, webhookURL string, webhookTester WebhookTester, webhookDeliveryStore WebhookDeliveryStore) *Router {
	r := &Router{
		mux:                  http.NewServeMux(),
		userStore:            userStore,
		repoStore:            repoStore,
		commitLister:         commitLister,
		postLister:           postLister,
		secretGen:            secretGen,
		webhookURL:           webhookURL,
		webhookTester:        webhookTester,
		webhookDeliveryStore: webhookDeliveryStore,
	}
	r.setupRoutes()
	return r
}


// NewRouterWithGitHubRepoLister creates a new web router with GitHub repo listing support (alice-60)
func NewRouterWithGitHubRepoLister(userStore UserStore, repoStore RepositoryStore, commitLister CommitLister, postLister PostLister, secretGen SecretGenerator, webhookURL string, githubRepoLister GitHubRepoLister) *Router {
	r := &Router{
		mux:              http.NewServeMux(),
		userStore:        userStore,
		repoStore:        repoStore,
		commitLister:     commitLister,
		postLister:       postLister,
		secretGen:        secretGen,
		webhookURL:       webhookURL,
		githubRepoLister: githubRepoLister,
	}
	r.setupRoutes()
	return r
}

// ServeHTTP implements http.Handler
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

func (r *Router) setupRoutes() {
	// Static files
	staticContent, _ := fs.Sub(staticFS, "static")
	r.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticContent))))

	// Pages
	r.mux.HandleFunc("/", r.handleHome)
	r.mux.HandleFunc("/login", r.handleLogin)
	r.mux.HandleFunc("/signup", r.handleSignup)
	r.mux.HandleFunc("/dashboard", r.handleDashboard)
	r.mux.HandleFunc("/logout", r.handleLogout)
	r.mux.HandleFunc("/connections", r.handleConnections)
	r.mux.HandleFunc("/connections/new", r.handleConnectionsNew)
	r.mux.HandleFunc("/repositories", r.handleRepositories)
	r.mux.HandleFunc("/repositories/new", r.handleRepositoriesNew)
	r.mux.HandleFunc("/drafts", r.handleDrafts)
	r.mux.HandleFunc("GET /drafts/{id}", r.handleDraftPreview)
	r.mux.HandleFunc("POST /drafts/{id}/edit", r.handleDraftEdit)
	r.mux.HandleFunc("POST /drafts/{id}/regenerate", r.handleDraftRegenerate)
	r.mux.HandleFunc("POST /drafts/{id}/delete", r.handleDraftDelete)
	r.mux.HandleFunc("POST /drafts/{id}/post", r.handleDraftPost)
	r.mux.HandleFunc("/repositories/success", r.handleRepositoriesSuccess)
	r.mux.HandleFunc("/repositories/{id}", r.handleRepositoryView)
	r.mux.HandleFunc("GET /repositories/{id}/edit", r.handleRepositoryEdit)
	r.mux.HandleFunc("POST /repositories/{id}/edit", r.handleRepositoryEditPost)
	r.mux.HandleFunc("GET /repositories/{id}/delete", r.handleRepositoryDelete)
	r.mux.HandleFunc("POST /repositories/{id}/delete", r.handleRepositoryDeletePost)
	r.mux.HandleFunc("/repositories/{id}/webhook/test", r.handleWebhookTest)
	r.mux.HandleFunc("/repositories/{id}/webhook/regenerate", r.handleWebhookRegenerate)
	r.mux.HandleFunc("GET /repositories/{id}/webhooks", r.handleWebhookDeliveries)

	// Connection management
	r.mux.HandleFunc("GET /connections/bluesky/connect", r.handleBlueskyConnect)
	r.mux.HandleFunc("POST /connections/bluesky/connect", r.handleBlueskyConnectPost)
	r.mux.HandleFunc("GET /connections/{platform}/disconnect", r.handleConnectionDisconnect)
	r.mux.HandleFunc("POST /connections/{platform}/disconnect", r.handleConnectionDisconnectPost)

	// GitHub OAuth routes
	r.mux.HandleFunc("GET /oauth/github", r.handleGitHubOAuthInitiate)
	r.mux.HandleFunc("GET /oauth/github/callback", r.handleGitHubOAuthCallback)

	// Threads OAuth routes
	r.mux.HandleFunc("GET /oauth/threads", r.handleThreadsOAuth)
	r.mux.HandleFunc("GET /oauth/threads/callback", r.handleThreadsOAuthCallback)
	r.mux.HandleFunc("POST /oauth/threads/refresh", r.handleThreadsTokenRefresh)

	// GitHub App setup callback
	r.mux.HandleFunc("GET /github-app/setup", r.handleGitHubAppSetup)
}

func (r *Router) handleHome(w http.ResponseWriter, req *http.Request) {
	// Only handle exact "/" path
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}

	r.renderPage(w, "home.html", PageData{
		Title: "Home",
	})
}

func (r *Router) handleLogin(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		r.handleLoginPost(w, req)
		return
	}

	r.renderPageWithCSRF(w, req, "login.html", PageData{
		Title: "Login",
	})
}

func (r *Router) handleLoginPost(w http.ResponseWriter, req *http.Request) {
	// Check rate limit to prevent brute force attacks
	if !auth.CheckRateLimit(r.authRateLimiter, w, req) {
		return
	}

	// Validate CSRF token
	cookieToken := auth.GetCSRFTokenFromCookie(req)
	formToken := auth.GetCSRFTokenFromRequest(req)
	if !auth.ValidateCSRFToken(cookieToken, formToken) {
		http.Error(w, "Forbidden - CSRF token validation failed", http.StatusForbidden)
		return
	}

	// Parse form
	if err := req.ParseForm(); err != nil {
		r.renderPageWithCSRF(w, req, "login.html", PageData{
			Title: "Login",
			Error: "Invalid form data",
		})
		return
	}

	email := req.FormValue("email")
	password := req.FormValue("password")

	// Validate input
	if email == "" || password == "" {
		r.renderPageWithCSRF(w, req, "login.html", PageData{
			Title: "Login",
			Error: "Email and password are required",
		})
		return
	}

	// Check if we have a user store
	if r.userStore == nil {
		r.renderPageWithCSRF(w, req, "login.html", PageData{
			Title: "Login",
			Error: "Authentication not configured",
		})
		return
	}

	// Look up user
	user, err := r.userStore.GetUserByEmail(req.Context(), email)
	if err != nil {
		r.renderPageWithCSRF(w, req, "login.html", PageData{
			Title: "Login",
			Error: "Invalid email or password",
		})
		return
	}

	if user == nil {
		// User not found - use same error message for security
		r.renderPageWithCSRF(w, req, "login.html", PageData{
			Title: "Login",
			Error: "Invalid email or password",
		})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		r.renderPageWithCSRF(w, req, "login.html", PageData{
			Title: "Login",
			Error: "Invalid email or password",
		})
		return
	}

	// Generate JWT token
	token, err := auth.GenerateToken(user.ID, user.Email)
	if err != nil {
		r.renderPageWithCSRF(w, req, "login.html", PageData{
			Title: "Login",
			Error: "Failed to create session",
		})
		return
	}

	// Set auth cookie (24 hours)
	auth.SetAuthCookie(w, token, 86400)

	// Redirect to dashboard
	http.Redirect(w, req, "/dashboard", http.StatusSeeOther)
}

func (r *Router) handleSignup(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		r.handleSignupPost(w, req)
		return
	}

	r.renderPageWithCSRF(w, req, "signup.html", PageData{
		Title: "Sign Up",
	})
}

func (r *Router) handleSignupPost(w http.ResponseWriter, req *http.Request) {
	// Check rate limit to prevent abuse
	if !auth.CheckRateLimit(r.authRateLimiter, w, req) {
		return
	}

	// Validate CSRF token
	cookieToken := auth.GetCSRFTokenFromCookie(req)
	formToken := auth.GetCSRFTokenFromRequest(req)
	if !auth.ValidateCSRFToken(cookieToken, formToken) {
		http.Error(w, "Forbidden - CSRF token validation failed", http.StatusForbidden)
		return
	}

	// Parse form
	if err := req.ParseForm(); err != nil {
		r.renderPageWithCSRF(w, req, "signup.html", PageData{
			Title: "Sign Up",
			Error: "Invalid form data",
		})
		return
	}

	email := req.FormValue("email")
	password := req.FormValue("password")
	confirmPassword := req.FormValue("confirm_password")

	// Validate input
	if email == "" || password == "" {
		r.renderPageWithCSRF(w, req, "signup.html", PageData{
			Title: "Sign Up",
			Error: "Email and password are required",
		})
		return
	}

	// Validate password length (min 8 characters)
	if len(password) < 8 {
		r.renderPageWithCSRF(w, req, "signup.html", PageData{
			Title: "Sign Up",
			Error: "Password must be at least 8 characters",
		})
		return
	}

	// Validate passwords match
	if password != confirmPassword {
		r.renderPageWithCSRF(w, req, "signup.html", PageData{
			Title: "Sign Up",
			Error: "Passwords do not match",
		})
		return
	}

	// Check if we have a user store
	if r.userStore == nil {
		r.renderPageWithCSRF(w, req, "signup.html", PageData{
			Title: "Sign Up",
			Error: "Registration not configured",
		})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		r.renderPageWithCSRF(w, req, "signup.html", PageData{
			Title: "Sign Up",
			Error: "Failed to process registration",
		})
		return
	}

	// Create user
	_, err = r.userStore.CreateUser(req.Context(), email, string(hashedPassword))
	if err != nil {
		if err == handlers.ErrDuplicateEmail {
			r.renderPageWithCSRF(w, req, "signup.html", PageData{
				Title: "Sign Up",
				Error: "An account with this email already exists",
			})
			return
		}
		r.renderPageWithCSRF(w, req, "signup.html", PageData{
			Title: "Sign Up",
			Error: "Failed to create account",
		})
		return
	}

	// Redirect to login
	http.Redirect(w, req, "/login", http.StatusSeeOther)
}

// DashboardData holds data specific to the dashboard page
type DashboardData struct {
	Repositories []*handlers.Repository
	Commits      []*DashboardCommit
	Posts        []*DashboardPost
	Activities   []*DashboardActivity
	IsEmpty      bool
	GitHubAppURL string // URL for installing the GitHub App (shown in empty state CTA)
	// Pagination for activities
	ActivityPage       int
	ActivityTotalPages int
	ActivityTotal      int
	ActivityPageSize   int
}

func (r *Router) handleDashboard(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		// Redirect to login for HTML requests
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		// Invalid/expired token - redirect to login
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Parse activity pagination params
	const activityPageSize = 10
	activityPage := 1
	if pageStr := req.URL.Query().Get("activity_page"); pageStr != "" {
		if p, err := parsePageNumber(pageStr); err == nil && p > 0 {
			activityPage = p
		}
	}

	// Fetch dashboard data
	dashData := &DashboardData{
		ActivityPage:     activityPage,
		ActivityPageSize: activityPageSize,
		GitHubAppURL:     r.githubAppURL,
	}

	// Get repositories if store is available
	if r.repoStore != nil {
		repos, err := r.repoStore.ListRepositoriesByUser(req.Context(), claims.UserID)
		if err == nil {
			dashData.Repositories = repos
		}
	}

	// Get commits if lister is available
	if r.commitLister != nil {
		commits, err := r.commitLister.ListCommitsByUser(req.Context(), claims.UserID)
		if err == nil {
			dashData.Commits = commits
		}
	}

	// Get posts if lister is available
	if r.postLister != nil {
		posts, err := r.postLister.ListPostsByUser(req.Context(), claims.UserID)
		if err == nil {
			dashData.Posts = posts
		}
	}

	// Get activities if lister is available
	if r.activityLister != nil {
		offset := (activityPage - 1) * activityPageSize
		activities, err := r.activityLister.ListActivitiesByUser(req.Context(), claims.UserID, activityPageSize, offset)
		if err == nil {
			dashData.Activities = activities
		}
		// Get total count for pagination
		total, err := r.activityLister.CountActivitiesByUser(req.Context(), claims.UserID)
		if err == nil {
			dashData.ActivityTotal = total
			dashData.ActivityTotalPages = (total + activityPageSize - 1) / activityPageSize
			if dashData.ActivityTotalPages == 0 {
				dashData.ActivityTotalPages = 1
			}
		}
	}

	// Check if dashboard is empty (no repos)
	dashData.IsEmpty = len(dashData.Repositories) == 0

	r.renderPage(w, "dashboard.html", PageData{
		Title: "Dashboard",
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data:       dashData,
		DraftCount: r.getDraftCount(req.Context(), claims.UserID),
	})
}

// parsePageNumber parses a page number from a string, returning 1 if invalid
func parsePageNumber(s string) (int, error) {
	var page int
	_, err := fmt.Sscanf(s, "%d", &page)
	return page, err
}

func (r *Router) handleLogout(w http.ResponseWriter, req *http.Request) {
	// Only accept POST requests (form submission)
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Clear auth cookie
	auth.ClearAuthCookie(w)

	// Redirect to login page
	http.Redirect(w, req, "/login", http.StatusSeeOther)
}

// =============================================================================
// Connections Page (hq-w12c)
// =============================================================================

// ConnectionsPageData holds data for the connections page
type ConnectionsPageData struct {
	Connections []*ConnectionData
}

func (r *Router) handleConnections(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Get connections with rate limits
	var connections []*ConnectionData
	if r.connectionLister != nil {
		connections, err = r.connectionLister.ListConnectionsWithRateLimits(req.Context(), claims.UserID)
		if err != nil {
			// Log error but show empty state
			connections = []*ConnectionData{}
		}
	}

	r.renderPage(w, "connections.html", PageData{
		Title:      "Connections",
		User:       &UserData{ID: claims.UserID, Email: claims.Email},
		Data:       ConnectionsPageData{Connections: connections},
		DraftCount: r.getDraftCount(req.Context(), claims.UserID),
	})
}

// ConnectionsNewData holds data for the connections_new page
type ConnectionsNewData struct {
	ThreadsEnabled bool
}

func (r *Router) handleConnectionsNew(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Check which platforms are enabled
	data := ConnectionsNewData{
		ThreadsEnabled: r.threadsOAuth != nil,
	}

	r.renderPage(w, "connections_new.html", PageData{
		Title: "Connect Account",
		User:  &UserData{ID: claims.UserID, Email: claims.Email},
		Data:  data,
	})
}

func (r *Router) handleBlueskyConnect(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	r.renderPage(w, "bluesky_connect.html", PageData{
		Title: "Connect Bluesky",
		User:  &UserData{ID: claims.UserID, Email: claims.Email},
	})
}

func (r *Router) handleBlueskyConnectPost(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Parse form
	if err := req.ParseForm(); err != nil {
		r.renderPage(w, "bluesky_connect.html", PageData{
			Title: "Connect Bluesky",
			User:  &UserData{ID: claims.UserID, Email: claims.Email},
			Error: "Invalid form data",
		})
		return
	}

	handle := strings.TrimSpace(req.FormValue("handle"))
	appPassword := req.FormValue("app_password")

	// Validate input
	if handle == "" || appPassword == "" {
		r.renderPage(w, "bluesky_connect.html", PageData{
			Title: "Connect Bluesky",
			User:  &UserData{ID: claims.UserID, Email: claims.Email},
			Error: "Handle and App Password are required",
		})
		return
	}

	// Check if connector is available
	if r.blueskyConnector == nil {
		r.renderPage(w, "bluesky_connect.html", PageData{
			Title: "Connect Bluesky",
			User:  &UserData{ID: claims.UserID, Email: claims.Email},
			Error: "Bluesky connection not configured",
		})
		return
	}

	// Connect to Bluesky
	result, err := r.blueskyConnector.Connect(req.Context(), claims.UserID, handle, appPassword)
	if err != nil {
		errMsg := "Failed to connect to Bluesky"
		if err.Error() != "" {
			errMsg = err.Error()
		}
		r.renderPage(w, "bluesky_connect.html", PageData{
			Title: "Connect Bluesky",
			User:  &UserData{ID: claims.UserID, Email: claims.Email},
			Error: errMsg,
		})
		return
	}

	if !result.Success {
		r.renderPage(w, "bluesky_connect.html", PageData{
			Title: "Connect Bluesky",
			User:  &UserData{ID: claims.UserID, Email: claims.Email},
			Error: result.Error,
		})
		return
	}

	// Success - redirect to connections list
	http.Redirect(w, req, "/connections?connected=bluesky", http.StatusSeeOther)
}

// RepositoriesListData holds data for the repositories list page
type RepositoriesListData struct {
	Repositories []*handlers.Repository
}

// DraftsListData holds data for the drafts list page
type DraftsListData struct {
	Drafts []*DraftItem
}

func (r *Router) handleRepositories(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Fetch repositories
	listData := &RepositoriesListData{}

	if r.repoStore != nil {
		repos, err := r.repoStore.ListRepositoriesByUser(req.Context(), claims.UserID)
		if err != nil {
			r.renderPage(w, "repositories_list.html", PageData{
				Title: "Repositories",
				User: &UserData{
					ID:    claims.UserID,
					Email: claims.Email,
				},
				Error: "Failed to load repositories",
			})
			return
		}
		listData.Repositories = repos
	}

	// Check for flash message from GitHub App installation
	var flash *FlashMessage
	if req.URL.Query().Get("installed") == "true" {
		flash = &FlashMessage{
			Type:    "success",
			Message: "GitHub App installed successfully! Your repositories have been synced.",
		}
	}

	r.renderPage(w, "repositories_list.html", PageData{
		Title: "Repositories",
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data:       listData,
		Flash:      flash,
		DraftCount: r.getDraftCount(req.Context(), claims.UserID),
	})
}

// RepoSelectionData holds data for the repo selection page
type RepoSelectionData struct {
	GitHubRepos      []GitHubRepoItem
	HasGitHubRepos   bool
	ConnectedRepoIDs map[string]bool // Map of GitHub URLs that are already connected
	GitHubAppURL     string          // URL for installing the GitHub App
}

// GitHubRepoItem represents a repo item for display in the selection list
type GitHubRepoItem struct {
	ID          int64
	Name        string
	FullName    string
	HTMLURL     string
	Description string
	Private     bool
	IsConnected bool
}

func (r *Router) handleDrafts(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Fetch drafts
	listData := &DraftsListData{}

	if r.draftLister != nil {
		drafts, err := r.draftLister.ListDraftsByUser(req.Context(), claims.UserID)
		if err != nil {
			r.renderPage(w, "drafts.html", PageData{
				Title: "Drafts",
				User: &UserData{
					ID:    claims.UserID,
					Email: claims.Email,
				},
				Error: "Failed to load drafts",
			})
			return
		}
		listData.Drafts = drafts
	}

	r.renderPage(w, "drafts.html", PageData{
		Title: "Drafts",
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data: listData,
	})
}

func (r *Router) handleRepositoriesNew(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	if req.Method == http.MethodPost {
		r.handleRepositoriesNewPost(w, req, claims)
		return
	}

	// If we have a GitHub repo lister, show the selection page
	if r.githubRepoLister != nil {
		r.handleRepoSelectionPage(w, req, claims)
		return
	}

	// Fall back to manual URL form
	pageData := PageData{
		Title: "Add Repository",
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
	}
	if r.githubAppURL != "" {
		pageData.Data = &RepoSelectionData{
			GitHubAppURL: r.githubAppURL,
		}
	}
	r.renderPageWithCSRF(w, req, "repositories_new.html", pageData)
}

// handleRepoSelectionPage renders the GitHub repo selection page
func (r *Router) handleRepoSelectionPage(w http.ResponseWriter, req *http.Request, claims *auth.Claims) {
	// Get connected repos to mark as already added
	connectedRepos := make(map[string]bool)
	if r.repoStore != nil {
		repos, err := r.repoStore.ListRepositoriesByUser(req.Context(), claims.UserID)
		if err == nil {
			for _, repo := range repos {
				connectedRepos[repo.GitHubURL] = true
			}
		}
	}

	// Fetch GitHub repos - for now use an empty access token since we get it from mock in tests
	// In production, this would come from credentialStore
	accessToken := ""
	if r.credentialStore != nil {
		creds, err := r.credentialStore.GetCredentials(req.Context(), claims.UserID, "github")
		if err == nil && creds != nil {
			accessToken = creds.AccessToken
		}
	}

	githubRepos, err := r.githubRepoLister.ListUserRepos(req.Context(), accessToken)
	if err != nil {
		r.renderPageWithCSRF(w, req, "repositories_new.html", PageData{
			Title: "Add Repository",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Data: &RepoSelectionData{
				GitHubAppURL: r.githubAppURL,
			},
			Error: "Failed to fetch GitHub repositories",
		})
		return
	}

	// Convert to display items
	repoItems := make([]GitHubRepoItem, 0, len(githubRepos))
	for _, repo := range githubRepos {
		repoItems = append(repoItems, GitHubRepoItem{
			ID:          repo.ID,
			Name:        repo.Name,
			FullName:    repo.FullName,
			HTMLURL:     repo.HTMLURL,
			Description: repo.Description,
			Private:     repo.Private,
			IsConnected: connectedRepos[repo.HTMLURL],
		})
	}

	r.renderPageWithCSRF(w, req, "repositories_new.html", PageData{
		Title: "Add Repository",
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data: &RepoSelectionData{
			GitHubRepos:      repoItems,
			HasGitHubRepos:   len(repoItems) > 0,
			ConnectedRepoIDs: connectedRepos,
			GitHubAppURL:     r.githubAppURL,
		},
	})
}

func (r *Router) handleRepositoriesNewPost(w http.ResponseWriter, req *http.Request, claims *auth.Claims) {
	// Validate CSRF token
	cookieToken := auth.GetCSRFTokenFromCookie(req)
	formToken := auth.GetCSRFTokenFromRequest(req)
	if !auth.ValidateCSRFToken(cookieToken, formToken) {
		http.Error(w, "Forbidden - CSRF token validation failed", http.StatusForbidden)
		return
	}

	// Parse form
	if err := req.ParseForm(); err != nil {
		r.renderPageWithCSRF(w, req, "repositories_new.html", PageData{
			Title: "Add Repository",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Invalid form data",
		})
		return
	}

	// Check if this is multi-select form (repos field) or single URL form (github_url field)
	selectedRepos := req.Form["repos"]
	if len(selectedRepos) > 0 {
		r.handleRepoSelectionPost(w, req, claims, selectedRepos)
		return
	}

	// Single URL form - fallback mode
	githubURL := req.FormValue("github_url")

	// Validate GitHub URL
	if err := r.validateGitHubURL(githubURL); err != nil {
		r.renderPage(w, "repositories_new.html", PageData{
			Title: "Add Repository",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: err.Error(),
		})
		return
	}

	// Check if stores are configured
	if r.repoStore == nil || r.secretGen == nil {
		r.renderPage(w, "repositories_new.html", PageData{
			Title: "Add Repository",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Repository creation not configured",
		})
		return
	}

	// Generate webhook secret
	secret, err := r.secretGen.Generate()
	if err != nil {
		r.renderPage(w, "repositories_new.html", PageData{
			Title: "Add Repository",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Failed to generate webhook secret",
		})
		return
	}

	// Create repository
	repo, err := r.repoStore.CreateRepository(req.Context(), claims.UserID, githubURL, secret)
	if err != nil {
		errMsg := "Failed to create repository"
		if err == handlers.ErrDuplicateRepository {
			errMsg = "This repository has already been added"
		}
		r.renderPage(w, "repositories_new.html", PageData{
			Title: "Add Repository",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: errMsg,
		})
		return
	}

	// Build webhook URL
	webhookURL := fmt.Sprintf("%s/webhooks/github/%s", r.webhookURL, repo.ID)

	// Redirect to success page with query params
	http.Redirect(w, req, fmt.Sprintf("/repositories/success?webhook_url=%s&webhook_secret=%s",
		url.QueryEscape(webhookURL),
		url.QueryEscape(secret)), http.StatusSeeOther)
}

// handleRepoSelectionPost handles POST from the multi-select repo form
func (r *Router) handleRepoSelectionPost(w http.ResponseWriter, req *http.Request, claims *auth.Claims, selectedRepos []string) {
	// Check if stores are configured
	if r.repoStore == nil || r.secretGen == nil {
		r.renderPage(w, "repositories_new.html", PageData{
			Title: "Add Repository",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Repository creation not configured",
		})
		return
	}

	// Create each selected repository
	for _, repoURL := range selectedRepos {
		// Validate GitHub URL
		if err := r.validateGitHubURL(repoURL); err != nil {
			continue // Skip invalid URLs
		}

		// Generate webhook secret for each repo
		secret, err := r.secretGen.Generate()
		if err != nil {
			continue // Skip if we can't generate a secret
		}

		// Create repository (ignore duplicates)
		_, err = r.repoStore.CreateRepository(req.Context(), claims.UserID, repoURL, secret)
		if err != nil && err != handlers.ErrDuplicateRepository {
			// Log error but continue with other repos
			continue
		}
	}

	// Redirect to repositories list
	http.Redirect(w, req, "/repositories", http.StatusSeeOther)
}

// validateGitHubURL validates that the URL is a valid GitHub repository URL
func (r *Router) validateGitHubURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("GitHub URL is required")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL format")
	}

	// Must be HTTPS
	if parsed.Scheme != "https" {
		return fmt.Errorf("URL must use HTTPS")
	}

	// Must be github.com
	if parsed.Host != "github.com" {
		return fmt.Errorf("URL must be a GitHub repository (github.com)")
	}

	// Path must have at least owner/repo format
	path := strings.Trim(parsed.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("URL must be a valid GitHub repository (github.com/owner/repo)")
	}

	return nil
}

// RepositorySuccessData holds data for the repository success page
type RepositorySuccessData struct {
	WebhookURL    string
	WebhookSecret string
}

// RepositoryViewData holds data for the single repository view page
type RepositoryViewData struct {
	Repository *handlers.Repository
	WebhookURL string
	RepoName   string
}

func (r *Router) handleRepositoriesSuccess(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Get query params
	webhookURL := req.URL.Query().Get("webhook_url")
	webhookSecret := req.URL.Query().Get("webhook_secret")

	// Validate required params
	if webhookURL == "" || webhookSecret == "" {
		r.renderPage(w, "repository_success.html", PageData{
			Title: "Repository Added",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Missing webhook configuration. Please add your repository again.",
		})
		return
	}

	r.renderPage(w, "repository_success.html", PageData{
		Title: "Repository Added",
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data: &RepositorySuccessData{
			WebhookURL:    webhookURL,
			WebhookSecret: webhookSecret,
		},
	})
}

// RepositoryEditData holds data for the repository edit page
type RepositoryEditData struct {
	Repository *handlers.Repository
}

// RepositoryDeleteData holds data for the repository delete confirmation page
type RepositoryDeleteData struct {
	Repository *handlers.Repository
	RepoName   string
}

func (r *Router) handleRepositoryView(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Get repository ID from path
	repoID := req.PathValue("id")
	if repoID == "" {
		http.NotFound(w, req)
		return
	}

	// Check if store is configured
	if r.repoStore == nil {
		r.renderPage(w, "repository_view.html", PageData{
			Title: "Repository",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Repository store not configured",
		})
		return
	}

	// Get repository
	repo, err := r.repoStore.GetRepositoryByID(req.Context(), repoID)
	if err != nil {
		r.renderPage(w, "repository_view.html", PageData{
			Title: "Repository",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Failed to load repository",
		})
		return
	}

	// Repository not found
	if repo == nil {
		http.NotFound(w, req)
		return
	}

	// Verify the repository belongs to the current user
	if repo.UserID != claims.UserID {
		http.NotFound(w, req)
		return
	}

	// Extract repository name from GitHub URL (owner/repo)
	repoName := extractRepoName(repo.GitHubURL)

	// Build webhook URL
	webhookURL := fmt.Sprintf("%s/webhooks/github/%s", r.webhookURL, repo.ID)

	r.renderPage(w, "repository_view.html", PageData{
		Title: repoName,
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data: &RepositoryViewData{
			Repository: repo,
			WebhookURL: webhookURL,
			RepoName:   repoName,
		},
	})
}

// extractRepoName extracts the owner/repo portion from a GitHub URL
func extractRepoName(githubURL string) string {
	parsed, err := url.Parse(githubURL)
	if err != nil {
		return githubURL
	}
	path := strings.Trim(parsed.Path, "/")
	return path
}

func (r *Router) handleRepositoryEdit(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Get repository ID from path
	repoID := req.PathValue("id")
	if repoID == "" {
		http.NotFound(w, req)
		return
	}

	// Check if repo store is available
	if r.repoStore == nil {
		http.Error(w, "Repository store not configured", http.StatusInternalServerError)
		return
	}

	// Fetch repository
	repo, err := r.repoStore.GetRepositoryByID(req.Context(), repoID)
	if err != nil {
		http.Error(w, "Failed to load repository", http.StatusInternalServerError)
		return
	}
	if repo == nil {
		http.NotFound(w, req)
		return
	}

	// Verify ownership
	if repo.UserID != claims.UserID {
		http.NotFound(w, req)
		return
	}

	r.renderPage(w, "repository_edit.html", PageData{
		Title: "Edit Repository",
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data: &RepositoryEditData{
			Repository: repo,
		},
	})
}

func (r *Router) handleRepositoryEditPost(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Get repository ID from path
	repoID := req.PathValue("id")
	if repoID == "" {
		http.NotFound(w, req)
		return
	}

	// Check if repo store is available
	if r.repoStore == nil {
		http.Error(w, "Repository store not configured", http.StatusInternalServerError)
		return
	}

	// Fetch repository to verify ownership
	repo, err := r.repoStore.GetRepositoryByID(req.Context(), repoID)
	if err != nil {
		http.Error(w, "Failed to load repository", http.StatusInternalServerError)
		return
	}
	if repo == nil {
		http.NotFound(w, req)
		return
	}

	// Verify ownership
	if repo.UserID != claims.UserID {
		http.NotFound(w, req)
		return
	}

	// Parse form
	if err := req.ParseForm(); err != nil {
		r.renderPage(w, "repository_edit.html", PageData{
			Title: "Edit Repository",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Invalid form data",
			Data:  &RepositoryEditData{Repository: repo},
		})
		return
	}

	name := req.FormValue("name")
	isActive := req.FormValue("is_active") == "true"

	// Validate name
	if name == "" {
		r.renderPage(w, "repository_edit.html", PageData{
			Title: "Edit Repository",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Repository name is required",
			Data:  &RepositoryEditData{Repository: repo},
		})
		return
	}

	// Update repository
	_, err = r.repoStore.UpdateRepository(req.Context(), repoID, name, isActive)
	if err != nil {
		r.renderPage(w, "repository_edit.html", PageData{
			Title: "Edit Repository",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Failed to update repository",
			Data:  &RepositoryEditData{Repository: repo},
		})
		return
	}

	// Redirect to repositories list
	http.Redirect(w, req, "/repositories", http.StatusSeeOther)
}

func (r *Router) handleRepositoryDelete(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Get repository ID from path
	repoID := req.PathValue("id")
	if repoID == "" {
		http.NotFound(w, req)
		return
	}

	// Check if repo store is available
	if r.repoStore == nil {
		http.Error(w, "Repository store not configured", http.StatusInternalServerError)
		return
	}

	// Fetch repository
	repo, err := r.repoStore.GetRepositoryByID(req.Context(), repoID)
	if err != nil {
		http.Error(w, "Failed to load repository", http.StatusInternalServerError)
		return
	}
	if repo == nil {
		http.NotFound(w, req)
		return
	}

	// Verify ownership
	if repo.UserID != claims.UserID {
		http.NotFound(w, req)
		return
	}

	// Extract repository name from GitHub URL
	repoName := extractRepoName(repo.GitHubURL)

	r.renderPage(w, "repository_delete.html", PageData{
		Title: "Delete Repository",
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data: &RepositoryDeleteData{
			Repository: repo,
			RepoName:   repoName,
		},
	})
}

func (r *Router) handleRepositoryDeletePost(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Get repository ID from path
	repoID := req.PathValue("id")
	if repoID == "" {
		http.NotFound(w, req)
		return
	}

	// Check if repo store is available
	if r.repoStore == nil {
		http.Error(w, "Repository store not configured", http.StatusInternalServerError)
		return
	}

	// Fetch repository to verify ownership
	repo, err := r.repoStore.GetRepositoryByID(req.Context(), repoID)
	if err != nil {
		http.Error(w, "Failed to load repository", http.StatusInternalServerError)
		return
	}
	if repo == nil {
		http.NotFound(w, req)
		return
	}

	// Verify ownership
	if repo.UserID != claims.UserID {
		http.NotFound(w, req)
		return
	}

	// Delete the repository
	err = r.repoStore.DeleteRepository(req.Context(), repoID)
	if err != nil {
		repoName := extractRepoName(repo.GitHubURL)
		r.renderPage(w, "repository_delete.html", PageData{
			Title: "Delete Repository",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Failed to delete repository",
			Data: &RepositoryDeleteData{
				Repository: repo,
				RepoName:   repoName,
			},
		})
		return
	}

	// Redirect to repositories list
	http.Redirect(w, req, "/repositories", http.StatusSeeOther)
}

// WebhookTestResult holds the result of a webhook test
type WebhookTestResult struct {
	Success    bool
	StatusCode int
	Error      string
}

func (r *Router) handleWebhookTest(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Only accept POST requests
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get repository ID from path
	repoID := req.PathValue("id")
	if repoID == "" {
		http.NotFound(w, req)
		return
	}

	// Check if store is configured
	if r.repoStore == nil {
		http.Error(w, "Repository store not configured", http.StatusInternalServerError)
		return
	}

	// Get repository
	repo, err := r.repoStore.GetRepositoryByID(req.Context(), repoID)
	if err != nil {
		http.Error(w, "Failed to load repository", http.StatusInternalServerError)
		return
	}

	// Repository not found
	if repo == nil {
		http.NotFound(w, req)
		return
	}

	// Verify the repository belongs to the current user
	if repo.UserID != claims.UserID {
		http.NotFound(w, req)
		return
	}

	// Build webhook URL
	webhookURL := fmt.Sprintf("%s/webhooks/github/%s", r.webhookURL, repo.ID)

	// Test the webhook
	var result WebhookTestResult
	var statusCode int
	var testErr error

	if r.webhookTester != nil {
		statusCode, testErr = r.webhookTester.TestWebhook(req.Context(), webhookURL, repo.WebhookSecret)
		if testErr != nil {
			result = WebhookTestResult{
				Success: false,
				Error:   fmt.Sprintf("Connection failed: %v", testErr),
			}
		} else if statusCode >= 200 && statusCode < 300 {
			result = WebhookTestResult{
				Success:    true,
				StatusCode: statusCode,
			}
		} else {
			result = WebhookTestResult{
				Success:    false,
				StatusCode: statusCode,
				Error:      fmt.Sprintf("Webhook returned status %d", statusCode),
			}
		}

		// Record the delivery if store is configured
		if r.webhookDeliveryStore != nil {
			testPayload := []byte(`{"zen": "Webhook test ping", "hook_id": 0}`)
			var errorMsg *string
			if testErr != nil {
				errStr := testErr.Error()
				errorMsg = &errStr
			} else if !result.Success {
				errorMsg = &result.Error
			}
			// Ignore errors from recording - test result is what matters to user
			_, _ = r.webhookDeliveryStore.CreateDelivery(req.Context(), CreateDeliveryParams{
				RepositoryID: repoID,
				DeliveryID:   fmt.Sprintf("test-ping-%d", time.Now().UnixNano()),
				EventType:    "ping",
				Payload:      testPayload,
				StatusCode:   statusCode,
				ErrorMessage: errorMsg,
			})
		}
	} else {
		result = WebhookTestResult{
			Success: false,
			Error:   "Webhook tester not configured",
		}
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if result.Success {
		fmt.Fprintf(w, `{"success": true, "status_code": %d}`, result.StatusCode)
	} else {
		fmt.Fprintf(w, `{"success": false, "error": %q}`, result.Error)
	}
}

// WebhookRegenerateData holds data for the webhook regenerate success page
type WebhookRegenerateData struct {
	Repository    *handlers.Repository
	WebhookURL    string
	WebhookSecret string
	RepoName      string
}

func (r *Router) handleWebhookRegenerate(w http.ResponseWriter, req *http.Request) {
	// Only allow POST
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Get repository ID from path
	repoID := req.PathValue("id")
	if repoID == "" {
		http.NotFound(w, req)
		return
	}

	// Check if stores are configured
	if r.repoStore == nil || r.secretGen == nil {
		r.renderPage(w, "webhook_regenerate.html", PageData{
			Title: "Regenerate Webhook Secret",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Webhook regeneration not configured",
		})
		return
	}

	// Get repository
	repo, err := r.repoStore.GetRepositoryByID(req.Context(), repoID)
	if err != nil {
		r.renderPage(w, "webhook_regenerate.html", PageData{
			Title: "Regenerate Webhook Secret",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Failed to load repository",
		})
		return
	}

	// Repository not found
	if repo == nil {
		http.NotFound(w, req)
		return
	}

	// Verify the repository belongs to the current user
	if repo.UserID != claims.UserID {
		http.NotFound(w, req)
		return
	}

	// Generate new webhook secret
	newSecret, err := r.secretGen.Generate()
	if err != nil {
		r.renderPage(w, "webhook_regenerate.html", PageData{
			Title: "Regenerate Webhook Secret",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Failed to generate new webhook secret",
		})
		return
	}

	// Update the repository with the new secret
	err = r.repoStore.UpdateWebhookSecret(req.Context(), repoID, newSecret)
	if err != nil {
		r.renderPage(w, "webhook_regenerate.html", PageData{
			Title: "Regenerate Webhook Secret",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Failed to update webhook secret",
		})
		return
	}

	// Extract repository name from GitHub URL
	repoName := extractRepoName(repo.GitHubURL)

	// Build webhook URL
	webhookURL := fmt.Sprintf("%s/webhooks/github/%s", r.webhookURL, repo.ID)

	// Render success page showing the new secret (one-time display)
	r.renderPage(w, "webhook_regenerate.html", PageData{
		Title: "Webhook Secret Regenerated",
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data: &WebhookRegenerateData{
			Repository:    repo,
			WebhookURL:    webhookURL,
			WebhookSecret: newSecret,
			RepoName:      repoName,
		},
	})
}

// =============================================================================
// Threads OAuth Handlers (alice-69)
// =============================================================================

// oauthStateCookieName is the cookie name for storing OAuth state
const oauthStateCookieName = "oauth_state"

// generateOAuthState generates a cryptographically secure random state string
func generateOAuthState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// handleThreadsOAuth initiates the Threads OAuth flow
// GET /oauth/threads
func (r *Router) handleThreadsOAuth(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie - user must be logged in
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	_, err = auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Check if Threads OAuth is configured
	if r.threadsOAuth == nil {
		http.Redirect(w, req, "/connections?error=threads_not_configured", http.StatusSeeOther)
		return
	}

	// Generate state for CSRF protection
	state, err := generateOAuthState()
	if err != nil {
		http.Redirect(w, req, "/connections?error=state_generation_failed", http.StatusSeeOther)
		return
	}

	// Store state in a cookie (expires in 10 minutes)
	stateCookie := &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	}
	http.SetCookie(w, stateCookie)

	// Build callback URL
	callbackURL := r.oauthCallbackURL + "/oauth/threads/callback"

	// Get auth URL from provider and redirect
	authURL := r.threadsOAuth.GetAuthURL(state, callbackURL)
	http.Redirect(w, req, authURL, http.StatusTemporaryRedirect)
}

// handleThreadsOAuthCallback handles the Threads OAuth callback
// GET /oauth/threads/callback
func (r *Router) handleThreadsOAuthCallback(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie - user must be logged in
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login?error=unauthorized", http.StatusSeeOther)
		return
	}

	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login?error=unauthorized", http.StatusSeeOther)
		return
	}

	// Check if Threads OAuth is configured
	if r.threadsOAuth == nil {
		http.Redirect(w, req, "/connections?error=threads_not_configured", http.StatusSeeOther)
		return
	}

	// Check for OAuth error from provider
	if oauthError := req.URL.Query().Get("error"); oauthError != "" {
		errorDesc := req.URL.Query().Get("error_description")
		if errorDesc == "" {
			errorDesc = oauthError
		}
		http.Redirect(w, req, "/connections?error="+url.QueryEscape(errorDesc), http.StatusSeeOther)
		return
	}

	// Get the authorization code
	code := req.URL.Query().Get("code")
	if code == "" {
		http.Redirect(w, req, "/connections?error=missing_code", http.StatusSeeOther)
		return
	}

	// Get and validate state
	state := req.URL.Query().Get("state")
	if state == "" {
		http.Redirect(w, req, "/connections?error=missing_state", http.StatusSeeOther)
		return
	}

	// Verify state matches the cookie
	stateCookie, err := req.Cookie(oauthStateCookieName)
	if err != nil || stateCookie.Value == "" {
		http.Redirect(w, req, "/connections?error=state_cookie_missing", http.StatusSeeOther)
		return
	}

	if state != stateCookie.Value {
		http.Redirect(w, req, "/connections?error=invalid_state", http.StatusSeeOther)
		return
	}

	// Clear the state cookie
	clearStateCookie := &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1, // Delete the cookie
	}
	http.SetCookie(w, clearStateCookie)

	// Build callback URL (same as used in initiation)
	callbackURL := r.oauthCallbackURL + "/oauth/threads/callback"

	// Exchange code for tokens and store credentials
	_, err = r.threadsOAuth.ExchangeCode(req.Context(), claims.UserID, code, callbackURL)
	if err != nil {
		http.Redirect(w, req, "/connections?error="+url.QueryEscape("Failed to connect Threads: "+err.Error()), http.StatusSeeOther)
		return
	}

	// Success - redirect to connections page
	http.Redirect(w, req, "/connections?connected=threads", http.StatusSeeOther)
}

// handleThreadsTokenRefresh refreshes the Threads OAuth access token
// POST /oauth/threads/refresh
func (r *Router) handleThreadsTokenRefresh(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie - user must be logged in
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate the token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Get existing credentials from credential store
	if r.credentialStore == nil {
		http.Error(w, "Credential store not configured", http.StatusInternalServerError)
		return
	}

	creds, err := r.credentialStore.GetCredentials(req.Context(), claims.UserID, "threads")
	if err != nil {
		http.Error(w, "No Threads credentials found", http.StatusBadRequest)
		return
	}

	// Call RefreshTokens on the OAuth provider
	if r.threadsOAuth == nil {
		http.Error(w, "Threads OAuth provider not configured", http.StatusInternalServerError)
		return
	}

	newTokens, err := r.threadsOAuth.RefreshTokens(req.Context(), creds.RefreshToken)
	if err != nil {
		http.Error(w, "Failed to refresh token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Update stored credentials
	creds.AccessToken = newTokens.AccessToken
	creds.RefreshToken = newTokens.RefreshToken
	creds.TokenExpiresAt = newTokens.ExpiresAt
	if newTokens.Scopes != "" {
		creds.Scopes = newTokens.Scopes
	}

	if err := r.credentialStore.SaveCredentials(req.Context(), creds); err != nil {
		http.Error(w, "Failed to save refreshed credentials", http.StatusInternalServerError)
		return
	}

	// Success - redirect to connections page
	http.Redirect(w, req, "/connections?refreshed=threads", http.StatusSeeOther)
}

func (r *Router) renderPage(w http.ResponseWriter, page string, data PageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Get the page-specific template
	t, ok := pageTemplates[page]
	if !ok {
		http.Error(w, "Template not found: "+page, http.StatusInternalServerError)
		return
	}

	// Execute the base template (which includes the page content)
	err := t.ExecuteTemplate(w, "base.html", data)
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// renderPageWithCSRF renders a page with CSRF token support
// This ensures a CSRF token exists (creates one if needed) and passes it to the template
func (r *Router) renderPageWithCSRF(w http.ResponseWriter, req *http.Request, page string, data PageData) {
	// Ensure CSRF token exists and get its value
	token, err := auth.EnsureCSRFToken(w, req)
	if err != nil {
		http.Error(w, "Failed to generate CSRF token", http.StatusInternalServerError)
		return
	}
	data.CSRFToken = token

	r.renderPage(w, page, data)
}

// getDraftCount returns the draft count for a user, or 0 if not available
func (r *Router) getDraftCount(ctx context.Context, userID string) int {
	if r.draftCounter == nil {
		return 0
	}
	count, err := r.draftCounter.CountDraftsByUser(ctx, userID)
	if err != nil {
		return 0
	}
	return count
}

// WebhookDeliveriesData holds data for the webhook deliveries page
type WebhookDeliveriesData struct {
	Repository *handlers.Repository
	Deliveries []*WebhookDelivery
	RepoName   string
}

func (r *Router) handleWebhookDeliveries(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Get repository ID from path
	repoID := req.PathValue("id")
	if repoID == "" {
		http.NotFound(w, req)
		return
	}

	// Check if stores are configured
	if r.repoStore == nil {
		r.renderPage(w, "webhook_deliveries.html", PageData{
			Title: "Webhook Deliveries",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Repository store not configured",
		})
		return
	}

	// Get repository
	repo, err := r.repoStore.GetRepositoryByID(req.Context(), repoID)
	if err != nil {
		r.renderPage(w, "webhook_deliveries.html", PageData{
			Title: "Webhook Deliveries",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Failed to load repository",
		})
		return
	}

	// Repository not found
	if repo == nil {
		http.NotFound(w, req)
		return
	}

	// Verify the repository belongs to the current user
	if repo.UserID != claims.UserID {
		http.NotFound(w, req)
		return
	}

	// Extract repository name
	repoName := extractRepoName(repo.GitHubURL)

	// Get webhook deliveries
	var deliveries []*WebhookDelivery
	if r.webhookDeliveryStore != nil {
		deliveries, err = r.webhookDeliveryStore.ListDeliveriesByRepository(req.Context(), repoID, 50)
		if err != nil {
			r.renderPage(w, "webhook_deliveries.html", PageData{
				Title: repoName + " - Webhook Deliveries",
				User: &UserData{
					ID:    claims.UserID,
					Email: claims.Email,
				},
				Error: "Failed to load webhook deliveries",
			})
			return
		}
	}

	r.renderPage(w, "webhook_deliveries.html", PageData{
		Title: repoName + " - Webhook Deliveries",
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data: &WebhookDeliveriesData{
			Repository: repo,
			Deliveries: deliveries,
			RepoName:   repoName,
		},
	})
}

// ConnectionDisconnectData holds data for the connection disconnect page
type ConnectionDisconnectData struct {
	Platform    string
	DisplayName string
	ProfileURL  string
}

func (r *Router) handleConnectionDisconnect(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Get platform from path
	platform := req.PathValue("platform")
	if platform == "" {
		http.NotFound(w, req)
		return
	}

	// Check if connection service is available
	if r.connectionService == nil {
		r.renderPage(w, "connection_disconnect.html", PageData{
			Title: "Disconnect " + platform,
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Connection service not configured",
		})
		return
	}

	// Get the connection
	conn, err := r.connectionService.GetConnection(req.Context(), claims.UserID, platform)
	if err != nil {
		http.NotFound(w, req)
		return
	}

	r.renderPage(w, "connection_disconnect.html", PageData{
		Title: "Disconnect " + platform,
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data: &ConnectionDisconnectData{
			Platform:    conn.Platform,
			DisplayName: conn.DisplayName,
			ProfileURL:  conn.ProfileURL,
		},
	})
}

func (r *Router) handleConnectionDisconnectPost(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Get platform from path
	platform := req.PathValue("platform")
	if platform == "" {
		http.NotFound(w, req)
		return
	}

	// Check if connection service is available
	if r.connectionService == nil {
		r.renderPage(w, "connection_disconnect.html", PageData{
			Title: "Disconnect " + platform,
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Connection service not configured",
		})
		return
	}

	// Get the connection first to verify it exists
	conn, err := r.connectionService.GetConnection(req.Context(), claims.UserID, platform)
	if err != nil {
		http.NotFound(w, req)
		return
	}

	// Disconnect the account
	err = r.connectionService.Disconnect(req.Context(), claims.UserID, platform)
	if err != nil {
		r.renderPage(w, "connection_disconnect.html", PageData{
			Title: "Disconnect " + platform,
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Failed to disconnect account",
			Data: &ConnectionDisconnectData{
				Platform:    conn.Platform,
				DisplayName: conn.DisplayName,
				ProfileURL:  conn.ProfileURL,
			},
		})
		return
	}

	// Redirect to dashboard with success message
	// Using query param for flash message since we don't have session-based flash
	http.Redirect(w, req, "/dashboard?disconnected="+platform, http.StatusSeeOther)
}

// =============================================================================
// GitHub OAuth Routes (alice-58)
// =============================================================================

// handleGitHubOAuthInitiate initiates the GitHub OAuth flow.
// GET /oauth/github
// Redirects to GitHub authorization page.
func (r *Router) handleGitHubOAuthInitiate(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	_, err = auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Check if GitHub OAuth provider is configured
	if r.githubOAuthProvider == nil {
		http.Error(w, "GitHub OAuth not configured", http.StatusInternalServerError)
		return
	}

	// Generate state parameter for CSRF protection
	// Store the state in a cookie for validation on callback
	state, err := generateOAuthState()
	if err != nil {
		http.Redirect(w, req, "/connections?error=state_generation_failed", http.StatusSeeOther)
		return
	}
	stateCookie := &http.Cookie{
		Name:     "github_oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   600, // 10 minutes
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, stateCookie)

	// Build redirect URL
	redirectURL := r.baseURL + "/oauth/github/callback"
	authURL := r.githubOAuthProvider.GetAuthURL(state, redirectURL)

	// Redirect to GitHub authorization page
	http.Redirect(w, req, authURL, http.StatusTemporaryRedirect)
}

// handleGitHubOAuthCallback handles the OAuth callback from GitHub.
// GET /oauth/github/callback
// Exchanges code for token, stores credentials, redirects to repo selection.
func (r *Router) handleGitHubOAuthCallback(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Check for error from GitHub
	if errParam := req.URL.Query().Get("error"); errParam != "" {
		errDesc := req.URL.Query().Get("error_description")
		http.Error(w, fmt.Sprintf("GitHub OAuth error: %s - %s", errParam, errDesc), http.StatusBadRequest)
		return
	}

	// Validate state parameter
	stateCookie, err := req.Cookie("github_oauth_state")
	if err != nil {
		http.Error(w, "Missing OAuth state", http.StatusBadRequest)
		return
	}

	state := req.URL.Query().Get("state")
	if state == "" || state != stateCookie.Value {
		http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
		return
	}

	// Clear the state cookie
	clearStateCookie := &http.Cookie{
		Name:     "github_oauth_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	http.SetCookie(w, clearStateCookie)

	// Get authorization code
	code := req.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Check if GitHub OAuth provider is configured
	if r.githubOAuthProvider == nil {
		http.Error(w, "GitHub OAuth not configured", http.StatusInternalServerError)
		return
	}

	// Exchange code for tokens
	redirectURL := r.baseURL + "/oauth/github/callback"
	tokens, err := r.githubOAuthProvider.ExchangeCode(req.Context(), code, redirectURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to exchange code: %v", err), http.StatusInternalServerError)
		return
	}

	// Store credentials
	if r.credentialStore != nil {
		creds := &PlatformCredentials{
			UserID:         claims.UserID,
			Platform:       "github",
			AccessToken:    tokens.AccessToken,
			RefreshToken:   tokens.RefreshToken,
			TokenExpiresAt: tokens.ExpiresAt,
			PlatformUserID: tokens.PlatformUserID,
			Scopes:         tokens.Scopes,
		}
		if err := r.credentialStore.SaveCredentials(req.Context(), creds); err != nil {
			http.Error(w, fmt.Sprintf("Failed to store credentials: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Redirect to repo selection page
	http.Redirect(w, req, "/repositories/new", http.StatusSeeOther)
}

func (r *Router) handleDraftPreview(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Get draft ID from path
	draftID := req.PathValue("id")
	if draftID == "" {
		http.NotFound(w, req)
		return
	}

	// Check if draft store is available
	if r.draftStore == nil {
		http.NotFound(w, req)
		return
	}

	// Get draft
	draft, err := r.draftStore.GetDraftByID(req.Context(), draftID)
	if err != nil {
		http.Error(w, "Failed to load draft", http.StatusInternalServerError)
		return
	}

	// Draft not found
	if draft == nil {
		http.NotFound(w, req)
		return
	}

	// Verify the draft belongs to the current user
	if draft.UserID != claims.UserID {
		http.NotFound(w, req)
		return
	}

	// Calculate character count
	charCount := len(draft.Content)
	charLimit := draft.CharLimit
	if charLimit == 0 {
		charLimit = 500 // Default limit
	}

	r.renderPage(w, "draft_preview.html", PageData{
		Title: "Edit Draft",
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data: &DraftPreviewData{
			Draft:     draft,
			CharCount: charCount,
			CharLimit: charLimit,
		},
	})
}

func (r *Router) handleDraftEdit(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Get draft ID from path
	draftID := req.PathValue("id")
	if draftID == "" {
		http.NotFound(w, req)
		return
	}

	// Check if draft store is available
	if r.draftStore == nil {
		http.NotFound(w, req)
		return
	}

	// Get draft to verify ownership
	draft, err := r.draftStore.GetDraftByID(req.Context(), draftID)
	if err != nil || draft == nil {
		http.NotFound(w, req)
		return
	}

	// Verify ownership
	if draft.UserID != claims.UserID {
		http.NotFound(w, req)
		return
	}

	// Parse form
	if err := req.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	content := req.FormValue("content")

	// Update draft content
	_, err = r.draftStore.UpdateDraftContent(req.Context(), draftID, content)
	if err != nil {
		http.Error(w, "Failed to update draft", http.StatusInternalServerError)
		return
	}

	// Redirect back to draft preview
	http.Redirect(w, req, "/drafts/"+draftID, http.StatusSeeOther)
}

func (r *Router) handleDraftRegenerate(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Get draft ID from path
	draftID := req.PathValue("id")
	if draftID == "" {
		http.NotFound(w, req)
		return
	}

	// Check if draft store is available
	if r.draftStore == nil {
		http.NotFound(w, req)
		return
	}

	// Get draft to verify ownership
	draft, err := r.draftStore.GetDraftByID(req.Context(), draftID)
	if err != nil || draft == nil {
		http.NotFound(w, req)
		return
	}

	// Verify ownership
	if draft.UserID != claims.UserID {
		http.NotFound(w, req)
		return
	}

	// Check if AI regenerator is available
	if r.aiRegenerator == nil {
		http.Error(w, "AI regeneration not configured", http.StatusServiceUnavailable)
		return
	}

	// Regenerate draft content using AI generator
	if err := r.aiRegenerator.RegenerateDraft(req.Context(), draftID); err != nil {
		http.Error(w, "Failed to regenerate draft", http.StatusInternalServerError)
		return
	}

	// Redirect back to draft preview with success message
	http.Redirect(w, req, "/drafts/"+draftID+"?regenerated=true", http.StatusSeeOther)
}

func (r *Router) handleDraftDelete(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Get draft ID from path
	draftID := req.PathValue("id")
	if draftID == "" {
		http.NotFound(w, req)
		return
	}

	// Check if draft store is available
	if r.draftStore == nil {
		http.NotFound(w, req)
		return
	}

	// Get draft to verify ownership
	draft, err := r.draftStore.GetDraftByID(req.Context(), draftID)
	if err != nil || draft == nil {
		http.NotFound(w, req)
		return
	}

	// Verify ownership
	if draft.UserID != claims.UserID {
		http.NotFound(w, req)
		return
	}

	// Delete the draft
	err = r.draftStore.DeleteDraft(req.Context(), draftID)
	if err != nil {
		http.Error(w, "Failed to delete draft", http.StatusInternalServerError)
		return
	}

	// Redirect to drafts list or dashboard
	http.Redirect(w, req, "/dashboard", http.StatusSeeOther)
}

func (r *Router) handleDraftPost(w http.ResponseWriter, req *http.Request) {
	// Check for auth cookie
	cookie, err := req.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Validate token
	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// Get draft ID from path
	draftID := req.PathValue("id")
	if draftID == "" {
		http.NotFound(w, req)
		return
	}

	// Check if draft store is available
	if r.draftStore == nil {
		http.NotFound(w, req)
		return
	}

	// Get draft to verify ownership
	draft, err := r.draftStore.GetDraftByID(req.Context(), draftID)
	if err != nil || draft == nil {
		http.NotFound(w, req)
		return
	}

	// Verify ownership
	if draft.UserID != claims.UserID {
		http.NotFound(w, req)
		return
	}

	// Post to social media if configured
	if r.socialPoster != nil {
		_, err = r.socialPoster.PostDraft(req.Context(), claims.UserID, draftID)
		if err != nil {
			http.Error(w, "Failed to post to social media: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Update draft status to posted
	_, err = r.draftStore.UpdateDraftStatus(req.Context(), draftID, "posted")
	if err != nil {
		http.Error(w, "Failed to update draft status", http.StatusInternalServerError)
		return
	}

	// Redirect to dashboard with success message
	http.Redirect(w, req, "/dashboard?posted=true", http.StatusSeeOther)
}

func (r *Router) handleGitHubAppSetup(w http.ResponseWriter, req *http.Request) {
	if r.githubAppSetup == nil {
		http.NotFound(w, req)
		return
	}
	r.githubAppSetup.ServeHTTP(w, req)
}

