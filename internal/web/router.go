package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
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

func init() {
	pageTemplates = make(map[string]*template.Template)
	pages := []string{"home.html", "login.html", "signup.html", "dashboard.html", "repositories_new.html", "repository_success.html", "repositories_list.html", "repository_view.html", "repository_edit.html", "webhook_regenerate.html", "webhook_deliveries.html", "connections_list.html", "connections_new.html", "connection_view.html", "connection_success.html"}

	for _, page := range pages {
		// Clone the base template and parse the page
		t := template.Must(template.ParseFS(templatesFS,
			"templates/layouts/base.html",
			"templates/pages/"+page,
		))
		pageTemplates[page] = t
	}
}

// PageData holds data passed to templates
type PageData struct {
	Title string
	User  *UserData
	Flash *FlashMessage
	Error string
	Data  interface{}
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
	EventType    string
	Payload      string
	StatusCode   int
	ErrorMessage *string
	ProcessedAt  *string
	CreatedAt    string
	IsSuccess    bool
}

// WebhookDeliveryStore interface for webhook delivery operations
type WebhookDeliveryStore interface {
	ListDeliveriesByRepository(ctx context.Context, repoID string, limit int) ([]*WebhookDelivery, error)
}

// ConnectionService interface for managing social media connections
type ConnectionService interface {
	ListConnections(ctx context.Context, userID string) ([]*Connection, error)
	GetConnection(ctx context.Context, userID, platform string) (*Connection, error)
	InitiateOAuth(ctx context.Context, userID, platform string) (*OAuthInfo, error)
	HandleOAuthCallback(ctx context.Context, userID, platform, code, state string) (*OAuthResult, error)
	Disconnect(ctx context.Context, userID, platform string) error
	TestConnection(ctx context.Context, userID, platform string) (*ConnectionTestResult, error)
}

// Connection represents a user's connection to a social platform (for web display)
type Connection struct {
	UserID         string
	Platform       string
	Status         string
	PlatformUserID string
	DisplayName    string
	Scopes         []string
	ConnectedAt    *time.Time
	ExpiresAt      *time.Time
	LastError      string
}

// IsHealthy returns true if the connection is active and not expired
func (c *Connection) IsHealthy() bool {
	if c.Status != "connected" {
		return false
	}
	if c.ExpiresAt != nil && time.Now().After(*c.ExpiresAt) {
		return false
	}
	return true
}

// ExpiresWithin7Days returns true if token expires within 7 days
func (c *Connection) ExpiresWithin7Days() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().Add(7 * 24 * time.Hour).After(*c.ExpiresAt)
}

// OAuthInfo contains OAuth authorization info
type OAuthInfo struct {
	AuthURL   string
	State     string
	ExpiresAt time.Time
}

// OAuthResult contains OAuth callback result
type OAuthResult struct {
	Connection      *Connection
	IsNewConnection bool
}

// ConnectionTestResult contains test results
type ConnectionTestResult struct {
	Platform string
	Success  bool
	Latency  time.Duration
	Error    string
}

// PlatformInfo contains platform display information
type PlatformInfo struct {
	ID          string
	Name        string
	Description string
	Permissions []string
	Enabled     bool
}

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

// Router is the main HTTP router for the web UI
type Router struct {
	mux                  *http.ServeMux
	userStore            UserStore
	repoStore            RepositoryStore
	commitLister         CommitLister
	postLister           PostLister
	secretGen            SecretGenerator
	webhookURL           string
	webhookTester        WebhookTester
	webhookDeliveryStore WebhookDeliveryStore
	connectionService    ConnectionService
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
	r.mux.HandleFunc("/repositories", r.handleRepositories)
	r.mux.HandleFunc("/repositories/new", r.handleRepositoriesNew)
	r.mux.HandleFunc("/repositories/success", r.handleRepositoriesSuccess)
	r.mux.HandleFunc("/repositories/{id}", r.handleRepositoryView)
	r.mux.HandleFunc("GET /repositories/{id}/edit", r.handleRepositoryEdit)
	r.mux.HandleFunc("POST /repositories/{id}/edit", r.handleRepositoryEditPost)
	r.mux.HandleFunc("/repositories/{id}/webhook/test", r.handleWebhookTest)
	r.mux.HandleFunc("/repositories/{id}/webhook/regenerate", r.handleWebhookRegenerate)
	r.mux.HandleFunc("GET /repositories/{id}/webhooks", r.handleWebhookDeliveries)

	// Connection management routes
	r.mux.HandleFunc("GET /connections", r.handleConnectionsList)
	r.mux.HandleFunc("GET /connections/new", r.handleConnectionsNew)
	r.mux.HandleFunc("GET /connections/{platform}", r.handleConnectionView)
	r.mux.HandleFunc("POST /connections/{platform}/connect", r.handleConnectionConnect)
	r.mux.HandleFunc("GET /oauth/{platform}/callback", r.handleOAuthCallback)
	r.mux.HandleFunc("POST /connections/{platform}/test", r.handleConnectionTest)
	r.mux.HandleFunc("POST /connections/{platform}/disconnect", r.handleConnectionDisconnect)
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

	r.renderPage(w, "login.html", PageData{
		Title: "Login",
	})
}

func (r *Router) handleLoginPost(w http.ResponseWriter, req *http.Request) {
	// Parse form
	if err := req.ParseForm(); err != nil {
		r.renderPage(w, "login.html", PageData{
			Title: "Login",
			Error: "Invalid form data",
		})
		return
	}

	email := req.FormValue("email")
	password := req.FormValue("password")

	// Validate input
	if email == "" || password == "" {
		r.renderPage(w, "login.html", PageData{
			Title: "Login",
			Error: "Email and password are required",
		})
		return
	}

	// Check if we have a user store
	if r.userStore == nil {
		r.renderPage(w, "login.html", PageData{
			Title: "Login",
			Error: "Authentication not configured",
		})
		return
	}

	// Look up user
	user, err := r.userStore.GetUserByEmail(req.Context(), email)
	if err != nil {
		r.renderPage(w, "login.html", PageData{
			Title: "Login",
			Error: "Invalid email or password",
		})
		return
	}

	if user == nil {
		// User not found - use same error message for security
		r.renderPage(w, "login.html", PageData{
			Title: "Login",
			Error: "Invalid email or password",
		})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		r.renderPage(w, "login.html", PageData{
			Title: "Login",
			Error: "Invalid email or password",
		})
		return
	}

	// Generate JWT token
	token, err := auth.GenerateToken(user.ID, user.Email)
	if err != nil {
		r.renderPage(w, "login.html", PageData{
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

	r.renderPage(w, "signup.html", PageData{
		Title: "Sign Up",
	})
}

func (r *Router) handleSignupPost(w http.ResponseWriter, req *http.Request) {
	// Parse form
	if err := req.ParseForm(); err != nil {
		r.renderPage(w, "signup.html", PageData{
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
		r.renderPage(w, "signup.html", PageData{
			Title: "Sign Up",
			Error: "Email and password are required",
		})
		return
	}

	// Validate password length (min 8 characters)
	if len(password) < 8 {
		r.renderPage(w, "signup.html", PageData{
			Title: "Sign Up",
			Error: "Password must be at least 8 characters",
		})
		return
	}

	// Validate passwords match
	if password != confirmPassword {
		r.renderPage(w, "signup.html", PageData{
			Title: "Sign Up",
			Error: "Passwords do not match",
		})
		return
	}

	// Check if we have a user store
	if r.userStore == nil {
		r.renderPage(w, "signup.html", PageData{
			Title: "Sign Up",
			Error: "Registration not configured",
		})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		r.renderPage(w, "signup.html", PageData{
			Title: "Sign Up",
			Error: "Failed to process registration",
		})
		return
	}

	// Create user
	_, err = r.userStore.CreateUser(req.Context(), email, string(hashedPassword))
	if err != nil {
		if err == handlers.ErrDuplicateEmail {
			r.renderPage(w, "signup.html", PageData{
				Title: "Sign Up",
				Error: "An account with this email already exists",
			})
			return
		}
		r.renderPage(w, "signup.html", PageData{
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
	IsEmpty      bool
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

	// Fetch dashboard data
	dashData := &DashboardData{}

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

	// Check if dashboard is empty (no repos)
	dashData.IsEmpty = len(dashData.Repositories) == 0

	r.renderPage(w, "dashboard.html", PageData{
		Title: "Dashboard",
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data: dashData,
	})
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

// RepositoriesListData holds data for the repositories list page
type RepositoriesListData struct {
	Repositories []*handlers.Repository
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

	r.renderPage(w, "repositories_list.html", PageData{
		Title: "Repositories",
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

	r.renderPage(w, "repositories_new.html", PageData{
		Title: "Add Repository",
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
	})
}

func (r *Router) handleRepositoriesNewPost(w http.ResponseWriter, req *http.Request, claims *auth.Claims) {
	// Parse form
	if err := req.ParseForm(); err != nil {
		r.renderPage(w, "repositories_new.html", PageData{
			Title: "Add Repository",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Invalid form data",
		})
		return
	}

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
	webhookURL := fmt.Sprintf("%s/webhook/%s", r.webhookURL, repo.ID)

	// Redirect to success page with query params
	http.Redirect(w, req, fmt.Sprintf("/repositories/success?webhook_url=%s&webhook_secret=%s",
		url.QueryEscape(webhookURL),
		url.QueryEscape(secret)), http.StatusSeeOther)
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
	webhookURL := fmt.Sprintf("%s/webhook/%s", r.webhookURL, repo.ID)

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
	webhookURL := fmt.Sprintf("%s/webhook/%s", r.webhookURL, repo.ID)

	// Test the webhook
	var result WebhookTestResult
	if r.webhookTester != nil {
		statusCode, err := r.webhookTester.TestWebhook(req.Context(), webhookURL, repo.WebhookSecret)
		if err != nil {
			result = WebhookTestResult{
				Success: false,
				Error:   fmt.Sprintf("Connection failed: %v", err),
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
	webhookURL := fmt.Sprintf("%s/webhook/%s", r.webhookURL, repo.ID)

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

// =============================================================================
// Connection Management Handlers
// =============================================================================

// ConnectionsListData holds data for the connections list page
type ConnectionsListData struct {
	Connections []*Connection
}

// ConnectionsNewData holds data for the new connection page
type ConnectionsNewData struct {
	Platforms []PlatformInfo
}

// ConnectionViewData holds data for the connection view page
type ConnectionViewData struct {
	Platform     string
	PlatformName string
	Connection   *Connection
	TestResult   *ConnectionTestResult
	RateLimits   *RateLimitDisplay
}

// RateLimitDisplay holds rate limit info for display
type RateLimitDisplay struct {
	Limit       int
	Remaining   int
	UsedPercent int
	ResetAt     time.Time
}

// ConnectionSuccessData holds data for the connection success page
type ConnectionSuccessData struct {
	Platform     string
	PlatformName string
	Connection   *Connection
}

// getSupportedPlatforms returns the list of supported platforms
func getSupportedPlatforms() []PlatformInfo {
	return []PlatformInfo{
		{
			ID:          "linkedin",
			Name:        "LinkedIn",
			Description: "Share professional updates and articles with your network.",
			Permissions: []string{"Read your profile", "Post on your behalf"},
			Enabled:     true,
		},
		{
			ID:          "twitter",
			Name:        "Twitter/X",
			Description: "Share tweets and engage with your followers.",
			Permissions: []string{"Read your profile", "Post tweets"},
			Enabled:     true,
		},
		{
			ID:          "threads",
			Name:        "Threads",
			Description: "Share text posts and join conversations.",
			Permissions: []string{"Read your profile", "Post threads"},
			Enabled:     false,
		},
		{
			ID:          "bluesky",
			Name:        "Bluesky",
			Description: "Share posts on the decentralized social network.",
			Permissions: []string{"Read your profile", "Post on your behalf"},
			Enabled:     false,
		},
	}
}

// platformName returns a display name for a platform
func platformName(platform string) string {
	switch platform {
	case "linkedin":
		return "LinkedIn"
	case "twitter":
		return "Twitter/X"
	case "threads":
		return "Threads"
	case "bluesky":
		return "Bluesky"
	case "instagram":
		return "Instagram"
	case "tiktok":
		return "TikTok"
	default:
		// Capitalize first letter
		if len(platform) == 0 {
			return platform
		}
		return strings.ToUpper(platform[:1]) + platform[1:]
	}
}

func (r *Router) handleConnectionsList(w http.ResponseWriter, req *http.Request) {
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

	// Get connections from service
	var connections []*Connection
	if r.connectionService != nil {
		connections, err = r.connectionService.ListConnections(req.Context(), claims.UserID)
		if err != nil {
			r.renderPage(w, "connections_list.html", PageData{
				Title: "Connected Platforms",
				User: &UserData{
					ID:    claims.UserID,
					Email: claims.Email,
				},
				Error: "Failed to load connections",
			})
			return
		}
	}

	r.renderPage(w, "connections_list.html", PageData{
		Title: "Connected Platforms",
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data: &ConnectionsListData{
			Connections: connections,
		},
	})
}

func (r *Router) handleConnectionsNew(w http.ResponseWriter, req *http.Request) {
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

	r.renderPage(w, "connections_new.html", PageData{
		Title: "Connect a Platform",
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data: &ConnectionsNewData{
			Platforms: getSupportedPlatforms(),
		},
	})
}

func (r *Router) handleConnectionView(w http.ResponseWriter, req *http.Request) {
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

	platform := req.PathValue("platform")
	if platform == "" {
		http.NotFound(w, req)
		return
	}

	var connection *Connection
	if r.connectionService != nil {
		connection, err = r.connectionService.GetConnection(req.Context(), claims.UserID, platform)
		if err != nil {
			// Connection not found is okay - we'll show the "not connected" state
			connection = nil
		}
	}

	r.renderPage(w, "connection_view.html", PageData{
		Title: platformName(platform),
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data: &ConnectionViewData{
			Platform:     platform,
			PlatformName: platformName(platform),
			Connection:   connection,
		},
	})
}

func (r *Router) handleConnectionConnect(w http.ResponseWriter, req *http.Request) {
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

	platform := req.PathValue("platform")
	if platform == "" {
		http.NotFound(w, req)
		return
	}

	if r.connectionService == nil {
		r.renderPage(w, "connections_new.html", PageData{
			Title: "Connect a Platform",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error:    "Connection service not configured",
			Data: &ConnectionsNewData{
				Platforms: getSupportedPlatforms(),
			},
		})
		return
	}

	// Initiate OAuth flow
	oauthInfo, err := r.connectionService.InitiateOAuth(req.Context(), claims.UserID, platform)
	if err != nil {
		r.renderPage(w, "connections_new.html", PageData{
			Title: "Connect a Platform",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Failed to initiate connection: " + err.Error(),
			Data: &ConnectionsNewData{
				Platforms: getSupportedPlatforms(),
			},
		})
		return
	}

	// Redirect to OAuth provider
	http.Redirect(w, req, oauthInfo.AuthURL, http.StatusSeeOther)
}

func (r *Router) handleOAuthCallback(w http.ResponseWriter, req *http.Request) {
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

	platform := req.PathValue("platform")
	if platform == "" {
		http.NotFound(w, req)
		return
	}

	// Get OAuth parameters from query
	code := req.URL.Query().Get("code")
	state := req.URL.Query().Get("state")

	if code == "" {
		// OAuth was denied or failed
		errorMsg := req.URL.Query().Get("error")
		if errorMsg == "" {
			errorMsg = "Authorization was denied"
		}
		r.renderPage(w, "connections_new.html", PageData{
			Title: "Connect a Platform",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: errorMsg,
			Data: &ConnectionsNewData{
				Platforms: getSupportedPlatforms(),
			},
		})
		return
	}

	if r.connectionService == nil {
		r.renderPage(w, "connections_new.html", PageData{
			Title: "Connect a Platform",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Connection service not configured",
			Data: &ConnectionsNewData{
				Platforms: getSupportedPlatforms(),
			},
		})
		return
	}

	// Exchange code for tokens
	result, err := r.connectionService.HandleOAuthCallback(req.Context(), claims.UserID, platform, code, state)
	if err != nil {
		r.renderPage(w, "connections_new.html", PageData{
			Title: "Connect a Platform",
			User: &UserData{
				ID:    claims.UserID,
				Email: claims.Email,
			},
			Error: "Failed to complete connection: " + err.Error(),
			Data: &ConnectionsNewData{
				Platforms: getSupportedPlatforms(),
			},
		})
		return
	}

	// Redirect to success page
	r.renderPage(w, "connection_success.html", PageData{
		Title: platformName(platform) + " Connected",
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data: &ConnectionSuccessData{
			Platform:     platform,
			PlatformName: platformName(platform),
			Connection:   result.Connection,
		},
	})
}

func (r *Router) handleConnectionTest(w http.ResponseWriter, req *http.Request) {
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

	platform := req.PathValue("platform")
	if platform == "" {
		http.NotFound(w, req)
		return
	}

	var testResult *ConnectionTestResult
	var connection *Connection

	if r.connectionService != nil {
		connection, _ = r.connectionService.GetConnection(req.Context(), claims.UserID, platform)
		testResult, err = r.connectionService.TestConnection(req.Context(), claims.UserID, platform)
		if err != nil {
			testResult = &ConnectionTestResult{
				Platform: platform,
				Success:  false,
				Error:    err.Error(),
			}
		}
	}

	r.renderPage(w, "connection_view.html", PageData{
		Title: platformName(platform),
		User: &UserData{
			ID:    claims.UserID,
			Email: claims.Email,
		},
		Data: &ConnectionViewData{
			Platform:     platform,
			PlatformName: platformName(platform),
			Connection:   connection,
			TestResult:   testResult,
		},
	})
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

	platform := req.PathValue("platform")
	if platform == "" {
		http.NotFound(w, req)
		return
	}

	if r.connectionService != nil {
		err = r.connectionService.Disconnect(req.Context(), claims.UserID, platform)
		if err != nil {
			r.renderPage(w, "connection_view.html", PageData{
				Title: platformName(platform),
				User: &UserData{
					ID:    claims.UserID,
					Email: claims.Email,
				},
				Error: "Failed to disconnect: " + err.Error(),
				Data: &ConnectionViewData{
					Platform:     platform,
					PlatformName: platformName(platform),
				},
			})
			return
		}
	}

	// Redirect to connections list
	http.Redirect(w, req, "/connections", http.StatusSeeOther)
}
