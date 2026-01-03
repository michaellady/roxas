package web

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strings"

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
	pages := []string{"home.html", "login.html", "signup.html", "dashboard.html", "repositories_new.html", "repository_success.html", "repositories_list.html"}

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
	mux          *http.ServeMux
	userStore    UserStore
	repoStore    RepositoryStore
	commitLister CommitLister
	postLister   PostLister
	secretGen    SecretGenerator
	webhookURL   string
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
