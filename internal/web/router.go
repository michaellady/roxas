package web

import (
	"context"
	"embed"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/mikelady/roxas/internal/auth"
	"github.com/mikelady/roxas/internal/handlers"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/*
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Templates holds parsed HTML templates
var templates *template.Template

func init() {
	// Parse all templates at startup
	templates = template.Must(template.ParseFS(templatesFS,
		"templates/layouts/*.html",
		"templates/pages/*.html",
	))
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

// Router is the main HTTP router for the web UI
type Router struct {
	mux       *http.ServeMux
	userStore UserStore
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
		// Will be implemented in TB-WEB-04
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	r.renderPage(w, "signup.html", PageData{
		Title: "Sign Up",
	})
}

func (r *Router) renderPage(w http.ResponseWriter, page string, data PageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// First render the page content
	err := templates.ExecuteTemplate(w, "base.html", data)
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
}
