package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
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

// Router is the main HTTP router for the web UI
type Router struct {
	mux *http.ServeMux
}

// NewRouter creates a new web router with all routes configured
func NewRouter() *Router {
	r := &Router{
		mux: http.NewServeMux(),
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
		// Will be implemented in TB-WEB-03
		http.Redirect(w, req, "/dashboard", http.StatusSeeOther)
		return
	}

	r.renderPage(w, "login.html", PageData{
		Title: "Login",
	})
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
