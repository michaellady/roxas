package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// =============================================================================
// TB-WEB-01: Static file serving + base HTML template (TDD - RED)
// =============================================================================

func TestRouter_GetRoot_ReturnsHTML(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return 200 OK
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Should return HTML content type
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Expected Content-Type text/html, got %s", contentType)
	}

	// Should contain HTML doctype
	body := rr.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Errorf("Expected HTML doctype, got: %s", body[:min(len(body), 100)])
	}

	// Should contain basic HTML structure
	if !strings.Contains(body, "<html") {
		t.Errorf("Expected <html> tag")
	}
	if !strings.Contains(body, "<head>") {
		t.Errorf("Expected <head> tag")
	}
	if !strings.Contains(body, "<body>") {
		t.Errorf("Expected <body> tag")
	}
}

func TestRouter_GetRoot_ContainsAppTitle(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	body := rr.Body.String()
	// Should contain app name in title
	if !strings.Contains(body, "Roxas") {
		t.Errorf("Expected 'Roxas' in page content")
	}
}

func TestRouter_GetStatic_ServesCSS(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/static/css/style.css", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return 200 OK
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Should return CSS content type
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/css") {
		t.Errorf("Expected Content-Type text/css, got %s", contentType)
	}
}

func TestRouter_GetLogin_ReturnsLoginPage(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "login") && !strings.Contains(body, "Login") {
		t.Errorf("Expected login form content")
	}
}

func TestRouter_GetSignup_ReturnsSignupPage(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/signup", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "signup") && !strings.Contains(body, "Sign") {
		t.Errorf("Expected signup form content")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
