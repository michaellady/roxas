package handlers

import (
	"net/http"
)

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	// db will be added when implementing
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(db interface{}) *AuthHandler {
	return &AuthHandler{}
}

// ServeHTTP implements http.Handler - stub for TDD
func (h *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Not implemented - tests should fail (RED)
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
