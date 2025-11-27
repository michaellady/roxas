package auth

import (
	"context"
	"net/http"
)

// Context keys for user information
type contextKey string

const (
	userIDKey contextKey = "user_id"
	emailKey  contextKey = "email"
)

// JWTMiddleware validates JWT tokens on protected routes
// TODO: Implement in TB09
func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Stub: just pass through without validation
		next.ServeHTTP(w, r)
	})
}

// GetUserIDFromContext extracts user ID from request context
func GetUserIDFromContext(ctx context.Context) string {
	if userID, ok := ctx.Value(userIDKey).(string); ok {
		return userID
	}
	return ""
}

// GetEmailFromContext extracts email from request context
func GetEmailFromContext(ctx context.Context) string {
	if email, ok := ctx.Value(emailKey).(string); ok {
		return email
	}
	return ""
}
