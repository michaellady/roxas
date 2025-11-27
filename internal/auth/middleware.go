package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// Context keys for user information
type contextKey string

const (
	userIDKey contextKey = "user_id"
	emailKey  contextKey = "email"
)

// JWTMiddleware validates JWT tokens on protected routes
func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeAuthError(w, "missing authorization header")
			return
		}

		// Check for Bearer prefix
		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeAuthError(w, "invalid authorization header format")
			return
		}

		// Extract token
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == "" {
			writeAuthError(w, "missing token")
			return
		}

		// Validate token
		claims, err := ValidateToken(tokenString)
		if err != nil {
			// Check for specific error types
			errMsg := err.Error()
			if strings.Contains(errMsg, "expired") {
				writeAuthError(w, "token expired")
				return
			}
			writeAuthError(w, "invalid token")
			return
		}

		// Add user info to context
		ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
		ctx = context.WithValue(ctx, emailKey, claims.Email)

		// Call next handler with enriched context
		next.ServeHTTP(w, r.WithContext(ctx))
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

// writeAuthError writes a 401 Unauthorized response with JSON body
func writeAuthError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
