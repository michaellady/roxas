package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// Context keys for user information
type contextKey string

const (
	userIDKey contextKey = "user_id"
	emailKey  contextKey = "email"
)

// CookieName is the name of the auth cookie
const CookieName = "auth_token"

// JWTMiddleware validates JWT tokens on protected routes
// Supports both cookie-based auth (auth_token cookie) and header-based auth (Authorization: Bearer)
// Cookie takes precedence when both are present
func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from request (cookie first, then header)
		tokenString, err := tokenFromRequest(r)
		if err != nil {
			writeAuthError(w, err.Error())
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

// tokenFromRequest extracts JWT token from request
// Priority: 1) auth_token cookie, 2) Authorization header
func tokenFromRequest(r *http.Request) (string, error) {
	// First, check for auth_token cookie
	cookie, err := r.Cookie(CookieName)
	if err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}

	// Fall back to Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing authorization header")
	}

	// Check for Bearer prefix
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("invalid authorization header format")
	}

	// Extract token
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == "" {
		return "", fmt.Errorf("missing token")
	}

	return tokenString, nil
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

// isSecureEnvironment returns true if running in an environment that uses HTTPS
// This includes prod, dev, and PR environments (anything deployed to AWS)
func isSecureEnvironment() bool {
	env := os.Getenv("ENVIRONMENT")
	// Any deployed environment uses HTTPS - only local dev should be insecure
	return env == "prod" || env == "dev" || env == "production"
}

// SetAuthCookie sets the auth_token cookie with the JWT token
// Cookie settings: HttpOnly, SameSite=Lax, Secure (when deployed)
func SetAuthCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge, // in seconds
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isSecureEnvironment(),
	})
}

// ClearAuthCookie removes the auth_token cookie
func ClearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Delete cookie
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isSecureEnvironment(),
	})
}
