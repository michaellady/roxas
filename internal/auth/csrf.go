package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
)

// CSRFCookieName is the name of the CSRF token cookie
const CSRFCookieName = "csrf_token"

// CSRFFormFieldName is the name of the hidden form field containing the CSRF token
const CSRFFormFieldName = "csrf_token"

// CSRFTokenLength is the number of random bytes used to generate a CSRF token
const CSRFTokenLength = 32

// GenerateCSRFToken generates a cryptographically secure random CSRF token
// Returns a base64 URL-encoded string of 32 random bytes
func GenerateCSRFToken() (string, error) {
	b := make([]byte, CSRFTokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// ValidateCSRFToken compares the cookie token with the form token using constant-time comparison
// Returns true if the tokens match, false otherwise
func ValidateCSRFToken(cookieToken, formToken string) bool {
	if cookieToken == "" || formToken == "" {
		return false
	}
	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(cookieToken), []byte(formToken)) == 1
}

// SetCSRFCookie sets the CSRF token cookie with secure settings
// Cookie settings: HttpOnly=false (needs to be readable by forms), SameSite=Strict, Secure (when deployed)
func SetCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   3600, // 1 hour
		HttpOnly: false, // Must be accessible to JavaScript for AJAX requests
		SameSite: http.SameSiteStrictMode,
		Secure:   isSecureEnvironment(),
	})
}

// GetCSRFTokenFromRequest extracts the CSRF token from the request
// Checks both the form field and the X-CSRF-Token header (for AJAX requests)
func GetCSRFTokenFromRequest(r *http.Request) string {
	// Check form field first
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			if token := r.FormValue(CSRFFormFieldName); token != "" {
				return token
			}
		}
	}
	// Fall back to header (for AJAX requests)
	return r.Header.Get("X-CSRF-Token")
}

// GetCSRFTokenFromCookie extracts the CSRF token from the cookie
func GetCSRFTokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie(CSRFCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// CSRFMiddleware validates CSRF tokens on POST, PUT, PATCH, DELETE requests
// Returns 403 Forbidden if the CSRF token is missing or invalid
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only validate state-changing methods
		if r.Method == http.MethodPost || r.Method == http.MethodPut ||
			r.Method == http.MethodPatch || r.Method == http.MethodDelete {

			cookieToken := GetCSRFTokenFromCookie(r)
			formToken := GetCSRFTokenFromRequest(r)

			if !ValidateCSRFToken(cookieToken, formToken) {
				http.Error(w, "Forbidden - CSRF token validation failed", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// EnsureCSRFToken ensures a CSRF token exists in the cookie, generating one if needed
// Returns the current or newly generated token
func EnsureCSRFToken(w http.ResponseWriter, r *http.Request) (string, error) {
	token := GetCSRFTokenFromCookie(r)
	if token != "" {
		return token, nil
	}

	// Generate new token
	newToken, err := GenerateCSRFToken()
	if err != nil {
		return "", err
	}

	SetCSRFCookie(w, newToken)
	return newToken, nil
}
