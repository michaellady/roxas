// Package tests contains property-based tests for the Roxas application.
// Property 4: For any JWT with past expiration, auth middleware rejects and requires re-auth.
// Validates Requirements 1.8 (session management), 12.5 (security token validation).
package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"

	"github.com/mikelady/roxas/internal/auth"
)

// =============================================================================
// Helper Functions for Token Generation
// =============================================================================

// createExpiredToken creates a JWT token that expired at the specified duration ago
func createExpiredToken(userID, email string, expiredAgo time.Duration) (string, error) {
	claims := &auth.Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-expiredAgo)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-expiredAgo - time.Hour)),
			Issuer:    "roxas",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(auth.JWTSecret)
}

// createValidToken creates a JWT token that expires in the future
func createValidToken(userID, email string, expiresIn time.Duration) (string, error) {
	claims := &auth.Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "roxas",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(auth.JWTSecret)
}

// testProtectedHandler is a simple handler for testing middleware
func testProtectedHandler(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserIDFromContext(r.Context())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"user_id": userID, "status": "authenticated"})
}

// =============================================================================
// Property Tests: Expired Token Rejection
// =============================================================================

// TestPropertyJWTExpiration_ExpiredTokensRejected verifies that all tokens with
// past expiration times are rejected by the auth middleware.
// Property 4.1: Any expired token results in 401 Unauthorized
// Validates Requirement 1.8: Session management with token expiration
func TestPropertyJWTExpiration_ExpiredTokensRejected(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for valid user IDs (UUID format)
	userIDGen := gen.RegexMatch(`user-[0-9a-f]{8}`)

	// Generator for valid email addresses
	emailGen := gen.RegexMatch(`[a-z]{5,10}@example\.com`)

	// Generator for expiration durations (1 second to 365 days in the past)
	expiredDurationGen := gen.Int64Range(1, 365*24*60*60).Map(func(seconds int64) time.Duration {
		return time.Duration(seconds) * time.Second
	})

	properties.Property("expired tokens via Bearer header return 401", prop.ForAll(
		func(userID, email string, expiredAgo time.Duration) bool {
			tokenString, err := createExpiredToken(userID, email, expiredAgo)
			if err != nil {
				return false
			}

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+tokenString)

			rr := httptest.NewRecorder()
			handler := auth.JWTMiddleware(http.HandlerFunc(testProtectedHandler))
			handler.ServeHTTP(rr, req)

			// Property: Expired token must return 401 Unauthorized
			return rr.Code == http.StatusUnauthorized
		},
		userIDGen,
		emailGen,
		expiredDurationGen,
	))

	properties.Property("expired tokens via cookie return 401", prop.ForAll(
		func(userID, email string, expiredAgo time.Duration) bool {
			tokenString, err := createExpiredToken(userID, email, expiredAgo)
			if err != nil {
				return false
			}

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.AddCookie(&http.Cookie{
				Name:  auth.CookieName,
				Value: tokenString,
			})

			rr := httptest.NewRecorder()
			handler := auth.JWTMiddleware(http.HandlerFunc(testProtectedHandler))
			handler.ServeHTTP(rr, req)

			// Property: Expired token in cookie must return 401 Unauthorized
			return rr.Code == http.StatusUnauthorized
		},
		userIDGen,
		emailGen,
		expiredDurationGen,
	))

	properties.TestingRun(t)
}

// TestPropertyJWTExpiration_ExpiredTokenErrorMessage verifies that expired tokens
// return an error message indicating expiration.
// Property 4.2: Expired token error response contains "expired" indication
// Validates Requirement 12.5: Security token validation with clear error messaging
func TestPropertyJWTExpiration_ExpiredTokenErrorMessage(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for valid user IDs
	userIDGen := gen.RegexMatch(`user-[0-9a-f]{8}`)

	// Generator for valid email addresses
	emailGen := gen.RegexMatch(`[a-z]{5,10}@example\.com`)

	// Generator for expiration durations (1 minute to 30 days)
	expiredDurationGen := gen.Int64Range(60, 30*24*60*60).Map(func(seconds int64) time.Duration {
		return time.Duration(seconds) * time.Second
	})

	properties.Property("expired token error message contains 'expired'", prop.ForAll(
		func(userID, email string, expiredAgo time.Duration) bool {
			tokenString, err := createExpiredToken(userID, email, expiredAgo)
			if err != nil {
				return false
			}

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+tokenString)

			rr := httptest.NewRecorder()
			handler := auth.JWTMiddleware(http.HandlerFunc(testProtectedHandler))
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				return false
			}

			// Parse error response
			var errResp map[string]string
			if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
				return false
			}

			// Property: Error message must contain "expired"
			return strings.Contains(strings.ToLower(errResp["error"]), "expired")
		},
		userIDGen,
		emailGen,
		expiredDurationGen,
	))

	properties.Property("error response has JSON content type", prop.ForAll(
		func(userID, email string, expiredAgo time.Duration) bool {
			tokenString, err := createExpiredToken(userID, email, expiredAgo)
			if err != nil {
				return false
			}

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+tokenString)

			rr := httptest.NewRecorder()
			handler := auth.JWTMiddleware(http.HandlerFunc(testProtectedHandler))
			handler.ServeHTTP(rr, req)

			// Property: Content-Type must be application/json
			contentType := rr.Header().Get("Content-Type")
			return strings.Contains(contentType, "application/json")
		},
		userIDGen,
		emailGen,
		expiredDurationGen,
	))

	properties.TestingRun(t)
}

// TestPropertyJWTExpiration_ValidTokensAccepted verifies that tokens with future
// expiration are accepted (contrast property for completeness).
// Property 4.3: Valid (non-expired) tokens are accepted
// Validates Requirement 1.8: Session management allows valid sessions
func TestPropertyJWTExpiration_ValidTokensAccepted(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for valid user IDs
	userIDGen := gen.RegexMatch(`user-[0-9a-f]{8}`)

	// Generator for valid email addresses
	emailGen := gen.RegexMatch(`[a-z]{5,10}@example\.com`)

	// Generator for valid durations (1 minute to 24 hours in the future)
	validDurationGen := gen.Int64Range(60, 24*60*60).Map(func(seconds int64) time.Duration {
		return time.Duration(seconds) * time.Second
	})

	properties.Property("non-expired tokens via Bearer header return 200", prop.ForAll(
		func(userID, email string, expiresIn time.Duration) bool {
			tokenString, err := createValidToken(userID, email, expiresIn)
			if err != nil {
				return false
			}

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+tokenString)

			rr := httptest.NewRecorder()
			handler := auth.JWTMiddleware(http.HandlerFunc(testProtectedHandler))
			handler.ServeHTTP(rr, req)

			// Property: Valid token must return 200 OK
			return rr.Code == http.StatusOK
		},
		userIDGen,
		emailGen,
		validDurationGen,
	))

	properties.Property("non-expired tokens via cookie return 200", prop.ForAll(
		func(userID, email string, expiresIn time.Duration) bool {
			tokenString, err := createValidToken(userID, email, expiresIn)
			if err != nil {
				return false
			}

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.AddCookie(&http.Cookie{
				Name:  auth.CookieName,
				Value: tokenString,
			})

			rr := httptest.NewRecorder()
			handler := auth.JWTMiddleware(http.HandlerFunc(testProtectedHandler))
			handler.ServeHTTP(rr, req)

			// Property: Valid token in cookie must return 200 OK
			return rr.Code == http.StatusOK
		},
		userIDGen,
		emailGen,
		validDurationGen,
	))

	properties.Property("valid token populates user context correctly", prop.ForAll(
		func(userID, email string, expiresIn time.Duration) bool {
			tokenString, err := createValidToken(userID, email, expiresIn)
			if err != nil {
				return false
			}

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+tokenString)

			rr := httptest.NewRecorder()
			handler := auth.JWTMiddleware(http.HandlerFunc(testProtectedHandler))
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				return false
			}

			var resp map[string]string
			if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
				return false
			}

			// Property: User ID from token must be in context
			return resp["user_id"] == userID
		},
		userIDGen,
		emailGen,
		validDurationGen,
	))

	properties.TestingRun(t)
}

// TestPropertyJWTExpiration_BoundaryConditions tests tokens at or near expiration
// boundary to ensure consistent rejection behavior.
// Property 4.4: Tokens at expiration boundary are consistently handled
// Validates Requirement 12.5: Deterministic security token validation
func TestPropertyJWTExpiration_BoundaryConditions(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	properties := gopter.NewProperties(parameters)

	// Generator for valid user IDs
	userIDGen := gen.RegexMatch(`user-[0-9a-f]{8}`)

	// Generator for valid email addresses
	emailGen := gen.RegexMatch(`[a-z]{5,10}@example\.com`)

	// Generator for very small expiration durations (just expired: 1-10 seconds ago)
	recentlyExpiredGen := gen.Int64Range(1, 10).Map(func(seconds int64) time.Duration {
		return time.Duration(seconds) * time.Second
	})

	properties.Property("recently expired tokens (1-10 seconds) are rejected", prop.ForAll(
		func(userID, email string, expiredAgo time.Duration) bool {
			tokenString, err := createExpiredToken(userID, email, expiredAgo)
			if err != nil {
				return false
			}

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+tokenString)

			rr := httptest.NewRecorder()
			handler := auth.JWTMiddleware(http.HandlerFunc(testProtectedHandler))
			handler.ServeHTTP(rr, req)

			// Property: Even recently expired tokens must be rejected
			return rr.Code == http.StatusUnauthorized
		},
		userIDGen,
		emailGen,
		recentlyExpiredGen,
	))

	properties.Property("tokens about to expire (in 30+ seconds) are accepted", prop.ForAll(
		func(userID, email string) bool {
			// Create token that expires in 30 seconds
			tokenString, err := createValidToken(userID, email, 30*time.Second)
			if err != nil {
				return false
			}

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+tokenString)

			rr := httptest.NewRecorder()
			handler := auth.JWTMiddleware(http.HandlerFunc(testProtectedHandler))
			handler.ServeHTTP(rr, req)

			// Property: Token not yet expired must be accepted
			return rr.Code == http.StatusOK
		},
		userIDGen,
		emailGen,
	))

	properties.TestingRun(t)
}

// TestPropertyJWTExpiration_ConsistentRejection verifies that expired tokens are
// consistently rejected across multiple validation attempts.
// Property 4.5: Expired token rejection is deterministic
// Validates Requirement 12.5: Consistent security behavior
func TestPropertyJWTExpiration_ConsistentRejection(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	properties := gopter.NewProperties(parameters)

	// Generator for valid user IDs
	userIDGen := gen.RegexMatch(`user-[0-9a-f]{8}`)

	// Generator for valid email addresses
	emailGen := gen.RegexMatch(`[a-z]{5,10}@example\.com`)

	// Generator for number of attempts (3-10)
	attemptCountGen := gen.IntRange(3, 10)

	properties.Property("expired token rejected consistently across multiple attempts", prop.ForAll(
		func(userID, email string, attempts int) bool {
			// Create single expired token
			tokenString, err := createExpiredToken(userID, email, time.Hour)
			if err != nil {
				return false
			}

			// Validate multiple times
			for i := 0; i < attempts; i++ {
				req := httptest.NewRequest(http.MethodGet, "/protected", nil)
				req.Header.Set("Authorization", "Bearer "+tokenString)

				rr := httptest.NewRecorder()
				handler := auth.JWTMiddleware(http.HandlerFunc(testProtectedHandler))
				handler.ServeHTTP(rr, req)

				// Property: Each attempt must return 401
				if rr.Code != http.StatusUnauthorized {
					return false
				}
			}

			return true
		},
		userIDGen,
		emailGen,
		attemptCountGen,
	))

	properties.TestingRun(t)
}

// TestPropertyJWTExpiration_DifferentUsersSameExpiration verifies that expiration
// checking is independent of user identity claims.
// Property 4.6: Expiration check is independent of user claims
// Validates Requirement 1.8: Universal session expiration policy
func TestPropertyJWTExpiration_DifferentUsersSameExpiration(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for two different user IDs
	userID1Gen := gen.RegexMatch(`user-a-[0-9a-f]{4}`)
	userID2Gen := gen.RegexMatch(`user-b-[0-9a-f]{4}`)

	// Generator for two different emails
	email1Gen := gen.RegexMatch(`alice[0-9]{3}@example\.com`)
	email2Gen := gen.RegexMatch(`bob[0-9]{3}@example\.com`)

	// Fixed expiration duration
	expiredDurationGen := gen.Int64Range(60, 3600).Map(func(seconds int64) time.Duration {
		return time.Duration(seconds) * time.Second
	})

	properties.Property("different users with same expiration both rejected", prop.ForAll(
		func(userID1, userID2, email1, email2 string, expiredAgo time.Duration) bool {
			// Create expired tokens for two different users
			token1, err := createExpiredToken(userID1, email1, expiredAgo)
			if err != nil {
				return false
			}

			token2, err := createExpiredToken(userID2, email2, expiredAgo)
			if err != nil {
				return false
			}

			// Test first user
			req1 := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req1.Header.Set("Authorization", "Bearer "+token1)
			rr1 := httptest.NewRecorder()
			auth.JWTMiddleware(http.HandlerFunc(testProtectedHandler)).ServeHTTP(rr1, req1)

			// Test second user
			req2 := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req2.Header.Set("Authorization", "Bearer "+token2)
			rr2 := httptest.NewRecorder()
			auth.JWTMiddleware(http.HandlerFunc(testProtectedHandler)).ServeHTTP(rr2, req2)

			// Property: Both users must be rejected identically
			return rr1.Code == http.StatusUnauthorized && rr2.Code == http.StatusUnauthorized
		},
		userID1Gen,
		userID2Gen,
		email1Gen,
		email2Gen,
		expiredDurationGen,
	))

	properties.TestingRun(t)
}
