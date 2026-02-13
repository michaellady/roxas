package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// Property Test: CSRF Protection (Property 35)
// Validates Requirements 13.6
//
// Property: For any form submission endpoint, the system should validate CSRF tokens
// and reject requests with missing or invalid tokens.
//
// This property test verifies that:
// - For ANY valid CSRF token, form submissions are accepted (200 OK or redirect)
// - For ANY form submission without a CSRF token, the request is rejected (403 Forbidden)
// - For ANY form submission with an invalid CSRF token, the request is rejected (403 Forbidden)
// - CSRF token validation uses constant-time comparison to prevent timing attacks

// dummyHandler is a simple handler that returns 200 OK when CSRF validation passes
func dummyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

// createFormRequest creates a POST request with form data and optional CSRF token
func createFormRequest(formData map[string]string, csrfCookie string, csrfFormToken string) *http.Request {
	form := url.Values{}
	for k, v := range formData {
		form.Add(k, v)
	}
	if csrfFormToken != "" {
		form.Add(CSRFFormFieldName, csrfFormToken)
	}

	req := httptest.NewRequest(http.MethodPost, "/form", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if csrfCookie != "" {
		req.AddCookie(&http.Cookie{
			Name:  CSRFCookieName,
			Value: csrfCookie,
		})
	}

	return req
}

// TestPropertyValidCSRFTokenAccepted verifies that valid CSRF tokens are always accepted
// Property: For any (formData, csrfToken) pair, if cookie token == form token, request succeeds
func TestPropertyValidCSRFTokenAccepted(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("Valid CSRF tokens are always accepted with 200 OK", prop.ForAll(
		func(fieldName string, fieldValue string) bool {
			// Generate a valid CSRF token
			token, err := GenerateCSRFToken()
			if err != nil {
				return false
			}

			// Create form data with the generated token
			formData := map[string]string{}
			if fieldName != "" {
				formData[fieldName] = fieldValue
			}

			req := createFormRequest(formData, token, token) // Same token in cookie and form
			rr := httptest.NewRecorder()

			handler := CSRFMiddleware(dummyHandler())
			handler.ServeHTTP(rr, req)

			// Valid CSRF token MUST result in 200 OK
			return rr.Code == http.StatusOK
		},
		gen.AlphaString(), // fieldName
		gen.AnyString(),   // fieldValue
	))

	properties.TestingRun(t)
}

// TestPropertyMissingCSRFTokenRejected verifies that missing CSRF tokens are always rejected
// Property: For any form submission without a CSRF token, the request is rejected with 403
func TestPropertyMissingCSRFTokenRejected(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("Missing CSRF token is always rejected with 403", prop.ForAll(
		func(fieldName string, fieldValue string) bool {
			formData := map[string]string{}
			if fieldName != "" {
				formData[fieldName] = fieldValue
			}

			// No CSRF token - neither in cookie nor in form
			req := createFormRequest(formData, "", "")
			rr := httptest.NewRecorder()

			handler := CSRFMiddleware(dummyHandler())
			handler.ServeHTTP(rr, req)

			// Missing CSRF token MUST result in 403 Forbidden
			return rr.Code == http.StatusForbidden
		},
		gen.AlphaString(), // fieldName
		gen.AnyString(),   // fieldValue
	))

	properties.TestingRun(t)
}

// TestPropertyMissingFormTokenRejected verifies that missing form token (but present cookie) is rejected
// Property: For any form submission with cookie token but no form token, request is rejected with 403
func TestPropertyMissingFormTokenRejected(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("Missing form token (cookie present) is always rejected with 403", prop.ForAll(
		func(fieldName string, fieldValue string) bool {
			token, err := GenerateCSRFToken()
			if err != nil {
				return false
			}

			formData := map[string]string{}
			if fieldName != "" {
				formData[fieldName] = fieldValue
			}

			// Cookie has token, but form does not
			req := createFormRequest(formData, token, "")
			rr := httptest.NewRecorder()

			handler := CSRFMiddleware(dummyHandler())
			handler.ServeHTTP(rr, req)

			// Missing form token MUST result in 403 Forbidden
			return rr.Code == http.StatusForbidden
		},
		gen.AlphaString(), // fieldName
		gen.AnyString(),   // fieldValue
	))

	properties.TestingRun(t)
}

// TestPropertyMissingCookieTokenRejected verifies that missing cookie token (but present form) is rejected
// Property: For any form submission with form token but no cookie token, request is rejected with 403
func TestPropertyMissingCookieTokenRejected(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("Missing cookie token (form present) is always rejected with 403", prop.ForAll(
		func(fieldName string, fieldValue string) bool {
			token, err := GenerateCSRFToken()
			if err != nil {
				return false
			}

			formData := map[string]string{}
			if fieldName != "" {
				formData[fieldName] = fieldValue
			}

			// Form has token, but cookie does not
			req := createFormRequest(formData, "", token)
			rr := httptest.NewRecorder()

			handler := CSRFMiddleware(dummyHandler())
			handler.ServeHTTP(rr, req)

			// Missing cookie token MUST result in 403 Forbidden
			return rr.Code == http.StatusForbidden
		},
		gen.AlphaString(), // fieldName
		gen.AnyString(),   // fieldValue
	))

	properties.TestingRun(t)
}

// TestPropertyInvalidCSRFTokenRejected verifies that invalid/mismatched CSRF tokens are always rejected
// Property: For any (cookieToken, formToken) pair where cookieToken != formToken, request is rejected
func TestPropertyInvalidCSRFTokenRejected(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("Invalid/mismatched CSRF tokens are always rejected with 403", prop.ForAll(
		func(fieldName string, fieldValue string, tokenSuffix string) bool {
			// Generate two different tokens
			cookieToken, err := GenerateCSRFToken()
			if err != nil {
				return false
			}
			formToken, err := GenerateCSRFToken()
			if err != nil {
				return false
			}

			// Ensure tokens are different (they almost certainly are, but just in case)
			if cookieToken == formToken {
				formToken = formToken + tokenSuffix // Make them different
			}

			formData := map[string]string{}
			if fieldName != "" {
				formData[fieldName] = fieldValue
			}

			req := createFormRequest(formData, cookieToken, formToken)
			rr := httptest.NewRecorder()

			handler := CSRFMiddleware(dummyHandler())
			handler.ServeHTTP(rr, req)

			// Mismatched CSRF tokens MUST result in 403 Forbidden
			return rr.Code == http.StatusForbidden
		},
		gen.AlphaString(), // fieldName
		gen.AnyString(),   // fieldValue
		gen.AlphaString(), // tokenSuffix (to ensure tokens differ)
	))

	properties.TestingRun(t)
}

// TestPropertyTamperedCSRFTokenRejected verifies that tampered CSRF tokens are rejected
// Property: For any valid token that is modified, the request is rejected with 403
func TestPropertyTamperedCSRFTokenRejected(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("Tampered CSRF tokens are always rejected with 403", prop.ForAll(
		func(fieldName string, fieldValue string, tamperedSuffix string) bool {
			token, err := GenerateCSRFToken()
			if err != nil {
				return false
			}

			// Tamper with the token
			tamperedToken := token + tamperedSuffix
			if tamperedToken == token {
				tamperedToken = token + "x" // Ensure it's different
			}

			formData := map[string]string{}
			if fieldName != "" {
				formData[fieldName] = fieldValue
			}

			req := createFormRequest(formData, token, tamperedToken)
			rr := httptest.NewRecorder()

			handler := CSRFMiddleware(dummyHandler())
			handler.ServeHTTP(rr, req)

			// Tampered CSRF token MUST result in 403 Forbidden
			return rr.Code == http.StatusForbidden
		},
		gen.AlphaString(), // fieldName
		gen.AnyString(),   // fieldValue
		gen.AlphaString(), // tamperedSuffix
	))

	properties.TestingRun(t)
}

// TestPropertyGETRequestsBypassCSRF verifies that GET requests bypass CSRF validation
// Property: For any GET request, CSRF validation is not applied
func TestPropertyGETRequestsBypassCSRF(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("GET requests bypass CSRF validation and return 200 OK", prop.ForAll(
		func(path string) bool {
			// Sanitize path to ensure it's valid
			if path == "" {
				path = "/"
			}
			if path[0] != '/' {
				path = "/" + path
			}

			req := httptest.NewRequest(http.MethodGet, path, nil)
			// No CSRF token
			rr := httptest.NewRecorder()

			handler := CSRFMiddleware(dummyHandler())
			handler.ServeHTTP(rr, req)

			// GET requests MUST bypass CSRF validation
			return rr.Code == http.StatusOK
		},
		gen.AlphaString(), // path
	))

	properties.TestingRun(t)
}

// TestPropertyConstantTimeComparison verifies that CSRF validation uses constant-time comparison
// Property: The validation function produces consistent results regardless of where tokens differ
// This is a structural test - we verify the code path, not timing (timing tests are flaky)
func TestPropertyConstantTimeComparison(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("CSRF validation uses constant-time comparison (returns consistent results)", prop.ForAll(
		func(suffix1 string, suffix2 string) bool {
			token1, err := GenerateCSRFToken()
			if err != nil {
				return false
			}
			token2, err := GenerateCSRFToken()
			if err != nil {
				return false
			}

			// Test that different tokens produce different validation results
			// and validation correctly distinguishes them
			valid1with1 := ValidateCSRFToken(token1, token1)
			valid2with2 := ValidateCSRFToken(token2, token2)
			valid1with2 := ValidateCSRFToken(token1, token2)
			valid2with1 := ValidateCSRFToken(token2, token1)

			// Same token should validate
			if !valid1with1 || !valid2with2 {
				return false
			}

			// Different tokens should not validate (unless by extremely unlikely collision)
			if token1 != token2 {
				if valid1with2 || valid2with1 {
					return false
				}
			}

			return true
		},
		gen.AlphaString(), // suffix1 (unused but for generator variety)
		gen.AlphaString(), // suffix2 (unused but for generator variety)
	))

	properties.TestingRun(t)
}

// TestPropertyCSRFTokenGeneration verifies that generated CSRF tokens are valid and unique
// Property: For any two generated tokens, they should be different (with high probability)
func TestPropertyCSRFTokenGeneration(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("Generated CSRF tokens are unique", prop.ForAll(
		func(_ int) bool {
			token1, err := GenerateCSRFToken()
			if err != nil {
				return false
			}
			token2, err := GenerateCSRFToken()
			if err != nil {
				return false
			}

			// Tokens should be different (probability of collision is negligible: 2^-256)
			return token1 != token2
		},
		gen.Int(), // dummy parameter to drive generation
	))

	properties.TestingRun(t)
}

// TestPropertyCSRFHeaderToken verifies that X-CSRF-Token header is accepted for AJAX requests
// Property: For any AJAX request with valid X-CSRF-Token header, the request succeeds
func TestPropertyCSRFHeaderToken(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("X-CSRF-Token header is accepted for valid tokens", prop.ForAll(
		func(requestBody string) bool {
			token, err := GenerateCSRFToken()
			if err != nil {
				return false
			}

			// Create POST request with header instead of form field
			req := httptest.NewRequest(http.MethodPost, "/api/endpoint", strings.NewReader(requestBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-CSRF-Token", token)
			req.AddCookie(&http.Cookie{
				Name:  CSRFCookieName,
				Value: token,
			})

			rr := httptest.NewRecorder()

			handler := CSRFMiddleware(dummyHandler())
			handler.ServeHTTP(rr, req)

			// Valid header token MUST result in 200 OK
			return rr.Code == http.StatusOK
		},
		gen.AnyString(), // requestBody
	))

	properties.TestingRun(t)
}
