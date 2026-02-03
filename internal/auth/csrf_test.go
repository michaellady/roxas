package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestGenerateCSRFToken_ReturnsNonEmptyToken(t *testing.T) {
	token, err := GenerateCSRFToken()
	if err != nil {
		t.Fatalf("GenerateCSRFToken failed: %v", err)
	}
	if token == "" {
		t.Error("Expected non-empty token")
	}
	// Token should be base64 encoded (44 chars for 32 bytes)
	if len(token) < 40 {
		t.Errorf("Token appears too short: %d chars", len(token))
	}
}

func TestGenerateCSRFToken_ReturnsUniqueTokens(t *testing.T) {
	token1, _ := GenerateCSRFToken()
	token2, _ := GenerateCSRFToken()
	if token1 == token2 {
		t.Error("Expected unique tokens, got same token twice")
	}
}

func TestValidateCSRFToken_MatchingTokens_ReturnsTrue(t *testing.T) {
	token := "test-token-value"
	if !ValidateCSRFToken(token, token) {
		t.Error("Expected matching tokens to validate")
	}
}

func TestValidateCSRFToken_DifferentTokens_ReturnsFalse(t *testing.T) {
	if ValidateCSRFToken("token1", "token2") {
		t.Error("Expected different tokens to fail validation")
	}
}

func TestValidateCSRFToken_EmptyCookieToken_ReturnsFalse(t *testing.T) {
	if ValidateCSRFToken("", "form-token") {
		t.Error("Expected empty cookie token to fail validation")
	}
}

func TestValidateCSRFToken_EmptyFormToken_ReturnsFalse(t *testing.T) {
	if ValidateCSRFToken("cookie-token", "") {
		t.Error("Expected empty form token to fail validation")
	}
}

func TestCSRFMiddleware_GETRequest_Passes(t *testing.T) {
	handler := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected GET request to pass, got status %d", rr.Code)
	}
}

func TestCSRFMiddleware_POSTWithoutToken_Returns403(t *testing.T) {
	handler := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected POST without CSRF to return 403, got %d", rr.Code)
	}
}

func TestCSRFMiddleware_POSTWithValidToken_Passes(t *testing.T) {
	handler := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	token, _ := GenerateCSRFToken()

	form := url.Values{}
	form.Set(CSRFFormFieldName, token)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected POST with valid CSRF to pass, got status %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCSRFMiddleware_POSTWithMismatchedToken_Returns403(t *testing.T) {
	handler := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	form := url.Values{}
	form.Set(CSRFFormFieldName, "form-token")

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "cookie-token"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected mismatched CSRF tokens to return 403, got %d", rr.Code)
	}
}

func TestCSRFMiddleware_POSTWithHeaderToken_Passes(t *testing.T) {
	handler := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	token, _ := GenerateCSRFToken()

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected POST with header CSRF token to pass, got status %d", rr.Code)
	}
}

func TestEnsureCSRFToken_NewToken_SetsTokenAndCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	token, err := EnsureCSRFToken(rr, req)
	if err != nil {
		t.Fatalf("EnsureCSRFToken failed: %v", err)
	}

	if token == "" {
		t.Error("Expected non-empty token")
	}

	// Should set cookie
	cookies := rr.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == CSRFCookieName {
			csrfCookie = c
			break
		}
	}

	if csrfCookie == nil {
		t.Error("Expected CSRF cookie to be set")
	} else if csrfCookie.Value != token {
		t.Errorf("Expected cookie value to match token, got %s", csrfCookie.Value)
	}
}

func TestEnsureCSRFToken_ExistingToken_ReturnsSameToken(t *testing.T) {
	existingToken := "existing-csrf-token"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: existingToken})
	rr := httptest.NewRecorder()

	token, err := EnsureCSRFToken(rr, req)
	if err != nil {
		t.Fatalf("EnsureCSRFToken failed: %v", err)
	}

	if token != existingToken {
		t.Errorf("Expected existing token %s, got %s", existingToken, token)
	}
}
