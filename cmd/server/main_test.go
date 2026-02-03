package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestWebhookHandlerValidWebhook tests successful webhook processing with mock APIs
func TestWebhookHandlerValidWebhook(t *testing.T) {
	// Create mock OpenAI server
	openAIMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/chat/completions") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"choices": []map[string]interface{}{
					{"message": map[string]string{"content": "Mock LinkedIn summary for test commit"}},
				},
			})
		} else if strings.Contains(r.URL.Path, "/images/generations") {
			// Use fake.openai.com which is recognized by the image downloader mock
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]string{
					{"url": "https://fake.openai.com/image.png"},
				},
			})
		}
	}))
	defer openAIMock.Close()

	// Create mock LinkedIn server
	var linkedInMock *httptest.Server
	linkedInMock = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/userinfo") {
			// Return person URN for authentication
			json.NewEncoder(w).Encode(map[string]string{"sub": "urn:li:person:test-user"})
		} else if strings.Contains(r.URL.Path, "/images") && r.Method == "POST" {
			// Initialize upload response - must match linkedin.go struct
			json.NewEncoder(w).Encode(map[string]interface{}{
				"value": map[string]interface{}{
					"uploadUrl":          linkedInMock.URL + "/upload",
					"image":              "urn:li:image:mock123",
					"uploadUrlExpiresAt": 9999999999999,
				},
			})
		} else if strings.Contains(r.URL.Path, "/upload") {
			// Image binary upload endpoint
			w.WriteHeader(http.StatusCreated)
		} else if strings.Contains(r.URL.Path, "/posts") {
			// Create post response - return ID in header like real API
			w.Header().Set("x-restli-id", "urn:li:share:mock-post-123")
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer linkedInMock.Close()

	// Set required environment variables with mock server URLs
	os.Setenv("OPENAI_API_KEY", "test-openai-key")
	os.Setenv("LINKEDIN_ACCESS_TOKEN", "test-linkedin-token")
	os.Setenv("WEBHOOK_SECRET", "test-secret")
	defer func() {
		os.Unsetenv("OPENAI_API_KEY")
		os.Unsetenv("LINKEDIN_ACCESS_TOKEN")
		os.Unsetenv("WEBHOOK_SECRET")
	}()

	// Create config with mock URLs injected via custom handler
	config := loadConfig()
	handler := webhookHandlerWithMocks(config, openAIMock.URL, linkedInMock.URL)

	// Create valid GitHub webhook payload
	payload := `{
		"repository": {"html_url": "https://github.com/test/repo"},
		"commits": [{
			"id": "abc123",
			"message": "feat: test commit",
			"author": {"name": "Test Author"}
		}]
	}`

	// Generate valid signature
	signature := "sha256=" + generateTestSignature([]byte(payload), "test-secret")

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", signature)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
		t.Logf("Response body: %s", rec.Body.String())
	}

	// Verify the response contains success message
	body := rec.Body.String()
	if !strings.Contains(body, "processed successfully") {
		t.Errorf("Expected success message, got: %s", body)
	}
}

// TestWebhookHandlerInvalidSignature tests rejection of invalid signatures
func TestWebhookHandlerInvalidSignature(t *testing.T) {
	os.Setenv("WEBHOOK_SECRET", "test-secret")
	defer os.Unsetenv("WEBHOOK_SECRET")

	config := loadConfig()
	handler := webhookHandler(config)

	payload := `{"commits": []}`

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", "sha256=invalidsignature")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rec.Code)
	}

	if !strings.Contains(rec.Body.String(), "Invalid signature") {
		t.Errorf("Expected error message about signature, got: %s", rec.Body.String())
	}
}

// TestValidateConfigMissingWebhookSecret tests that validateConfig catches missing WEBHOOK_SECRET
func TestValidateConfigMissingWebhookSecret(t *testing.T) {
	config := Config{
		OpenAIAPIKey:        "test-key",
		LinkedInAccessToken: "test-token",
		WebhookSecret:       "", // Missing
	}

	err := validateConfig(config)
	if err == nil {
		t.Error("Expected error for missing WEBHOOK_SECRET")
	}
}

// TestValidateConfigValid tests that validateConfig passes with required fields
func TestValidateConfigValid(t *testing.T) {
	config := Config{
		WebhookSecret: "test-secret",
		// OpenAI and LinkedIn are optional for validation
	}

	err := validateConfig(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

// TestConfigLoadsFromEnv tests environment variable loading
func TestConfigLoadsFromEnv(t *testing.T) {
	// Set specific env var values
	os.Setenv("OPENAI_API_KEY", "sk-test-key-123")
	os.Setenv("LINKEDIN_ACCESS_TOKEN", "linkedin-token-456")
	os.Setenv("WEBHOOK_SECRET", "webhook-secret-789")
	defer func() {
		os.Unsetenv("OPENAI_API_KEY")
		os.Unsetenv("LINKEDIN_ACCESS_TOKEN")
		os.Unsetenv("WEBHOOK_SECRET")
	}()

	config := loadConfig()

	if config.OpenAIAPIKey != "sk-test-key-123" {
		t.Errorf("Expected OpenAI key 'sk-test-key-123', got '%s'", config.OpenAIAPIKey)
	}

	if config.LinkedInAccessToken != "linkedin-token-456" {
		t.Errorf("Expected LinkedIn token 'linkedin-token-456', got '%s'", config.LinkedInAccessToken)
	}

	if config.WebhookSecret != "webhook-secret-789" {
		t.Errorf("Expected webhook secret 'webhook-secret-789', got '%s'", config.WebhookSecret)
	}
}

// TestWebhookHandlerParsesWebhookPayload tests webhook payload parsing
func TestWebhookHandlerParsesWebhookPayload(t *testing.T) {
	os.Setenv("WEBHOOK_SECRET", "test-secret")
	defer os.Unsetenv("WEBHOOK_SECRET")

	config := loadConfig()
	handler := webhookHandler(config)

	// Create webhook with specific commit message
	payload := `{
		"repository": {"html_url": "https://github.com/test/repo"},
		"commits": [{
			"id": "commit123",
			"message": "feat: add authentication system",
			"author": {"name": "Developer"}
		}]
	}`

	signature := "sha256=" + generateTestSignature([]byte(payload), "test-secret")

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", signature)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should accept the webhook (200 for missing API keys)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestWebhookHandlerMissingSignature tests handling of requests without signature
func TestWebhookHandlerMissingSignature(t *testing.T) {
	os.Setenv("WEBHOOK_SECRET", "test-secret")
	defer os.Unsetenv("WEBHOOK_SECRET")

	config := loadConfig()
	handler := webhookHandler(config)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(`{"commits": []}`))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for missing signature, got %d", rec.Code)
	}
}

// TestCombinedRouterServesWebhook tests that /webhook is routed correctly
func TestCombinedRouterServesWebhook(t *testing.T) {
	os.Setenv("WEBHOOK_SECRET", "test-secret")
	defer os.Unsetenv("WEBHOOK_SECRET")

	config := loadConfig()
	router := createRouter(config, nil)

	payload := `{
		"repository": {"html_url": "https://github.com/test/repo"},
		"commits": [{
			"id": "abc123",
			"message": "test",
			"author": {"name": "Test"}
		}]
	}`
	signature := "sha256=" + generateTestSignature([]byte(payload), "test-secret")

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", signature)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Should return 200 (webhook accepted, processing skipped due to missing API keys)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestCombinedRouterWebhookTrailingSlash tests that /webhook/ (with trailing slash) is rejected
// This documents the expected behavior: GitHub sends to /webhook exactly, not /webhook/
// The trailing slash path falls through to the web router, which rejects it via CSRF protection
func TestCombinedRouterWebhookTrailingSlash(t *testing.T) {
	os.Setenv("WEBHOOK_SECRET", "test-secret")
	defer os.Unsetenv("WEBHOOK_SECRET")

	config := loadConfig()
	router := createRouter(config, nil)

	req := httptest.NewRequest(http.MethodPost, "/webhook/", strings.NewReader(`{"commits": []}`))
	req.Header.Set("X-Hub-Signature-256", "sha256=test")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// /webhook/ falls through to web router which rejects POST without CSRF token
	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for /webhook/, got %d", rec.Code)
	}
}

// TestCombinedRouterServesHomePage tests that / is routed to web UI
func TestCombinedRouterServesHomePage(t *testing.T) {
	config := loadConfig()
	router := createRouter(config, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	// Should return HTML
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Errorf("Expected HTML content type, got %s", rec.Header().Get("Content-Type"))
	}
}

// TestCombinedRouterServesLoginPage tests that /login is routed to web UI
func TestCombinedRouterServesLoginPage(t *testing.T) {
	config := loadConfig()
	router := createRouter(config, nil)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	// Should return HTML with login form
	body := rec.Body.String()
	if !strings.Contains(body, "Login") {
		t.Error("Expected login page content")
	}
}

// TestCombinedRouterServesStaticCSS tests that /static/css/style.css serves CSS
func TestCombinedRouterServesStaticCSS(t *testing.T) {
	config := loadConfig()
	router := createRouter(config, nil)

	req := httptest.NewRequest(http.MethodGet, "/static/css/style.css", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	// Should return CSS content type
	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/css") {
		t.Errorf("Expected CSS content type, got %s", contentType)
	}

	// Should contain CSS content, not HTML
	body := rec.Body.String()
	if strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("Expected CSS content but got HTML")
	}
}

// Helper function to generate HMAC signature for testing
func generateTestSignature(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
