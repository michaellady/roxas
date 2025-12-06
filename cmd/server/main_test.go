package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestWebhookHandlerValidWebhook tests successful webhook processing
func TestWebhookHandlerValidWebhook(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping system test that requires real API credentials")
	}

	// Set required environment variables
	os.Setenv("OPENAI_API_KEY", "test-openai-key")
	os.Setenv("LINKEDIN_ACCESS_TOKEN", "test-linkedin-token")
	os.Setenv("WEBHOOK_SECRET", "test-secret")
	defer func() {
		os.Unsetenv("OPENAI_API_KEY")
		os.Unsetenv("LINKEDIN_ACCESS_TOKEN")
		os.Unsetenv("WEBHOOK_SECRET")
	}()

	config := loadConfig()
	handler := webhookHandler(config)

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

// TestCombinedRouterWebhookTrailingSlash tests that /webhook/ (with trailing slash) returns 404
// This documents the expected behavior: GitHub sends to /webhook exactly, not /webhook/
func TestCombinedRouterWebhookTrailingSlash(t *testing.T) {
	os.Setenv("WEBHOOK_SECRET", "test-secret")
	defer os.Unsetenv("WEBHOOK_SECRET")

	config := loadConfig()
	router := createRouter(config, nil)

	req := httptest.NewRequest(http.MethodPost, "/webhook/", strings.NewReader(`{"commits": []}`))
	req.Header.Set("X-Hub-Signature-256", "sha256=test")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// /webhook/ falls through to web router which returns 404 for unknown paths
	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for /webhook/, got %d", rec.Code)
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

// Helper function to generate HMAC signature for testing
func generateTestSignature(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
