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
		WebhookSecret: "", // Missing
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
	}

	err := validateConfig(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

// TestConfigLoadsFromEnv tests environment variable loading
func TestConfigLoadsFromEnv(t *testing.T) {
	// Set specific env var values
	os.Setenv("WEBHOOK_SECRET", "webhook-secret-789")
	os.Setenv("BEDROCK_MODEL_ID", "us.anthropic.claude-sonnet-4-5-20250929-v1:0")
	os.Setenv("BUFFER_ACCESS_TOKEN", "buffer-token-123")
	defer func() {
		os.Unsetenv("WEBHOOK_SECRET")
		os.Unsetenv("BEDROCK_MODEL_ID")
		os.Unsetenv("BUFFER_ACCESS_TOKEN")
	}()

	config := loadConfig()

	if config.WebhookSecret != "webhook-secret-789" {
		t.Errorf("Expected webhook secret 'webhook-secret-789', got '%s'", config.WebhookSecret)
	}

	if config.BedrockModelID != "us.anthropic.claude-sonnet-4-5-20250929-v1:0" {
		t.Errorf("Expected Bedrock model ID, got '%s'", config.BedrockModelID)
	}

	if config.BufferAccessToken != "buffer-token-123" {
		t.Errorf("Expected Buffer token 'buffer-token-123', got '%s'", config.BufferAccessToken)
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

	// Should accept the webhook (200)
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

	// Should return 200 (webhook accepted)
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
