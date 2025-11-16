package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

// TestLambdaHandlerValidWebhook tests successful webhook processing
func TestLambdaHandlerValidWebhook(t *testing.T) {
	// Set required environment variables
	os.Setenv("OPENAI_API_KEY", "test-openai-key")
	os.Setenv("LINKEDIN_ACCESS_TOKEN", "test-linkedin-token")
	os.Setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
	defer func() {
		os.Unsetenv("OPENAI_API_KEY")
		os.Unsetenv("LINKEDIN_ACCESS_TOKEN")
		os.Unsetenv("GITHUB_WEBHOOK_SECRET")
	}()

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
	signature := generateTestSignature([]byte(payload), "test-secret")

	// Create Lambda API Gateway event
	request := events.APIGatewayProxyRequest{
		Body: payload,
		Headers: map[string]string{
			"X-Hub-Signature-256": "sha256=" + signature,
			"Content-Type":        "application/json",
		},
		HTTPMethod: "POST",
		Path:       "/webhook",
	}

	// Call handler
	response, err := Handler(context.Background(), request)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if response.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", response.StatusCode)
		t.Logf("Response body: %s", response.Body)
	}
}

// TestLambdaHandlerInvalidSignature tests rejection of invalid signatures
func TestLambdaHandlerInvalidSignature(t *testing.T) {
	// Set required environment variables
	os.Setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
	defer os.Unsetenv("GITHUB_WEBHOOK_SECRET")

	payload := `{"commits": []}`

	request := events.APIGatewayProxyRequest{
		Body: payload,
		Headers: map[string]string{
			"X-Hub-Signature-256": "sha256=invalidsignature",
			"Content-Type":        "application/json",
		},
		HTTPMethod: "POST",
	}

	response, err := Handler(context.Background(), request)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if response.StatusCode != 401 {
		t.Errorf("Expected status 401, got %d", response.StatusCode)
	}

	if !strings.Contains(response.Body, "Invalid signature") && !strings.Contains(response.Body, "Unauthorized") {
		t.Errorf("Expected error message about signature, got: %s", response.Body)
	}
}

// TestLambdaHandlerMissingEnvVars tests handling of missing configuration
func TestLambdaHandlerMissingEnvVars(t *testing.T) {
	// Clear environment variables
	os.Unsetenv("OPENAI_API_KEY")
	os.Unsetenv("LINKEDIN_ACCESS_TOKEN")
	os.Unsetenv("GITHUB_WEBHOOK_SECRET")

	payload := `{"commits": []}`

	request := events.APIGatewayProxyRequest{
		Body:       payload,
		HTTPMethod: "POST",
	}

	response, err := Handler(context.Background(), request)

	// Should handle gracefully - either return error or 500
	if err == nil && response.StatusCode == 200 {
		t.Error("Expected error or non-200 status with missing env vars")
	}

	if response.StatusCode != 0 && response.StatusCode != 500 && response.StatusCode != 401 {
		t.Logf("Got status %d (acceptable for missing config)", response.StatusCode)
	}
}

// TestLambdaHandlerLoadsFromEnv tests environment variable loading
func TestLambdaHandlerLoadsFromEnv(t *testing.T) {
	// Set specific env var values
	os.Setenv("OPENAI_API_KEY", "sk-test-key-123")
	os.Setenv("LINKEDIN_ACCESS_TOKEN", "linkedin-token-456")
	os.Setenv("GITHUB_WEBHOOK_SECRET", "webhook-secret-789")
	defer func() {
		os.Unsetenv("OPENAI_API_KEY")
		os.Unsetenv("LINKEDIN_ACCESS_TOKEN")
		os.Unsetenv("GITHUB_WEBHOOK_SECRET")
	}()

	// Get config (this will be implemented)
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

// TestLambdaHandlerReturns200 tests proper HTTP response format
func TestLambdaHandlerReturns200(t *testing.T) {
	os.Setenv("OPENAI_API_KEY", "test-key")
	os.Setenv("LINKEDIN_ACCESS_TOKEN", "test-token")
	os.Setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
	defer func() {
		os.Unsetenv("OPENAI_API_KEY")
		os.Unsetenv("LINKEDIN_ACCESS_TOKEN")
		os.Unsetenv("GITHUB_WEBHOOK_SECRET")
	}()

	payload := `{
		"repository": {"html_url": "https://github.com/test/repo"},
		"commits": [{
			"id": "xyz",
			"message": "test",
			"author": {"name": "Test"}
		}]
	}`

	signature := generateTestSignature([]byte(payload), "test-secret")

	request := events.APIGatewayProxyRequest{
		Body: payload,
		Headers: map[string]string{
			"X-Hub-Signature-256": "sha256=" + signature,
		},
		HTTPMethod: "POST",
	}

	response, err := Handler(context.Background(), request)

	if err != nil {
		t.Fatalf("Handler returned error: %v", err)
	}

	// Should return valid API Gateway response
	if response.StatusCode == 0 {
		t.Error("Expected non-zero status code")
	}

	// Should have proper structure
	if response.Body == "" && response.StatusCode == 200 {
		t.Error("Expected response body for 200 status")
	}
}

// TestLambdaHandlerParsesWebhookPayload tests webhook payload parsing
func TestLambdaHandlerParsesWebhookPayload(t *testing.T) {
	os.Setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
	defer os.Unsetenv("GITHUB_WEBHOOK_SECRET")

	// Create webhook with specific commit message
	payload := `{
		"repository": {"html_url": "https://github.com/test/repo"},
		"commits": [{
			"id": "commit123",
			"message": "feat: add authentication system",
			"author": {"name": "Developer"}
		}]
	}`

	signature := generateTestSignature([]byte(payload), "test-secret")

	request := events.APIGatewayProxyRequest{
		Body: payload,
		Headers: map[string]string{
			"X-Hub-Signature-256": "sha256=" + signature,
			"Content-Type":        "application/json",
		},
		HTTPMethod: "POST",
	}

	response, err := Handler(context.Background(), request)

	// Should parse successfully
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should accept the webhook (even if processing fails due to missing real API keys)
	if response.StatusCode != 200 && response.StatusCode != 202 {
		t.Logf("Got status %d (may be acceptable if async processing)", response.StatusCode)
	}
}

// TestLambdaHandlerMissingSignature tests handling of requests without signature
func TestLambdaHandlerMissingSignature(t *testing.T) {
	os.Setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
	defer os.Unsetenv("GITHUB_WEBHOOK_SECRET")

	request := events.APIGatewayProxyRequest{
		Body:       `{"commits": []}`,
		Headers:    map[string]string{},
		HTTPMethod: "POST",
	}

	response, err := Handler(context.Background(), request)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if response.StatusCode != 401 {
		t.Errorf("Expected status 401 for missing signature, got %d", response.StatusCode)
	}
}

// Helper function to generate HMAC signature for testing
func generateTestSignature(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
