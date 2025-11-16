package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

// generateHMAC creates a GitHub-style HMAC signature
func generateHMAC(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// TestWebhookValidatesSignature tests that valid signatures are accepted
func TestWebhookValidatesSignature(t *testing.T) {
	secret := "test-secret"
	payload := []byte(`{"commits":[{"message":"test commit","id":"abc123"}]}`)

	// Generate valid signature
	validSig := generateHMAC(payload, secret)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", "sha256="+validSig)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := NewWebhookHandler(secret)

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

// TestWebhookRejectsInvalidSignature tests that invalid signatures are rejected
func TestWebhookRejectsInvalidSignature(t *testing.T) {
	secret := "test-secret"
	payload := []byte(`{"commits":[{"message":"test"}]}`)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", "sha256=invalidsignature")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := NewWebhookHandler(secret)

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

// TestWebhookRejectsMissingSignature tests that requests without signatures are rejected
func TestWebhookRejectsMissingSignature(t *testing.T) {
	secret := "test-secret"
	payload := []byte(`{"commits":[{"message":"test"}]}`)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	// No signature header

	rr := httptest.NewRecorder()
	handler := NewWebhookHandler(secret)

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

// TestWebhookParsesCommitData tests that commit data is correctly extracted
func TestWebhookParsesCommitData(t *testing.T) {
	secret := "test-secret"
	payload := []byte(`{
		"repository": {
			"html_url": "https://github.com/test/repo"
		},
		"commits": [{
			"message": "fix: resolve memory leak",
			"id": "abc123",
			"author": {
				"name": "Test Author"
			}
		}]
	}`)

	validSig := generateHMAC(payload, secret)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", "sha256="+validSig)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := NewWebhookHandler(secret)

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// In TB03, we'll verify the commit was actually parsed
	// For now, just verify the request succeeds
}

// TestWebhookExtractCommit tests the commit extraction logic
func TestWebhookExtractCommit(t *testing.T) {
	payload := []byte(`{
		"repository": {
			"html_url": "https://github.com/test/repo"
		},
		"commits": [{
			"message": "feat: add new feature",
			"id": "xyz789",
			"author": {
				"name": "Jane Developer"
			}
		}]
	}`)

	commit, err := extractCommitFromWebhook(payload)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if commit.Message != "feat: add new feature" {
		t.Errorf("Expected message 'feat: add new feature', got '%s'", commit.Message)
	}

	if commit.Author != "Jane Developer" {
		t.Errorf("Expected author 'Jane Developer', got '%s'", commit.Author)
	}

	if commit.RepoURL != "https://github.com/test/repo" {
		t.Errorf("Expected repo URL 'https://github.com/test/repo', got '%s'", commit.RepoURL)
	}
}

// TestWebhookHandlesInvalidJSON tests error handling for malformed JSON
func TestWebhookHandlesInvalidJSON(t *testing.T) {
	secret := "test-secret"
	payload := []byte(`{invalid json}`)

	validSig := generateHMAC(payload, secret)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", "sha256="+validSig)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := NewWebhookHandler(secret)

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}
