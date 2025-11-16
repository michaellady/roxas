package tests

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// generateHMAC creates a GitHub-style HMAC signature for webhook validation
func generateHMAC(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// loadTestWebhook loads a test webhook payload from testdata
func loadTestWebhook(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}

// MockLinkedInTracker tracks LinkedIn posts created during tests
type MockLinkedInTracker struct {
	Posts []LinkedInPost
}

type LinkedInPost struct {
	Text      string
	ImagePath string
	Timestamp time.Time
}

var testLinkedInTracker *MockLinkedInTracker

// TestEndToEndWebhookToLinkedIn tests the complete flow from GitHub webhook to LinkedIn post
func TestEndToEndWebhookToLinkedIn(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Initialize test tracker
	testLinkedInTracker = &MockLinkedInTracker{
		Posts: make([]LinkedInPost, 0),
	}

	// Setup test orchestrator (will be implemented in TB11)
	orchestrator := setupTestOrchestrator(testLinkedInTracker)
	defer teardownTestOrchestrator(orchestrator)

	// Load test webhook payload
	payload, err := loadTestWebhook("testdata/commit_webhook.json")
	if err != nil {
		t.Fatalf("Failed to load test webhook: %v", err)
	}

	// Create test HTTP request with GitHub webhook signature
	secret := "test-webhook-secret"
	signature := generateHMAC(payload, secret)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", "sha256="+signature)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "push")

	// Create response recorder
	rr := httptest.NewRecorder()

	// Send webhook request to orchestrator
	orchestrator.HandleWebhook(rr, req)

	// Verify webhook was accepted
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
		t.Logf("Response body: %s", rr.Body.String())
	}

	// Wait for async processing to complete
	// In TB11, orchestrator will process: webhook → summarize → generate image → post to LinkedIn
	time.Sleep(3 * time.Second)

	// Verify LinkedIn post was created
	if len(testLinkedInTracker.Posts) == 0 {
		t.Fatal("Expected at least one LinkedIn post to be created")
	}

	post := testLinkedInTracker.Posts[0]

	// Verify post contains commit information
	if post.Text == "" {
		t.Error("Expected non-empty post text")
	}

	// Post should reference the optimization work
	lowerText := strings.ToLower(post.Text)
	hasRelevantKeywords := strings.Contains(lowerText, "database") ||
		strings.Contains(lowerText, "performance") ||
		strings.Contains(lowerText, "optimization") ||
		strings.Contains(lowerText, "query")

	if !hasRelevantKeywords {
		t.Errorf("Expected post to mention database/performance/optimization, got: %s", post.Text)
	}

	// Verify image was generated
	if post.ImagePath == "" {
		t.Error("Expected image to be generated for LinkedIn post")
	}

	// Verify image file exists
	if post.ImagePath != "" {
		if _, err := os.Stat(post.ImagePath); os.IsNotExist(err) {
			t.Errorf("Image file does not exist at path: %s", post.ImagePath)
		}
	}
}

// TestEndToEndWithMultipleCommits tests handling of webhook with multiple commits
func TestEndToEndWithMultipleCommits(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Initialize test tracker
	testLinkedInTracker = &MockLinkedInTracker{
		Posts: make([]LinkedInPost, 0),
	}

	orchestrator := setupTestOrchestrator(testLinkedInTracker)
	defer teardownTestOrchestrator(orchestrator)

	// Create webhook payload with multiple commits
	payload := []byte(`{
		"repository": {
			"html_url": "https://github.com/test/repo",
			"full_name": "test/repo"
		},
		"commits": [
			{
				"id": "commit1",
				"message": "feat: add user authentication",
				"author": {"name": "Dev1"}
			},
			{
				"id": "commit2",
				"message": "fix: resolve memory leak",
				"author": {"name": "Dev2"}
			}
		]
	}`)

	secret := "test-webhook-secret"
	signature := generateHMAC(payload, secret)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", "sha256="+signature)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	orchestrator.HandleWebhook(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Wait for processing
	time.Sleep(2 * time.Second)

	// Should process the first (most recent) commit
	if len(testLinkedInTracker.Posts) == 0 {
		t.Fatal("Expected at least one LinkedIn post")
	}

	// Verify it's about authentication (the first commit)
	post := testLinkedInTracker.Posts[0]
	if !strings.Contains(strings.ToLower(post.Text), "authentication") &&
		!strings.Contains(strings.ToLower(post.Text), "auth") {
		t.Errorf("Expected post about authentication, got: %s", post.Text)
	}
}

// TestEndToEndHandlesAPIErrors tests error handling during the pipeline
func TestEndToEndHandlesAPIErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create orchestrator configured to simulate API failures
	orchestrator := setupTestOrchestratorWithErrors()
	defer teardownTestOrchestrator(orchestrator)

	payload, err := loadTestWebhook("testdata/commit_webhook.json")
	if err != nil {
		t.Fatalf("Failed to load test webhook: %v", err)
	}

	secret := "test-webhook-secret"
	signature := generateHMAC(payload, secret)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", "sha256="+signature)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	orchestrator.HandleWebhook(rr, req)

	// Webhook should still be accepted (202) even if downstream processing fails
	if rr.Code != http.StatusOK && rr.Code != http.StatusAccepted {
		t.Errorf("Expected status 200 or 202, got %d", rr.Code)
	}

	// Processing should handle errors gracefully without crashing
	time.Sleep(2 * time.Second)

	// No posts should be created due to simulated errors
	if testLinkedInTracker != nil && len(testLinkedInTracker.Posts) > 0 {
		t.Error("Expected no posts when API errors occur")
	}
}

// setupTestOrchestrator creates an orchestrator for integration testing
// This will be implemented in TB11
func setupTestOrchestrator(tracker *MockLinkedInTracker) *TestOrchestrator {
	// TODO: TB11 - Create orchestrator with mocked services
	return &TestOrchestrator{
		tracker: tracker,
	}
}

// setupTestOrchestratorWithErrors creates an orchestrator that simulates API failures
func setupTestOrchestratorWithErrors() *TestOrchestrator {
	// TODO: TB11 - Create orchestrator with error-injecting mocks
	return &TestOrchestrator{
		simulateErrors: true,
	}
}

// teardownTestOrchestrator cleans up test orchestrator resources
func teardownTestOrchestrator(orchestrator *TestOrchestrator) {
	// TODO: TB11 - Clean up resources, temp files, etc.
	if orchestrator != nil && orchestrator.tracker != nil {
		// Clean up any generated images
		for _, post := range orchestrator.tracker.Posts {
			if post.ImagePath != "" {
				os.Remove(post.ImagePath)
			}
		}
	}
}

// TestOrchestrator is a test version of the main orchestrator
// Will be properly implemented in TB11
type TestOrchestrator struct {
	tracker        *MockLinkedInTracker
	simulateErrors bool
}

// HandleWebhook processes webhook requests (to be implemented in TB11)
func (o *TestOrchestrator) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	// TODO: TB11 - Implement full orchestration:
	// 1. Validate webhook signature
	// 2. Extract commit data
	// 3. Summarize commit
	// 4. Generate image
	// 5. Post to LinkedIn
	// 6. Track in mock for testing

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "Webhook received")
}
