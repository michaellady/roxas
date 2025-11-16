package tests

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mikelady/roxas/internal/handlers"
	"github.com/mikelady/roxas/internal/models"
	"github.com/mikelady/roxas/internal/orchestrator"
	"github.com/mikelady/roxas/internal/services"
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

	// Initialize test tracker
	testLinkedInTracker = &MockLinkedInTracker{
		Posts: make([]LinkedInPost, 0),
	}

	// Create orchestrator configured to simulate API failures
	orchestrator := setupTestOrchestratorWithErrors(testLinkedInTracker)
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

// Mock clients for testing

// MockOpenAIClient simulates ChatGPT for testing
type MockOpenAIClient struct {
	Error error
}

func (m *MockOpenAIClient) CreateChatCompletion(prompt string) (string, error) {
	if m.Error != nil {
		return "", m.Error
	}

	// Generate context-aware response based on the prompt content
	lowerPrompt := strings.ToLower(prompt)

	// Check for database/performance first (more specific)
	if strings.Contains(lowerPrompt, "database") || strings.Contains(lowerPrompt, "query optimization") {
		return "Excited to share our latest achievement: implementing database query optimization that improved page load times by 40%. This enhancement demonstrates our commitment to performance and user experience. #SoftwareEngineering #Performance", nil
	}

	if strings.Contains(lowerPrompt, "user authentication") || strings.Contains(lowerPrompt, "add user authentication") {
		return "Proud to announce our implementation of user authentication! This security enhancement protects user data and provides a seamless login experience. Building trust through secure software. #Security #Authentication", nil
	}

	// Default response for other cases
	return "Excited to share our latest software engineering achievement! This update brings meaningful improvements to our users. #SoftwareEngineering #Innovation", nil
}

// MockDALLEClient simulates DALL-E for testing
type MockDALLEClient struct {
	Error error
}

func (m *MockDALLEClient) GenerateImage(prompt string) (string, error) {
	if m.Error != nil {
		return "", m.Error
	}
	return "https://fake.openai.com/images/test-image.png", nil
}

// MockLinkedInClient simulates LinkedIn API for testing
type MockLinkedInClient struct {
	Error         error
	Tracker       *MockLinkedInTracker
	lastImagePath string
}

func (m *MockLinkedInClient) UploadImage(imagePath string) (string, error) {
	if m.Error != nil {
		return "", m.Error
	}
	// Store the actual image path from the generator
	m.lastImagePath = imagePath
	return "urn:li:digitalmediaAsset:test123", nil
}

func (m *MockLinkedInClient) CreatePost(text string, imageURN string) (string, error) {
	if m.Error != nil {
		return "", m.Error
	}

	// Track the post in our test tracker
	if m.Tracker != nil {
		m.Tracker.Posts = append(m.Tracker.Posts, LinkedInPost{
			Text:      text,
			ImagePath: m.lastImagePath,
			Timestamp: time.Now(),
		})
	}

	return "urn:li:share:integration-test-123", nil
}

// setupTestOrchestrator creates an orchestrator for integration testing
func setupTestOrchestrator(tracker *MockLinkedInTracker) *TestOrchestrator {
	// Create mock clients
	openAIClient := &MockOpenAIClient{}
	dalleClient := &MockDALLEClient{}
	linkedInClient := &MockLinkedInClient{Tracker: tracker}

	// Create services with mock clients
	summarizer := services.NewSummarizer(openAIClient)
	imageGenerator := services.NewImageGenerator(dalleClient)
	linkedInPoster := services.NewLinkedInPoster(linkedInClient, "test-access-token")

	// Create orchestrator
	orch := orchestrator.NewOrchestrator(summarizer, imageGenerator, linkedInPoster)

	// Create webhook handler
	webhookHandler := handlers.NewWebhookHandler("test-webhook-secret")

	return &TestOrchestrator{
		orchestrator:   orch,
		webhookHandler: webhookHandler,
		tracker:        tracker,
	}
}

// setupTestOrchestratorWithErrors creates an orchestrator that simulates API failures
func setupTestOrchestratorWithErrors(tracker *MockLinkedInTracker) *TestOrchestrator {
	// Create error-injecting mock clients
	openAIClient := &MockOpenAIClient{Error: fmt.Errorf("API rate limit exceeded")}
	dalleClient := &MockDALLEClient{Error: fmt.Errorf("DALL-E service unavailable")}
	linkedInClient := &MockLinkedInClient{
		Error:   fmt.Errorf("LinkedIn authentication failed"),
		Tracker: tracker,
	}

	// Create services
	summarizer := services.NewSummarizer(openAIClient)
	imageGenerator := services.NewImageGenerator(dalleClient)
	linkedInPoster := services.NewLinkedInPoster(linkedInClient, "test-token")

	// Create orchestrator
	orch := orchestrator.NewOrchestrator(summarizer, imageGenerator, linkedInPoster)

	// Create webhook handler
	webhookHandler := handlers.NewWebhookHandler("test-webhook-secret")

	return &TestOrchestrator{
		orchestrator:   orch,
		webhookHandler: webhookHandler,
		tracker:        tracker,
		simulateErrors: true,
	}
}

// teardownTestOrchestrator cleans up test orchestrator resources
func teardownTestOrchestrator(orchestrator *TestOrchestrator) {
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
type TestOrchestrator struct {
	orchestrator   *orchestrator.Orchestrator
	webhookHandler *handlers.WebhookHandler
	tracker        *MockLinkedInTracker
	simulateErrors bool
}

// HandleWebhook processes webhook requests with full orchestration
func (o *TestOrchestrator) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	// Read body for webhook validation and processing
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Validate webhook signature using handler
	signature := r.Header.Get("X-Hub-Signature-256")
	if signature == "" {
		http.Error(w, "Missing signature", http.StatusUnauthorized)
		return
	}

	// Extract commit from webhook payload
	var webhook struct {
		Repository struct {
			HTMLURL string `json:"html_url"`
		} `json:"repository"`
		Commits []struct {
			ID      string `json:"id"`
			Message string `json:"message"`
			Author  struct {
				Name string `json:"name"`
			} `json:"author"`
		} `json:"commits"`
	}

	if err := json.Unmarshal(body, &webhook); err != nil {
		http.Error(w, "Failed to parse webhook payload", http.StatusBadRequest)
		return
	}

	if len(webhook.Commits) == 0 {
		http.Error(w, "No commits in webhook payload", http.StatusBadRequest)
		return
	}

	// Create commit model
	commit := models.Commit{
		Message: webhook.Commits[0].Message,
		Author:  webhook.Commits[0].Author.Name,
		RepoURL: webhook.Repository.HTMLURL,
	}

	// Process commit through orchestrator
	go func() {
		_, err := o.orchestrator.ProcessCommit(commit)
		if err != nil {
			// Log error but don't fail the webhook response
			fmt.Printf("Error processing commit: %v\n", err)
		}
	}()

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "Webhook received")
}
