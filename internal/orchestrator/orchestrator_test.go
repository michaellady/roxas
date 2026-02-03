package orchestrator

import (
	"errors"
	"strings"
	"testing"

	"github.com/mikelady/roxas/internal/models"
	"github.com/mikelady/roxas/internal/services"
)

// MockOpenAIClient simulates OpenAI API for testing
type MockOpenAIClient struct {
	Response string
	Error    error
}

func (m *MockOpenAIClient) CreateChatCompletion(prompt string) (string, error) {
	if m.Error != nil {
		return "", m.Error
	}
	return m.Response, nil
}

// MockDALLEClient simulates DALL-E API for testing
type MockDALLEClient struct {
	ImageURL string
	Error    error
}

func (m *MockDALLEClient) GenerateImage(prompt string) (string, error) {
	if m.Error != nil {
		return "", m.Error
	}
	return m.ImageURL, nil
}

// MockLinkedInClient simulates LinkedIn API for testing
type MockLinkedInClient struct {
	ImageURN  string
	PostID    string
	UploadErr error
	PostErr   error
}

func (m *MockLinkedInClient) UploadImage(imagePath string) (string, error) {
	if m.UploadErr != nil {
		return "", m.UploadErr
	}
	return m.ImageURN, nil
}

func (m *MockLinkedInClient) CreatePost(text string, imageURN string) (string, error) {
	if m.PostErr != nil {
		return "", m.PostErr
	}
	return m.PostID, nil
}

// TestNewOrchestrator tests that NewOrchestrator creates an orchestrator with correct services
func TestNewOrchestrator(t *testing.T) {
	summarizer := services.NewSummarizer(&MockOpenAIClient{})
	imageGen := services.NewImageGenerator(&MockDALLEClient{})
	poster := services.NewLinkedInPoster(&MockLinkedInClient{}, "test-token")

	orch := NewOrchestrator(summarizer, imageGen, poster)

	if orch == nil {
		t.Fatal("Expected non-nil orchestrator")
	}
	if orch.summarizer != summarizer {
		t.Error("Orchestrator should have the provided summarizer")
	}
	if orch.imageGenerator != imageGen {
		t.Error("Orchestrator should have the provided image generator")
	}
	if orch.linkedInPoster != poster {
		t.Error("Orchestrator should have the provided LinkedIn poster")
	}
}

// TestProcessCommitSuccess tests the full pipeline with successful operations
func TestProcessCommitSuccess(t *testing.T) {
	mockOpenAI := &MockOpenAIClient{
		Response: "🚀 Great performance improvements! #tech #opensource",
	}
	mockDALLE := &MockDALLEClient{
		ImageURL: "https://fake.openai.com/images/test.png",
	}
	mockLinkedIn := &MockLinkedInClient{
		ImageURN: "urn:li:digitalmediaAsset:123456",
		PostID:   "urn:li:share:987654321",
	}

	summarizer := services.NewSummarizer(mockOpenAI)
	imageGen := services.NewImageGenerator(mockDALLE)
	poster := services.NewLinkedInPoster(mockLinkedIn, "test-token")

	orch := NewOrchestrator(summarizer, imageGen, poster)

	commit := models.Commit{
		Message: "perf: optimize database queries",
		Diff:    "- added index on user_id",
		Author:  "test-author",
		RepoURL: "https://github.com/test/repo",
	}

	postURL, err := orch.ProcessCommit(commit)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if postURL == "" {
		t.Error("Expected non-empty post URL")
	}
	if !strings.Contains(postURL, "linkedin.com") {
		t.Errorf("Expected LinkedIn URL, got %s", postURL)
	}
}

// TestProcessCommitSummarizeError tests error handling when summarization fails
func TestProcessCommitSummarizeError(t *testing.T) {
	mockOpenAI := &MockOpenAIClient{
		Error: errors.New("OpenAI API rate limit exceeded"),
	}
	mockDALLE := &MockDALLEClient{
		ImageURL: "https://fake.openai.com/images/test.png",
	}
	mockLinkedIn := &MockLinkedInClient{
		ImageURN: "urn:li:digitalmediaAsset:123456",
		PostID:   "urn:li:share:987654321",
	}

	summarizer := services.NewSummarizer(mockOpenAI)
	imageGen := services.NewImageGenerator(mockDALLE)
	poster := services.NewLinkedInPoster(mockLinkedIn, "test-token")

	orch := NewOrchestrator(summarizer, imageGen, poster)

	commit := models.Commit{
		Message: "fix: bug fix",
		Diff:    "- fixed issue",
		Author:  "dev",
		RepoURL: "https://github.com/test/repo",
	}

	_, err := orch.ProcessCommit(commit)

	if err == nil {
		t.Fatal("Expected error when summarization fails")
	}
	if !strings.Contains(err.Error(), "summarize") {
		t.Errorf("Error should mention summarize failure, got: %v", err)
	}
}

// TestProcessCommitImageGenerationError tests error handling when image generation fails
func TestProcessCommitImageGenerationError(t *testing.T) {
	mockOpenAI := &MockOpenAIClient{
		Response: "🚀 Great update! #tech",
	}
	mockDALLE := &MockDALLEClient{
		Error: errors.New("DALL-E API error"),
	}
	mockLinkedIn := &MockLinkedInClient{
		ImageURN: "urn:li:digitalmediaAsset:123456",
		PostID:   "urn:li:share:987654321",
	}

	summarizer := services.NewSummarizer(mockOpenAI)
	imageGen := services.NewImageGenerator(mockDALLE)
	poster := services.NewLinkedInPoster(mockLinkedIn, "test-token")

	orch := NewOrchestrator(summarizer, imageGen, poster)

	commit := models.Commit{
		Message: "feat: add feature",
		Diff:    "- new feature",
		Author:  "dev",
		RepoURL: "https://github.com/test/repo",
	}

	_, err := orch.ProcessCommit(commit)

	if err == nil {
		t.Fatal("Expected error when image generation fails")
	}
	if !strings.Contains(err.Error(), "image") {
		t.Errorf("Error should mention image failure, got: %v", err)
	}
}

// TestProcessCommitLinkedInPostError tests error handling when LinkedIn posting fails
func TestProcessCommitLinkedInPostError(t *testing.T) {
	mockOpenAI := &MockOpenAIClient{
		Response: "🚀 Great update! #tech",
	}
	mockDALLE := &MockDALLEClient{
		ImageURL: "https://fake.openai.com/images/test.png",
	}
	mockLinkedIn := &MockLinkedInClient{
		ImageURN: "urn:li:digitalmediaAsset:123456",
		PostErr:  errors.New("LinkedIn API error: unauthorized"),
	}

	summarizer := services.NewSummarizer(mockOpenAI)
	imageGen := services.NewImageGenerator(mockDALLE)
	poster := services.NewLinkedInPoster(mockLinkedIn, "test-token")

	orch := NewOrchestrator(summarizer, imageGen, poster)

	commit := models.Commit{
		Message: "docs: update readme",
		Diff:    "- updated docs",
		Author:  "dev",
		RepoURL: "https://github.com/test/repo",
	}

	_, err := orch.ProcessCommit(commit)

	if err == nil {
		t.Fatal("Expected error when LinkedIn posting fails")
	}
	if !strings.Contains(err.Error(), "LinkedIn") {
		t.Errorf("Error should mention LinkedIn failure, got: %v", err)
	}
}

// TestProcessCommitLinkedInImageUploadError tests error handling when image upload fails
func TestProcessCommitLinkedInImageUploadError(t *testing.T) {
	mockOpenAI := &MockOpenAIClient{
		Response: "🚀 Great update! #tech",
	}
	mockDALLE := &MockDALLEClient{
		ImageURL: "https://fake.openai.com/images/test.png",
	}
	mockLinkedIn := &MockLinkedInClient{
		UploadErr: errors.New("LinkedIn image upload failed"),
	}

	summarizer := services.NewSummarizer(mockOpenAI)
	imageGen := services.NewImageGenerator(mockDALLE)
	poster := services.NewLinkedInPoster(mockLinkedIn, "test-token")

	orch := NewOrchestrator(summarizer, imageGen, poster)

	commit := models.Commit{
		Message: "feat: new feature",
		Diff:    "- added feature",
		Author:  "dev",
		RepoURL: "https://github.com/test/repo",
	}

	_, err := orch.ProcessCommit(commit)

	if err == nil {
		t.Fatal("Expected error when image upload fails")
	}
	if !strings.Contains(err.Error(), "LinkedIn") {
		t.Errorf("Error should mention LinkedIn failure, got: %v", err)
	}
}

// TestProcessCommitEmptyMessage tests handling commits with empty messages
func TestProcessCommitEmptyMessage(t *testing.T) {
	mockOpenAI := &MockOpenAIClient{
		Response: "Update to the repository",
	}
	mockDALLE := &MockDALLEClient{
		ImageURL: "https://fake.openai.com/images/test.png",
	}
	mockLinkedIn := &MockLinkedInClient{
		ImageURN: "urn:li:digitalmediaAsset:123456",
		PostID:   "urn:li:share:987654321",
	}

	summarizer := services.NewSummarizer(mockOpenAI)
	imageGen := services.NewImageGenerator(mockDALLE)
	poster := services.NewLinkedInPoster(mockLinkedIn, "test-token")

	orch := NewOrchestrator(summarizer, imageGen, poster)

	commit := models.Commit{
		Message: "",
		Diff:    "- some changes",
		Author:  "dev",
		RepoURL: "https://github.com/test/repo",
	}

	_, err := orch.ProcessCommit(commit)

	// Should fail because empty commit message is rejected by summarizer
	if err == nil {
		t.Error("Expected error for empty commit message")
	}
}

// TestProcessCommitReturnsCorrectURL tests that the returned URL is properly formatted
func TestProcessCommitReturnsCorrectURL(t *testing.T) {
	postID := "urn:li:share:7654321098765432100"
	mockOpenAI := &MockOpenAIClient{
		Response: "🚀 Amazing work! #tech #opensource",
	}
	mockDALLE := &MockDALLEClient{
		ImageURL: "https://fake.openai.com/images/test.png",
	}
	mockLinkedIn := &MockLinkedInClient{
		ImageURN: "urn:li:digitalmediaAsset:123456",
		PostID:   postID,
	}

	summarizer := services.NewSummarizer(mockOpenAI)
	imageGen := services.NewImageGenerator(mockDALLE)
	poster := services.NewLinkedInPoster(mockLinkedIn, "test-token")

	orch := NewOrchestrator(summarizer, imageGen, poster)

	commit := models.Commit{
		Message: "feat: add authentication",
		Diff:    "- OAuth2 implementation",
		Author:  "security-team",
		RepoURL: "https://github.com/test/repo",
	}

	postURL, err := orch.ProcessCommit(commit)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	expectedURL := "https://www.linkedin.com/feed/update/" + postID
	if postURL != expectedURL {
		t.Errorf("Expected URL %s, got %s", expectedURL, postURL)
	}
}
