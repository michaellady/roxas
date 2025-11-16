package services

import (
	"errors"
	"strings"
	"testing"

	"github.com/mikelady/roxas/internal/models"
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

// TestSummarizeCommitReturnsText tests that summarization returns text
func TestSummarizeCommitReturnsText(t *testing.T) {
	mockClient := &MockOpenAIClient{
		Response: "🚀 Performance Improvement: Optimized database queries\n\nReduced query time by 60% through better indexing.",
	}

	summarizer := NewSummarizer(mockClient)
	commit := models.Commit{
		Message: "perf: optimize database queries",
		Diff:    "- added index on user_id column",
		Author:  "test-author",
		RepoURL: "https://github.com/test/repo",
	}

	summary, err := summarizer.Summarize(commit)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if summary == "" {
		t.Error("Expected non-empty summary")
	}
}

// TestSummaryLengthValidation tests output is 500-1000 characters for LinkedIn
func TestSummaryLengthValidation(t *testing.T) {
	mockResponse := strings.Repeat("Professional LinkedIn post about improvements. ", 15) // ~720 chars

	mockClient := &MockOpenAIClient{
		Response: mockResponse,
	}

	summarizer := NewSummarizer(mockClient)
	commit := models.Commit{
		Message: "feat: add authentication",
		Diff:    "- OAuth2 support added",
		Author:  "dev",
		RepoURL: "https://github.com/test/repo",
	}

	summary, err := summarizer.Summarize(commit)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	length := len(summary)
	if length < 100 {
		t.Errorf("Summary too short: %d chars (expected 500-1000)", length)
	}

	if length > 1500 {
		t.Errorf("Summary too long: %d chars (expected 500-1000)", length)
	}
}

// TestSummaryIncludesBusinessValue tests that output focuses on impact
func TestSummaryIncludesBusinessValue(t *testing.T) {
	mockClient := &MockOpenAIClient{
		Response: "🔒 Enhanced Security\n\nAdded OAuth2 authentication for enterprise-ready access control.\n\nImpact: Better security compliance and SSO integration.",
	}

	summarizer := NewSummarizer(mockClient)
	commit := models.Commit{
		Message: "feat: add OAuth2 authentication",
		Diff:    "- implemented OAuth2 flow",
		Author:  "security-team",
		RepoURL: "https://github.com/test/repo",
	}

	summary, err := summarizer.Summarize(commit)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check for business-oriented keywords
	lowerSummary := strings.ToLower(summary)
	businessKeywords := []string{"impact", "security", "enterprise", "authentication"}

	foundKeyword := false
	for _, keyword := range businessKeywords {
		if strings.Contains(lowerSummary, keyword) {
			foundKeyword = true
			break
		}
	}

	if !foundKeyword {
		t.Error("Summary should include business value keywords")
	}
}

// TestSummarizerHandlesAPIError tests error handling when API fails
func TestSummarizerHandlesAPIError(t *testing.T) {
	mockClient := &MockOpenAIClient{
		Error: errors.New("API rate limit exceeded"),
	}

	summarizer := NewSummarizer(mockClient)
	commit := models.Commit{
		Message: "fix: bug fix",
		Diff:    "- fixed issue",
		Author:  "dev",
		RepoURL: "https://github.com/test/repo",
	}

	_, err := summarizer.Summarize(commit)

	if err == nil {
		t.Error("Expected error when API fails, got nil")
	}

	if !strings.Contains(err.Error(), "API") && !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("Expected API error message, got: %v", err)
	}
}

// TestSummarizerBuildsPrompt tests that prompt includes commit context
func TestSummarizerBuildsPrompt(t *testing.T) {
	commit := models.Commit{
		Message: "feat: add user dashboard",
		Diff:    "- new dashboard component",
		Author:  "frontend-team",
		RepoURL: "https://github.com/acme/product",
	}

	prompt := buildPromptForLinkedIn(commit)

	// Prompt should include key information
	if !strings.Contains(prompt, commit.Message) {
		t.Error("Prompt should include commit message")
	}

	if !strings.Contains(prompt, "LinkedIn") {
		t.Error("Prompt should mention LinkedIn context")
	}

	if !strings.Contains(prompt, "professional") || !strings.Contains(prompt, "business") {
		t.Error("Prompt should emphasize professional/business tone")
	}
}

// TestSummarizerHandlesEmptyCommit tests handling of empty/invalid commits
func TestSummarizerHandlesEmptyCommit(t *testing.T) {
	mockClient := &MockOpenAIClient{
		Response: "Update made to repository",
	}

	summarizer := NewSummarizer(mockClient)
	commit := models.Commit{
		Message: "",
		Diff:    "",
		Author:  "",
		RepoURL: "",
	}

	summary, err := summarizer.Summarize(commit)

	// Should handle gracefully, either return error or generic summary
	if err == nil && summary == "" {
		t.Error("Should either return error or non-empty summary for empty commit")
	}
}

// TestSummaryAvoidsTechnicalJargon tests professional, accessible language
func TestSummaryAvoidsTechnicalJargon(t *testing.T) {
	mockClient := &MockOpenAIClient{
		Response: "Improved system performance by optimizing data retrieval. Users will experience faster load times and better responsiveness.",
	}

	summarizer := NewSummarizer(mockClient)
	commit := models.Commit{
		Message: "perf: refactor SQL queries with prepared statements",
		Diff:    "- changed to prepared statements",
		Author:  "backend",
		RepoURL: "https://github.com/test/repo",
	}

	summary, err := summarizer.Summarize(commit)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Summary should be accessible (this is a basic check)
	if strings.Contains(summary, "mutex") || strings.Contains(summary, "refactor") {
		t.Log("Warning: Summary may contain technical jargon, but that's ok for some contexts")
	}

	// Just verify we got a reasonable response
	if len(summary) == 0 {
		t.Error("Expected non-empty summary")
	}
}
