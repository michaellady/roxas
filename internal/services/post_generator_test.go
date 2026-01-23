package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// TB16: Post Generation Service Tests (TDD - RED)
// TB17: Implementation to make tests GREEN
// =============================================================================

// =============================================================================
// Mock Chat Client for Testing
// =============================================================================

// MockChatClient records prompts and returns canned responses
type MockChatClient struct {
	Response      string
	Error         error
	RecordedPrompt string
}

func (m *MockChatClient) CreateChatCompletion(prompt string) (string, error) {
	m.RecordedPrompt = prompt
	if m.Error != nil {
		return "", m.Error
	}
	return m.Response, nil
}

// =============================================================================
// Test: Generate LinkedIn Post - Professional Content
// =============================================================================

func TestPostGenerator_LinkedIn_ProfessionalContent(t *testing.T) {
	// LinkedIn posts should be professional, longer-form content

	mockClient := &MockChatClient{
		Response: `🚀 Excited to share our latest engineering achievement!

We've just shipped a major performance improvement that reduces API response times by 40%. This optimization directly impacts user experience and sets the foundation for future scalability.

Key highlights:
• Optimized database query patterns
• Implemented intelligent caching
• Reduced server resource consumption

Building great software is a team effort. Grateful for the collaboration! #SoftwareEngineering #Performance #Tech`,
	}

	generator := NewPostGenerator(mockClient)

	commit := &Commit{
		ID:           "commit-123",
		RepositoryID: "repo-456",
		CommitSHA:    "abc123def456",
		GitHubURL:    "https://github.com/test/repo/commit/abc123",
		Message:      "perf: optimize database queries for 40% faster response",
		Author:       "Jane Developer",
		Timestamp:    time.Now(),
	}

	ctx := context.Background()
	post, err := generator.Generate(ctx, PlatformLinkedIn, commit)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if post == nil {
		t.Fatal("Expected post, got nil")
	}

	if post.Platform != PlatformLinkedIn {
		t.Errorf("Expected platform %s, got %s", PlatformLinkedIn, post.Platform)
	}

	// LinkedIn posts should be substantial (500+ chars for professional content)
	if len(post.Content) < 200 {
		t.Errorf("LinkedIn post too short (%d chars), expected professional content", len(post.Content))
	}

	// Verify prompt included commit context
	if !strings.Contains(mockClient.RecordedPrompt, commit.Message) {
		t.Error("Prompt should include commit message")
	}

	if !strings.Contains(mockClient.RecordedPrompt, "LinkedIn") || !strings.Contains(mockClient.RecordedPrompt, "professional") {
		t.Error("Prompt should specify LinkedIn professional context")
	}
}

// =============================================================================
// Test: Generate Twitter Post - Concise (<=280 chars)
// =============================================================================

func TestPostGenerator_Twitter_ConciseContent(t *testing.T) {
	// Twitter posts must be <=280 characters

	mockClient := &MockChatClient{
		Response: "🚀 Just shipped: 40% faster API responses! Database optimizations FTW. #coding #performance",
	}

	generator := NewPostGenerator(mockClient)

	commit := &Commit{
		ID:           "commit-123",
		RepositoryID: "repo-456",
		CommitSHA:    "abc123def456",
		GitHubURL:    "https://github.com/test/repo/commit/abc123",
		Message:      "perf: optimize database queries",
		Author:       "Jane Developer",
		Timestamp:    time.Now(),
	}

	ctx := context.Background()
	post, err := generator.Generate(ctx, PlatformTwitter, commit)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if post == nil {
		t.Fatal("Expected post, got nil")
	}

	if post.Platform != PlatformTwitter {
		t.Errorf("Expected platform %s, got %s", PlatformTwitter, post.Platform)
	}

	// Twitter strict limit: 280 characters
	if len(post.Content) > 280 {
		t.Errorf("Twitter post too long: %d chars (max 280)", len(post.Content))
	}

	// Verify prompt specified Twitter constraints
	if !strings.Contains(mockClient.RecordedPrompt, "280") || !strings.Contains(mockClient.RecordedPrompt, "Twitter") {
		t.Error("Prompt should specify Twitter 280 character limit")
	}
}

// =============================================================================
// Test: Generate Instagram Post - Contains Hashtags
// =============================================================================

func TestPostGenerator_Instagram_ContainsHashtags(t *testing.T) {
	// Instagram posts should contain relevant hashtags

	mockClient := &MockChatClient{
		Response: `✨ Code optimization complete!

Faster responses = happier users. Another day, another improvement to the codebase.

#coding #developer #softwareengineering #tech #programming #webdev #devlife #coder`,
	}

	generator := NewPostGenerator(mockClient)

	commit := &Commit{
		ID:           "commit-123",
		RepositoryID: "repo-456",
		CommitSHA:    "abc123def456",
		GitHubURL:    "https://github.com/test/repo/commit/abc123",
		Message:      "perf: optimize database queries",
		Author:       "Jane Developer",
		Timestamp:    time.Now(),
	}

	ctx := context.Background()
	post, err := generator.Generate(ctx, PlatformInstagram, commit)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if post == nil {
		t.Fatal("Expected post, got nil")
	}

	if post.Platform != PlatformInstagram {
		t.Errorf("Expected platform %s, got %s", PlatformInstagram, post.Platform)
	}

	// Instagram posts should contain hashtags
	if !strings.Contains(post.Content, "#") {
		t.Error("Instagram post should contain hashtags")
	}

	// Count hashtags (should have multiple)
	hashtagCount := strings.Count(post.Content, "#")
	if hashtagCount < 3 {
		t.Errorf("Instagram post should have multiple hashtags, got %d", hashtagCount)
	}

	// Verify prompt specified Instagram context
	if !strings.Contains(mockClient.RecordedPrompt, "Instagram") || !strings.Contains(mockClient.RecordedPrompt, "hashtag") {
		t.Error("Prompt should specify Instagram hashtag requirements")
	}
}

// =============================================================================
// Test: Generate YouTube Description - Longer Form
// =============================================================================

func TestPostGenerator_YouTube_LongerDescription(t *testing.T) {
	// YouTube descriptions can be longer and more detailed

	mockClient := &MockChatClient{
		Response: `In this commit, we tackle database performance optimization!

🎯 What we changed:
- Optimized SQL query patterns
- Added strategic indexes
- Implemented query result caching

📊 Results:
- 40% faster API response times
- Reduced database load
- Better user experience

🔗 Links:
GitHub: https://github.com/test/repo

#programming #database #optimization #coding #developer`,
	}

	generator := NewPostGenerator(mockClient)

	commit := &Commit{
		ID:           "commit-123",
		RepositoryID: "repo-456",
		CommitSHA:    "abc123def456",
		GitHubURL:    "https://github.com/test/repo/commit/abc123",
		Message:      "perf: optimize database queries for 40% faster response",
		Author:       "Jane Developer",
		Timestamp:    time.Now(),
	}

	ctx := context.Background()
	post, err := generator.Generate(ctx, PlatformYouTube, commit)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if post == nil {
		t.Fatal("Expected post, got nil")
	}

	if post.Platform != PlatformYouTube {
		t.Errorf("Expected platform %s, got %s", PlatformYouTube, post.Platform)
	}

	// YouTube descriptions can be longer
	if len(post.Content) < 100 {
		t.Errorf("YouTube description too short (%d chars)", len(post.Content))
	}

	// Verify prompt specified YouTube context
	if !strings.Contains(mockClient.RecordedPrompt, "YouTube") {
		t.Error("Prompt should specify YouTube context")
	}
}

// =============================================================================
// Test: Different Commits Produce Different Content
// =============================================================================

func TestPostGenerator_DifferentCommits_DifferentContent(t *testing.T) {
	// Different commits should produce different prompts/content

	var recordedPrompts []string

	mockClient := &MockChatClient{}

	generator := NewPostGenerator(mockClient)
	ctx := context.Background()

	// First commit - performance optimization
	commit1 := &Commit{
		ID:           "commit-1",
		RepositoryID: "repo-456",
		CommitSHA:    "sha111111",
		GitHubURL:    "https://github.com/test/repo/commit/sha1",
		Message:      "perf: optimize database queries",
		Author:       "Alice",
		Timestamp:    time.Now(),
	}

	mockClient.Response = "Performance improvement post content"
	_, err := generator.Generate(ctx, PlatformLinkedIn, commit1)
	if err != nil {
		t.Fatalf("Expected no error for commit1, got: %v", err)
	}
	recordedPrompts = append(recordedPrompts, mockClient.RecordedPrompt)

	// Second commit - bug fix (different type of change)
	commit2 := &Commit{
		ID:           "commit-2",
		RepositoryID: "repo-456",
		CommitSHA:    "sha222222",
		GitHubURL:    "https://github.com/test/repo/commit/sha2",
		Message:      "fix: resolve authentication bypass vulnerability",
		Author:       "Bob",
		Timestamp:    time.Now(),
	}

	mockClient.Response = "Security fix post content"
	_, err = generator.Generate(ctx, PlatformLinkedIn, commit2)
	if err != nil {
		t.Fatalf("Expected no error for commit2, got: %v", err)
	}
	recordedPrompts = append(recordedPrompts, mockClient.RecordedPrompt)

	// Prompts should be different (contain different commit info)
	if recordedPrompts[0] == recordedPrompts[1] {
		t.Error("Different commits should produce different prompts")
	}

	// Each prompt should contain its respective commit message
	if !strings.Contains(recordedPrompts[0], "optimize database") {
		t.Error("First prompt should contain first commit message")
	}

	if !strings.Contains(recordedPrompts[1], "authentication bypass") {
		t.Error("Second prompt should contain second commit message")
	}
}

// =============================================================================
// Test: OpenAI Error Bubbles Up
// =============================================================================

func TestPostGenerator_OpenAIError_BubblesUp(t *testing.T) {
	// Errors from OpenAI should bubble up without being wrapped generically

	apiError := errors.New("API rate limit exceeded: too many requests")

	mockClient := &MockChatClient{
		Error: apiError,
	}

	generator := NewPostGenerator(mockClient)

	commit := &Commit{
		ID:           "commit-123",
		RepositoryID: "repo-456",
		CommitSHA:    "abc123def456",
		GitHubURL:    "https://github.com/test/repo/commit/abc123",
		Message:      "feat: add new feature",
		Author:       "Jane Developer",
		Timestamp:    time.Now(),
	}

	ctx := context.Background()
	_, err := generator.Generate(ctx, PlatformLinkedIn, commit)

	if err == nil {
		t.Fatal("Expected error when OpenAI fails, got nil")
	}

	// Error should contain the original error detail (not wrapped generically)
	if !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("Error should contain original API error detail, got: %v", err)
	}
}

// =============================================================================
// Test: Invalid Platform Returns Error
// =============================================================================

func TestPostGenerator_InvalidPlatform_ReturnsError(t *testing.T) {
	mockClient := &MockChatClient{
		Response: "test",
	}

	generator := NewPostGenerator(mockClient)

	commit := &Commit{
		ID:           "commit-123",
		RepositoryID: "repo-456",
		CommitSHA:    "abc123def456",
		GitHubURL:    "https://github.com/test/repo/commit/abc123",
		Message:      "feat: add new feature",
		Author:       "Jane Developer",
		Timestamp:    time.Now(),
	}

	ctx := context.Background()
	_, err := generator.Generate(ctx, "invalid-platform", commit)

	if err == nil {
		t.Fatal("Expected error for invalid platform, got nil")
	}

	if !strings.Contains(err.Error(), "unsupported platform") {
		t.Errorf("Expected 'unsupported platform' error, got: %v", err)
	}
}

// =============================================================================
// Test: Bluesky Prompt Focuses on Commit Changes (TB-hq-nkc2d - TDD RED)
// =============================================================================

func TestPostGenerator_Bluesky_PromptContainsCommitEnablesGuidance(t *testing.T) {
	// Bluesky prompt should guide AI to focus on what THIS commit enables/fixes

	mockClient := &MockChatClient{
		Response: "Bluesky support is live! Connect your account now.",
	}

	generator := NewPostGenerator(mockClient)

	commit := &Commit{
		ID:           "commit-123",
		RepositoryID: "repo-456",
		CommitSHA:    "abc123def456",
		GitHubURL:    "https://github.com/test/repo/commit/abc123",
		Message:      "feat: add Bluesky OAuth integration",
		Author:       "Jane Developer",
		Timestamp:    time.Now(),
	}

	ctx := context.Background()
	_, err := generator.Generate(ctx, PlatformBluesky, commit)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	prompt := mockClient.RecordedPrompt

	// Prompt should instruct AI to focus on what THIS commit enables
	if !strings.Contains(strings.ToLower(prompt), "what this commit enables") &&
		!strings.Contains(strings.ToLower(prompt), "focus on what") {
		t.Error("Bluesky prompt should contain guidance to focus on what the commit enables")
	}
}

func TestPostGenerator_Bluesky_PromptNoGenericPhrasing(t *testing.T) {
	// Bluesky prompt should NOT use generic "software development update" phrasing

	mockClient := &MockChatClient{
		Response: "Added webhook validation for Bluesky posts.",
	}

	generator := NewPostGenerator(mockClient)

	commit := &Commit{
		ID:           "commit-123",
		RepositoryID: "repo-456",
		CommitSHA:    "abc123def456",
		GitHubURL:    "https://github.com/test/repo/commit/abc123",
		Message:      "feat: add webhook handler",
		Author:       "Jane Developer",
		Timestamp:    time.Now(),
	}

	ctx := context.Background()
	_, err := generator.Generate(ctx, PlatformBluesky, commit)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	prompt := mockClient.RecordedPrompt

	// Bluesky prompt should NOT contain generic phrasing that other platforms use
	if strings.Contains(strings.ToLower(prompt), "software development update") {
		t.Error("Bluesky prompt should NOT use generic 'software development update' phrasing")
	}

	// Should instruct not to explain what the app is
	if !strings.Contains(strings.ToLower(prompt), "don't explain what the app is") &&
		!strings.Contains(strings.ToLower(prompt), "assume readers follow") {
		t.Error("Bluesky prompt should instruct not to re-explain what the app is")
	}
}

func TestPostGenerator_Bluesky_PromptHasGoodBadExamples(t *testing.T) {
	// Bluesky prompt should include examples of good vs bad post format

	mockClient := &MockChatClient{
		Response: "Now supports Bluesky! Auto-post your dev updates.",
	}

	generator := NewPostGenerator(mockClient)

	commit := &Commit{
		ID:           "commit-123",
		RepositoryID: "repo-456",
		CommitSHA:    "abc123def456",
		GitHubURL:    "https://github.com/test/repo/commit/abc123",
		Message:      "feat: add Bluesky posting support",
		Author:       "Jane Developer",
		Timestamp:    time.Now(),
	}

	ctx := context.Background()
	_, err := generator.Generate(ctx, PlatformBluesky, commit)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	prompt := mockClient.RecordedPrompt

	// Prompt should contain BAD/GOOD examples to guide the AI
	hasBadExample := strings.Contains(strings.ToUpper(prompt), "BAD:") ||
		strings.Contains(strings.ToUpper(prompt), "BAD EXAMPLE")
	hasGoodExample := strings.Contains(strings.ToUpper(prompt), "GOOD:") ||
		strings.Contains(strings.ToUpper(prompt), "GOOD EXAMPLE")

	if !hasBadExample || !hasGoodExample {
		t.Error("Bluesky prompt should include BAD and GOOD examples to guide post style")
	}
}

func TestPostGenerator_Bluesky_PromptLeadWithActionOutcome(t *testing.T) {
	// Bluesky prompt should instruct to lead with action/outcome

	mockClient := &MockChatClient{
		Response: "Fixed auth timeout. Sessions now persist properly.",
	}

	generator := NewPostGenerator(mockClient)

	commit := &Commit{
		ID:           "commit-123",
		RepositoryID: "repo-456",
		CommitSHA:    "abc123def456",
		GitHubURL:    "https://github.com/test/repo/commit/abc123",
		Message:      "fix: resolve session timeout issue",
		Author:       "Jane Developer",
		Timestamp:    time.Now(),
	}

	ctx := context.Background()
	_, err := generator.Generate(ctx, PlatformBluesky, commit)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	prompt := mockClient.RecordedPrompt

	// Should instruct to lead with action words
	hasLeadWithAction := strings.Contains(strings.ToLower(prompt), "lead with") ||
		strings.Contains(strings.ToLower(prompt), "start with the action") ||
		(strings.Contains(strings.ToLower(prompt), "added") &&
			strings.Contains(strings.ToLower(prompt), "fixed") &&
			strings.Contains(strings.ToLower(prompt), "now supports"))

	if !hasLeadWithAction {
		t.Error("Bluesky prompt should instruct to lead with action/outcome (Added X, Fixed Y, Now supports Z)")
	}

	// Should mention being specific about functionality
	if !strings.Contains(strings.ToLower(prompt), "specific") {
		t.Error("Bluesky prompt should instruct to be specific about functionality")
	}
}

// =============================================================================
// Test: Prompt Includes Commit Metadata
// =============================================================================

func TestPostGenerator_PromptIncludesCommitMetadata(t *testing.T) {
	mockClient := &MockChatClient{
		Response: "Test post content",
	}

	generator := NewPostGenerator(mockClient)

	commit := &Commit{
		ID:           "commit-123",
		RepositoryID: "repo-456",
		CommitSHA:    "abc123def456",
		GitHubURL:    "https://github.com/acme/awesome-project/commit/abc123",
		Message:      "feat: implement OAuth2 authentication flow",
		Author:       "Security Team",
		Timestamp:    time.Now(),
	}

	ctx := context.Background()
	_, err := generator.Generate(ctx, PlatformLinkedIn, commit)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	prompt := mockClient.RecordedPrompt

	// Prompt should include key commit metadata
	if !strings.Contains(prompt, commit.Message) {
		t.Error("Prompt should include commit message")
	}

	if !strings.Contains(prompt, commit.Author) {
		t.Error("Prompt should include commit author")
	}

	// Should reference the repository (from URL)
	if !strings.Contains(prompt, "acme") || !strings.Contains(prompt, "awesome-project") {
		t.Error("Prompt should include repository information")
	}
}
