package services

import (
	"fmt"

	"github.com/mikelady/roxas/internal/models"
)

// OpenAIClient interface for GPT-4 API calls
type OpenAIClient interface {
	CreateChatCompletion(prompt string) (string, error)
}

// Summarizer generates LinkedIn-style summaries from git commits
type Summarizer struct {
	client OpenAIClient
}

// NewSummarizer creates a new summarizer with the given OpenAI client
func NewSummarizer(client OpenAIClient) *Summarizer {
	return &Summarizer{
		client: client,
	}
}

// Summarize transforms a git commit into a professional LinkedIn post
func (s *Summarizer) Summarize(commit models.Commit) (string, error) {
	// Validate input
	if commit.Message == "" {
		return "", fmt.Errorf("commit message is empty")
	}

	// Build prompt
	prompt := buildPromptForLinkedIn(commit)

	// Call GPT-4
	summary, err := s.client.CreateChatCompletion(prompt)
	if err != nil {
		return "", fmt.Errorf("failed to generate summary: %w", err)
	}

	return summary, nil
}

// buildPromptForLinkedIn creates a prompt that guides GPT-4 to write LinkedIn posts
func buildPromptForLinkedIn(commit models.Commit) string {
	return fmt.Sprintf(`You are a technical product marketing expert who translates software engineering work into business value for executive audiences on LinkedIn.

Transform this git commit into an engaging LinkedIn post that helps open source projects attract funding and executive attention.

Repository: %s
Commit Message: %s
Code Changes: %s
Author: %s

Create a LinkedIn post that:
1. Starts with an attention-grabbing hook (emoji + benefit statement)
2. Explains the business problem being solved
3. Describes the technical solution in accessible terms
4. Highlights measurable impact (performance, cost, reliability, security)
5. Emphasizes open source benefits (transparency, no vendor lock-in, community)
6. Length: 500-1000 characters
7. Tone: Professional but conversational, technical but accessible
8. Focus on WHY this matters to businesses and users, not just WHAT changed
9. End with 3-5 relevant hashtags

Target audience: CTOs, VPs of Engineering, investors, and budget holders.

Output ONLY the LinkedIn post text, no extra commentary.`,
		commit.RepoURL,
		commit.Message,
		commit.Diff,
		commit.Author,
	)
}
