package services

import (
	"context"
	"fmt"
	"strings"
)

// =============================================================================
// Post Generator Service Implementation (TB17)
// =============================================================================

// Platform constants for social media targets
// Note: PlatformBluesky is defined in credential_store.go
const (
	PlatformLinkedIn  = "linkedin"
	PlatformTwitter   = "twitter"
	PlatformInstagram = "instagram"
	PlatformYouTube   = "youtube"
)

// GeneratedPost represents a generated social media post
type GeneratedPost struct {
	Platform string
	Content  string
	CommitID string
}

// PostGeneratorService defines the interface for generating social media posts
type PostGeneratorService interface {
	// Generate creates a social media post for the given platform and commit
	Generate(ctx context.Context, platform string, commit *Commit) (*GeneratedPost, error)
}

// ChatClient interface for OpenAI-like chat completions
type ChatClient interface {
	CreateChatCompletion(prompt string) (string, error)
}

// PostGenerator generates social media posts using an AI chat client
type PostGenerator struct {
	client ChatClient
}

// NewPostGenerator creates a new post generator with the given chat client
func NewPostGenerator(client ChatClient) *PostGenerator {
	return &PostGenerator{
		client: client,
	}
}

// platformConfig holds platform-specific settings
type platformConfig struct {
	Name       string
	MaxLength  int    // 0 = no limit
	Tone       string // Description of desired tone
	HashtagReq bool   // Whether hashtags are required
}

// Platform configurations
var platformConfigs = map[string]platformConfig{
	PlatformLinkedIn: {
		Name:       "LinkedIn",
		MaxLength:  0, // No strict limit, but aim for 500-1500 chars
		Tone:       "professional, business-focused, highlighting impact and value",
		HashtagReq: false,
	},
	PlatformTwitter: {
		Name:       "Twitter",
		MaxLength:  280,
		Tone:       "concise, engaging, casual but informative",
		HashtagReq: false,
	},
	PlatformInstagram: {
		Name:       "Instagram",
		MaxLength:  0, // Instagram allows 2200 chars
		Tone:       "visual, engaging, lifestyle-oriented",
		HashtagReq: true,
	},
	PlatformYouTube: {
		Name:       "YouTube",
		MaxLength:  0, // YouTube descriptions can be up to 5000 chars
		Tone:       "informative, detailed, with sections and links",
		HashtagReq: false,
	},
	PlatformBluesky: {
		Name:       "Bluesky",
		MaxLength:  300,
		Tone:       "concise, engaging, focused on what was built/shipped",
		HashtagReq: false,
	},
}

// Generate creates a social media post for the given platform and commit
func (p *PostGenerator) Generate(ctx context.Context, platform string, commit *Commit) (*GeneratedPost, error) {
	// Validate platform
	config, ok := platformConfigs[platform]
	if !ok {
		return nil, fmt.Errorf("unsupported platform: %s", platform)
	}

	// Build platform-specific prompt
	prompt := buildPrompt(config, commit)

	// Call AI to generate content
	content, err := p.client.CreateChatCompletion(prompt)
	if err != nil {
		// Bubble up error without wrapping generically (callers need detail)
		return nil, err
	}

	// Enforce platform constraints
	content = enforceConstraints(content, config)

	return &GeneratedPost{
		Platform: platform,
		Content:  content,
		CommitID: commit.ID,
	}, nil
}

// buildPrompt creates a platform-specific prompt for the AI
func buildPrompt(config platformConfig, commit *Commit) string {
	// Extract repo info from GitHub URL
	repoInfo := extractRepoInfo(commit.GitHubURL)

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Generate a %s post about this software development update.\n\n", config.Name))

	sb.WriteString("Commit Information:\n")
	sb.WriteString(fmt.Sprintf("- Message: %s\n", commit.Message))
	sb.WriteString(fmt.Sprintf("- Author: %s\n", commit.Author))
	if repoInfo != "" {
		sb.WriteString(fmt.Sprintf("- Repository: %s\n", repoInfo))
	}

	sb.WriteString(fmt.Sprintf("\nTone: %s\n", config.Tone))

	// Platform-specific instructions
	switch config.Name {
	case "LinkedIn":
		sb.WriteString("\nRequirements for LinkedIn:\n")
		sb.WriteString("- Write in a professional, business-focused tone\n")
		sb.WriteString("- Highlight the impact and value of this change\n")
		sb.WriteString("- Make it engaging for a professional audience\n")
		sb.WriteString("- Include relevant hashtags at the end if appropriate\n")
		sb.WriteString("- Aim for 500-1000 characters\n")
	case "Twitter":
		sb.WriteString("\nRequirements for Twitter:\n")
		sb.WriteString("- MUST be 280 characters or less (this is critical!)\n")
		sb.WriteString("- Be concise and punchy\n")
		sb.WriteString("- Include 1-2 relevant hashtags\n")
		sb.WriteString("- Make it engaging and shareable\n")
	case "Instagram":
		sb.WriteString("\nRequirements for Instagram:\n")
		sb.WriteString("- Write engaging, visual-oriented copy\n")
		sb.WriteString("- MUST include multiple relevant hashtags (at least 5-10)\n")
		sb.WriteString("- Use emojis to make it visually appealing\n")
		sb.WriteString("- Focus on the story behind the code\n")
	case "YouTube":
		sb.WriteString("\nRequirements for YouTube video description:\n")
		sb.WriteString("- Write a detailed description with sections\n")
		sb.WriteString("- Include what was changed and why\n")
		sb.WriteString("- Add relevant hashtags at the end\n")
		sb.WriteString("- Make it informative for developers\n")
	case "Bluesky":
		sb.WriteString("\nRequirements for Bluesky:\n")
		sb.WriteString("- MUST be 300 characters or less (this is critical!)\n")
		sb.WriteString("- Be concise and engaging\n")
		sb.WriteString("- Focus on what was built or shipped\n")
		sb.WriteString("- Keep it punchy and direct\n")
	}

	sb.WriteString("\nGenerate only the post content, nothing else.")

	return sb.String()
}

// extractRepoInfo extracts owner/repo from a GitHub URL
func extractRepoInfo(githubURL string) string {
	// Expected format: https://github.com/owner/repo/...
	if githubURL == "" {
		return ""
	}

	// Remove protocol and domain
	url := strings.TrimPrefix(githubURL, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "github.com/")

	// Get owner/repo (first two path segments)
	parts := strings.Split(url, "/")
	if len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}

	return ""
}

// enforceConstraints applies platform-specific constraints to the content
func enforceConstraints(content string, config platformConfig) string {
	content = strings.TrimSpace(content)

	// Enforce max length for platforms with limits
	if config.MaxLength > 0 && len(content) > config.MaxLength {
		// Truncate gracefully with ellipsis (use "..." for ASCII compatibility)
		content = content[:config.MaxLength-3] + "..."
	}

	return content
}
