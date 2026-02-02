package services

import (
	"strings"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// Property Test: AI Prompt Construction (Property 20)
// Validates Requirements 5.13, 5.14
//
// Property: For any draft generation, the GPT prompt should include all commit messages,
// diffs (or summaries), author name, repository name, and a 300-character limit instruction.
//
// This test verifies:
// 1. Prompt includes commit message for any commit
// 2. Prompt includes author name for any commit
// 3. Prompt includes repository name when GitHub URL is present
// 4. Prompt includes 300-char limit instruction for Bluesky platform
// 5. enforceConstraints truncates content exceeding platform limits

func TestProperty20_PromptIncludesCommitMessage(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Property 20a: For any commit, the prompt contains the commit message
	properties.Property("prompt includes commit message", prop.ForAll(
		func(message string) bool {
			if message == "" {
				return true // Empty messages are valid edge case
			}

			commit := &Commit{
				ID:        "test-id",
				Message:   message,
				Author:    "Test Author",
				GitHubURL: "https://github.com/owner/repo/commit/abc123",
				Timestamp: time.Now(),
			}

			config := platformConfigs[PlatformBluesky]
			prompt := buildPrompt(config, commit)

			return strings.Contains(prompt, message)
		},
		genCommitMessage(),
	))

	properties.TestingRun(t)
}

func TestProperty20_PromptIncludesAuthor(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Property 20b: For any commit, the prompt contains the author name
	properties.Property("prompt includes author name", prop.ForAll(
		func(author string) bool {
			if author == "" {
				return true // Empty author is valid edge case
			}

			commit := &Commit{
				ID:        "test-id",
				Message:   "Test commit message",
				Author:    author,
				GitHubURL: "https://github.com/owner/repo/commit/abc123",
				Timestamp: time.Now(),
			}

			config := platformConfigs[PlatformBluesky]
			prompt := buildPrompt(config, commit)

			return strings.Contains(prompt, author)
		},
		genAuthorName(),
	))

	properties.TestingRun(t)
}

func TestProperty20_PromptIncludesRepoName(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Property 20c: For any valid GitHub URL, the prompt contains the repository name
	properties.Property("prompt includes repository name from GitHub URL", prop.ForAll(
		func(owner, repo string) bool {
			if owner == "" || repo == "" {
				return true // Empty values are edge cases
			}

			githubURL := "https://github.com/" + owner + "/" + repo + "/commit/abc123"
			expectedRepo := owner + "/" + repo

			commit := &Commit{
				ID:        "test-id",
				Message:   "Test commit message",
				Author:    "Test Author",
				GitHubURL: githubURL,
				Timestamp: time.Now(),
			}

			config := platformConfigs[PlatformBluesky]
			prompt := buildPrompt(config, commit)

			return strings.Contains(prompt, expectedRepo)
		},
		genGitHubOwner(),
		genGitHubRepoName(),
	))

	properties.TestingRun(t)
}

func TestProperty20_BlueskyPromptIncludes300CharLimit(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Property 20d: For Bluesky platform, prompt always includes 300-char limit instruction
	properties.Property("Bluesky prompt includes 300 character limit instruction", prop.ForAll(
		func(message, author string) bool {
			commit := &Commit{
				ID:        "test-id",
				Message:   message,
				Author:    author,
				GitHubURL: "https://github.com/owner/repo/commit/abc123",
				Timestamp: time.Now(),
			}

			config := platformConfigs[PlatformBluesky]
			prompt := buildPrompt(config, commit)

			// Check for the critical 300-char limit instruction
			return strings.Contains(prompt, "300 characters or less")
		},
		genCommitMessage(),
		genAuthorName(),
	))

	properties.TestingRun(t)
}

func TestProperty20_EnforceConstraintsTruncatesBluesky(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 500 // Allow longer strings

	properties := gopter.NewProperties(parameters)

	// Property 20e: For Bluesky, enforceConstraints truncates content exceeding 300 chars
	properties.Property("Bluesky content is truncated to 300 characters", prop.ForAll(
		func(content string) bool {
			config := platformConfigs[PlatformBluesky]
			result := enforceConstraints(content, config)

			// Result should never exceed 300 characters
			return len(result) <= 300
		},
		gen.AnyString(),
	))

	// Property 20f: Content under limit is preserved
	properties.Property("content under 300 chars is preserved", prop.ForAll(
		func(content string) bool {
			// Generate content that's definitely under 300 chars
			if len(content) > 297 {
				content = content[:297]
			}

			config := platformConfigs[PlatformBluesky]
			result := enforceConstraints(content, config)

			// After trimming whitespace, short content should be preserved
			return strings.TrimSpace(result) == strings.TrimSpace(content)
		},
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) <= 297 }),
	))

	properties.TestingRun(t)
}

func TestProperty20_ExtractRepoInfoVariousURLFormats(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Property 20g: extractRepoInfo correctly extracts owner/repo from various URL formats
	properties.Property("extractRepoInfo handles https URLs", prop.ForAll(
		func(owner, repo string) bool {
			if owner == "" || repo == "" {
				return true
			}

			url := "https://github.com/" + owner + "/" + repo + "/commit/abc123"
			expected := owner + "/" + repo

			result := extractRepoInfo(url)
			return result == expected
		},
		genGitHubOwner(),
		genGitHubRepoName(),
	))

	properties.Property("extractRepoInfo handles http URLs", prop.ForAll(
		func(owner, repo string) bool {
			if owner == "" || repo == "" {
				return true
			}

			url := "http://github.com/" + owner + "/" + repo + "/commit/abc123"
			expected := owner + "/" + repo

			result := extractRepoInfo(url)
			return result == expected
		},
		genGitHubOwner(),
		genGitHubRepoName(),
	))

	properties.Property("extractRepoInfo handles URLs without protocol", prop.ForAll(
		func(owner, repo string) bool {
			if owner == "" || repo == "" {
				return true
			}

			url := "github.com/" + owner + "/" + repo + "/commit/abc123"
			expected := owner + "/" + repo

			result := extractRepoInfo(url)
			return result == expected
		},
		genGitHubOwner(),
		genGitHubRepoName(),
	))

	properties.Property("extractRepoInfo returns empty for empty URL", prop.ForAll(
		func(_ int) bool {
			result := extractRepoInfo("")
			return result == ""
		},
		gen.Int(),
	))

	properties.TestingRun(t)
}

func TestProperty20_TwitterPromptIncludes280CharLimit(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Property 20h: For Twitter platform, prompt includes 280-char limit instruction
	properties.Property("Twitter prompt includes 280 character limit instruction", prop.ForAll(
		func(message, author string) bool {
			commit := &Commit{
				ID:        "test-id",
				Message:   message,
				Author:    author,
				GitHubURL: "https://github.com/owner/repo/commit/abc123",
				Timestamp: time.Now(),
			}

			config := platformConfigs[PlatformTwitter]
			prompt := buildPrompt(config, commit)

			// Check for the critical 280-char limit instruction
			return strings.Contains(prompt, "280 characters or less")
		},
		genCommitMessage(),
		genAuthorName(),
	))

	properties.TestingRun(t)
}

func TestProperty20_AllPlatformPromptsIncludeCommitInfo(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	platforms := []string{PlatformLinkedIn, PlatformTwitter, PlatformInstagram, PlatformYouTube, PlatformBluesky}

	// Property 20i: All platform prompts include the "Commit Information:" section
	properties.Property("all platform prompts include Commit Information section", prop.ForAll(
		func(platformIdx int, message, author string) bool {
			if message == "" || author == "" {
				return true
			}

			// Select platform based on generated index
			platform := platforms[platformIdx%len(platforms)]

			commit := &Commit{
				ID:        "test-id",
				Message:   message,
				Author:    author,
				GitHubURL: "https://github.com/owner/repo/commit/abc123",
				Timestamp: time.Now(),
			}

			config := platformConfigs[platform]
			prompt := buildPrompt(config, commit)

			// All prompts should include the commit information section header
			hasSection := strings.Contains(prompt, "Commit Information:")
			hasMessage := strings.Contains(prompt, "- Message:")
			hasAuthor := strings.Contains(prompt, "- Author:")

			return hasSection && hasMessage && hasAuthor
		},
		gen.IntRange(0, len(platforms)-1),
		genCommitMessage(),
		genAuthorName(),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Generators
// =============================================================================

// genCommitMessage generates realistic commit messages
func genCommitMessage() gopter.Gen {
	prefixes := gen.OneConstOf(
		"feat:", "fix:", "docs:", "style:", "refactor:",
		"test:", "chore:", "perf:", "ci:", "build:",
		"Add", "Fix", "Update", "Remove", "Implement",
		"Refactor", "Improve", "Change", "Create", "Delete",
	)

	subjects := gen.OneConstOf(
		"user authentication",
		"database connection",
		"API endpoint",
		"unit tests",
		"documentation",
		"error handling",
		"configuration",
		"logging",
		"caching",
		"validation",
		"performance optimization",
		"security fix",
		"bug in login flow",
		"typo in README",
		"webpack config",
	)

	return gopter.CombineGens(prefixes, subjects).Map(func(vals []interface{}) string {
		return vals[0].(string) + " " + vals[1].(string)
	})
}

// genAuthorName generates realistic author names
func genAuthorName() gopter.Gen {
	firstNames := gen.OneConstOf(
		"Alice", "Bob", "Charlie", "Diana", "Eve",
		"Frank", "Grace", "Henry", "Ivy", "Jack",
		"Kate", "Leo", "Mia", "Noah", "Olivia",
	)

	lastNames := gen.OneConstOf(
		"Smith", "Johnson", "Williams", "Brown", "Jones",
		"Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
		"Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
	)

	return gopter.CombineGens(firstNames, lastNames).Map(func(vals []interface{}) string {
		return vals[0].(string) + " " + vals[1].(string)
	})
}

// genGitHubOwner generates valid GitHub usernames/org names
func genGitHubOwner() gopter.Gen {
	// GitHub usernames: alphanumeric and hyphens, 1-39 chars, can't start/end with hyphen
	return gen.RegexMatch(`[a-z][a-z0-9-]{0,20}[a-z0-9]`).SuchThat(func(s string) bool {
		return len(s) >= 2 && !strings.Contains(s, "--")
	})
}

// genGitHubRepoName generates valid GitHub repository names
func genGitHubRepoName() gopter.Gen {
	// Repo names: alphanumeric, hyphens, underscores, dots
	return gen.RegexMatch(`[a-z][a-z0-9._-]{0,20}[a-z0-9]`).SuchThat(func(s string) bool {
		return len(s) >= 2
	})
}
