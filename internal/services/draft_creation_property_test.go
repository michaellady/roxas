package services

import (
	"context"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// Property Test: Draft Creation with Status (Property 21)
// Validates Requirements 5.15
//
// Property: For any successful AI content generation, the system should create
// a draft record with status "draft" and the generated content.
// This means:
// 1. Successful AI generation always results in a draft
// 2. The draft always has status "draft"
// 3. The draft contains the exact generated content
// 4. The draft has the correct commit ID and platform

// =============================================================================
// Property Test Mocks
// =============================================================================

// propertyMockCommitLookup implements CommitLookup for property testing
type propertyMockCommitLookup struct {
	commits map[string]*Commit
}

func (m *propertyMockCommitLookup) GetCommitByID(ctx context.Context, id string) (*Commit, error) {
	commit, ok := m.commits[id]
	if !ok {
		return nil, nil
	}
	return commit, nil
}

// propertyMockGenerator implements PostGeneratorService for property testing
type propertyMockGenerator struct {
	content string
}

func (m *propertyMockGenerator) Generate(ctx context.Context, platform string, commit *Commit) (*GeneratedPost, error) {
	return &GeneratedPost{
		Platform: platform,
		Content:  m.content,
		CommitID: commit.ID,
	}, nil
}

// propertyMockDraftStore implements DraftStore for property testing
type propertyMockDraftStore struct {
	created *DraftPost
}

func (m *propertyMockDraftStore) CreateDraftPost(ctx context.Context, commitID, platform, content string) (*DraftPost, error) {
	post := &DraftPost{
		ID:        "draft-" + commitID,
		CommitID:  commitID,
		Platform:  platform,
		Content:   content,
		Status:    DraftStatusDraft,
		CreatedAt: time.Now(),
	}
	m.created = post
	return post, nil
}

// =============================================================================
// Property 21 Tests
// =============================================================================

func TestProperty21_DraftCreationWithStatus(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	// Property 21a: Successful AI generation always creates a draft with status "draft"
	properties.Property("successful AI generation creates draft with status draft", prop.ForAll(
		func(commitID, message, author, generatedContent string, platformIdx int) bool {
			if commitID == "" || generatedContent == "" {
				return true // Skip empty cases
			}

			platforms := []string{PlatformLinkedIn, PlatformTwitter, PlatformInstagram, PlatformYouTube}
			platform := platforms[platformIdx%len(platforms)]

			commit := &Commit{
				ID:      commitID,
				Message: message,
				Author:  author,
			}

			commitLookup := &propertyMockCommitLookup{
				commits: map[string]*Commit{commitID: commit},
			}
			generator := &propertyMockGenerator{content: generatedContent}
			store := &propertyMockDraftStore{}

			creator := NewDraftPostCreator(commitLookup, generator, store)
			draft, err := creator.CreateDraft(context.Background(), commitID, platform)

			if err != nil {
				return false // Should not error on valid inputs
			}
			if draft == nil {
				return false
			}

			// Key assertion: status must be "draft"
			return draft.Status == DraftStatusDraft
		},
		genNonEmptyString(),
		gen.AnyString(),
		gen.AnyString(),
		genNonEmptyString(),
		gen.IntRange(0, 3),
	))

	// Property 21b: Draft contains exact generated content
	properties.Property("draft contains exact generated content", prop.ForAll(
		func(commitID, generatedContent string, platformIdx int) bool {
			if commitID == "" || generatedContent == "" {
				return true
			}

			platforms := []string{PlatformLinkedIn, PlatformTwitter, PlatformInstagram, PlatformYouTube}
			platform := platforms[platformIdx%len(platforms)]

			commit := &Commit{ID: commitID}
			commitLookup := &propertyMockCommitLookup{
				commits: map[string]*Commit{commitID: commit},
			}
			generator := &propertyMockGenerator{content: generatedContent}
			store := &propertyMockDraftStore{}

			creator := NewDraftPostCreator(commitLookup, generator, store)
			draft, err := creator.CreateDraft(context.Background(), commitID, platform)

			if err != nil {
				return false
			}

			// Content must match exactly
			return draft.Content == generatedContent
		},
		genNonEmptyString(),
		genNonEmptyString(),
		gen.IntRange(0, 3),
	))

	// Property 21c: Draft has correct commit ID
	properties.Property("draft has correct commit ID", prop.ForAll(
		func(commitID, generatedContent string, platformIdx int) bool {
			if commitID == "" || generatedContent == "" {
				return true
			}

			platforms := []string{PlatformLinkedIn, PlatformTwitter, PlatformInstagram, PlatformYouTube}
			platform := platforms[platformIdx%len(platforms)]

			commit := &Commit{ID: commitID}
			commitLookup := &propertyMockCommitLookup{
				commits: map[string]*Commit{commitID: commit},
			}
			generator := &propertyMockGenerator{content: generatedContent}
			store := &propertyMockDraftStore{}

			creator := NewDraftPostCreator(commitLookup, generator, store)
			draft, err := creator.CreateDraft(context.Background(), commitID, platform)

			if err != nil {
				return false
			}

			return draft.CommitID == commitID
		},
		genNonEmptyString(),
		genNonEmptyString(),
		gen.IntRange(0, 3),
	))

	// Property 21d: Draft has correct platform
	properties.Property("draft has correct platform", prop.ForAll(
		func(commitID, generatedContent string, platformIdx int) bool {
			if commitID == "" || generatedContent == "" {
				return true
			}

			platforms := []string{PlatformLinkedIn, PlatformTwitter, PlatformInstagram, PlatformYouTube}
			platform := platforms[platformIdx%len(platforms)]

			commit := &Commit{ID: commitID}
			commitLookup := &propertyMockCommitLookup{
				commits: map[string]*Commit{commitID: commit},
			}
			generator := &propertyMockGenerator{content: generatedContent}
			store := &propertyMockDraftStore{}

			creator := NewDraftPostCreator(commitLookup, generator, store)
			draft, err := creator.CreateDraft(context.Background(), commitID, platform)

			if err != nil {
				return false
			}

			return draft.Platform == platform
		},
		genNonEmptyString(),
		genNonEmptyString(),
		gen.IntRange(0, 3),
	))

	// Property 21e: All supported platforms create drafts with status "draft"
	properties.Property("all supported platforms create draft with status draft", prop.ForAll(
		func(commitID, generatedContent string) bool {
			if commitID == "" || generatedContent == "" {
				return true
			}

			platforms := []string{PlatformLinkedIn, PlatformTwitter, PlatformInstagram, PlatformYouTube}

			for _, platform := range platforms {
				commit := &Commit{ID: commitID}
				commitLookup := &propertyMockCommitLookup{
					commits: map[string]*Commit{commitID: commit},
				}
				generator := &propertyMockGenerator{content: generatedContent}
				store := &propertyMockDraftStore{}

				creator := NewDraftPostCreator(commitLookup, generator, store)
				draft, err := creator.CreateDraft(context.Background(), commitID, platform)

				if err != nil {
					return false
				}
				if draft.Status != DraftStatusDraft {
					return false
				}
			}

			return true
		},
		genNonEmptyString(),
		genNonEmptyString(),
	))

	// Property 21f: Draft status is never empty or invalid
	properties.Property("draft status is never empty", prop.ForAll(
		func(commitID, generatedContent string, platformIdx int) bool {
			if commitID == "" || generatedContent == "" {
				return true
			}

			platforms := []string{PlatformLinkedIn, PlatformTwitter, PlatformInstagram, PlatformYouTube}
			platform := platforms[platformIdx%len(platforms)]

			commit := &Commit{ID: commitID}
			commitLookup := &propertyMockCommitLookup{
				commits: map[string]*Commit{commitID: commit},
			}
			generator := &propertyMockGenerator{content: generatedContent}
			store := &propertyMockDraftStore{}

			creator := NewDraftPostCreator(commitLookup, generator, store)
			draft, err := creator.CreateDraft(context.Background(), commitID, platform)

			if err != nil {
				return false
			}

			// Status must not be empty and must be the expected value
			return draft.Status != "" && draft.Status == DraftStatusDraft
		},
		genNonEmptyString(),
		genNonEmptyString(),
		gen.IntRange(0, 3),
	))

	// Property 21g: Special characters in generated content are preserved
	properties.Property("special characters in content are preserved", prop.ForAll(
		func(commitID, generatedContent string, platformIdx int) bool {
			if commitID == "" || generatedContent == "" {
				return true
			}

			platforms := []string{PlatformLinkedIn, PlatformTwitter, PlatformInstagram, PlatformYouTube}
			platform := platforms[platformIdx%len(platforms)]

			commit := &Commit{ID: commitID}
			commitLookup := &propertyMockCommitLookup{
				commits: map[string]*Commit{commitID: commit},
			}
			generator := &propertyMockGenerator{content: generatedContent}
			store := &propertyMockDraftStore{}

			creator := NewDraftPostCreator(commitLookup, generator, store)
			draft, err := creator.CreateDraft(context.Background(), commitID, platform)

			if err != nil {
				return false
			}

			// Byte-level equality check
			return draft.Content == generatedContent && len(draft.Content) == len(generatedContent)
		},
		genNonEmptyString(),
		gen.AnyString().SuchThat(func(s string) bool { return len(s) > 0 }),
		gen.IntRange(0, 3),
	))

	properties.TestingRun(t)
}

// TestProperty21_DraftStatusConstant verifies the draft status constant is correct
func TestProperty21_DraftStatusConstant(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Property: DraftStatusDraft constant always equals "draft"
	properties.Property("DraftStatusDraft constant equals 'draft'", prop.ForAll(
		func(_ int) bool {
			return DraftStatusDraft == "draft"
		},
		gen.IntRange(0, 100),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Generators
// =============================================================================

// genNonEmptyString generates non-empty strings for testing
func genNonEmptyString() gopter.Gen {
	return gen.AnyString().SuchThat(func(s string) bool {
		return len(s) > 0
	})
}

// genCommitID generates realistic commit IDs
func genCommitID() gopter.Gen {
	return gen.RegexMatch(`[a-z0-9]{8,40}`)
}

// genGeneratedContent generates realistic AI-generated social media content
func genGeneratedContent() gopter.Gen {
	prefixes := gen.OneConstOf(
		"🚀 Just shipped:",
		"New feature alert!",
		"We just released",
		"Check out our latest update:",
		"Exciting news!",
	)
	body := gen.AnyString().Map(func(s string) string {
		if len(s) > 200 {
			return s[:200]
		}
		return s
	})

	return gopter.CombineGens(prefixes, body).Map(func(vals []interface{}) string {
		prefix := vals[0].(string)
		b := vals[1].(string)
		return prefix + " " + b
	})
}

// genPlatform generates valid platform names
func genPlatform() gopter.Gen {
	return gen.OneConstOf(
		PlatformLinkedIn,
		PlatformTwitter,
		PlatformInstagram,
		PlatformYouTube,
	)
}
