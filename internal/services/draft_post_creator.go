package services

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// =============================================================================
// DraftPostCreator Interface and Implementation (TB-POST-01)
// =============================================================================

// DraftPost status constants
const (
	DraftStatusDraft   = "draft"
	DraftStatusPosted  = "posted"
	DraftStatusFailed  = "failed"
)

// Error definitions
var (
	ErrCommitNotFound      = errors.New("commit not found")
	ErrUnsupportedPlatform = errors.New("unsupported platform")
	ErrInvalidInput        = errors.New("invalid input")
)

// DraftPost represents a draft social media post
type DraftPost struct {
	ID        string
	CommitID  string
	Platform  string
	Content   string
	Status    string
	CreatedAt time.Time
}

// DraftPostCreator creates draft social media posts from commits
type DraftPostCreator interface {
	// CreateDraft generates and stores a draft post for the given commit and platform
	CreateDraft(ctx context.Context, commitID, platform string) (*DraftPost, error)
}

// CommitLookup provides commit retrieval by ID
type CommitLookup interface {
	GetCommitByID(ctx context.Context, id string) (*Commit, error)
}

// DraftStore provides draft post persistence
type DraftStore interface {
	CreateDraftPost(ctx context.Context, commitID, platform, content string) (*DraftPost, error)
}

// draftPostCreator implements DraftPostCreator
type draftPostCreator struct {
	commitLookup CommitLookup
	generator    PostGeneratorService
	store        DraftStore
}

// NewDraftPostCreator creates a new DraftPostCreator instance
func NewDraftPostCreator(commitLookup CommitLookup, generator PostGeneratorService, store DraftStore) DraftPostCreator {
	return &draftPostCreator{
		commitLookup: commitLookup,
		generator:    generator,
		store:        store,
	}
}

// supportedPlatforms defines valid platforms for draft creation
var supportedPlatformsSet = map[string]bool{
	PlatformLinkedIn:  true,
	PlatformTwitter:   true,
	PlatformInstagram: true,
	PlatformYouTube:   true,
}

// CreateDraft implements DraftPostCreator.CreateDraft
func (c *draftPostCreator) CreateDraft(ctx context.Context, commitID, platform string) (*DraftPost, error) {
	// Validate inputs
	if commitID == "" {
		return nil, fmt.Errorf("%w: commit ID is required", ErrInvalidInput)
	}
	if platform == "" {
		return nil, fmt.Errorf("%w: platform is required", ErrInvalidInput)
	}

	// Validate platform before doing any work
	if !supportedPlatformsSet[platform] {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPlatform, platform)
	}

	// Look up the commit
	commit, err := c.commitLookup.GetCommitByID(ctx, commitID)
	if err != nil {
		return nil, fmt.Errorf("looking up commit: %w", err)
	}
	if commit == nil {
		return nil, ErrCommitNotFound
	}

	// Generate post content
	generated, err := c.generator.Generate(ctx, platform, commit)
	if err != nil {
		return nil, fmt.Errorf("generating post content: %w", err)
	}

	// Store the draft
	draft, err := c.store.CreateDraftPost(ctx, commitID, platform, generated.Content)
	if err != nil {
		return nil, fmt.Errorf("storing draft post: %w", err)
	}

	return draft, nil
}
