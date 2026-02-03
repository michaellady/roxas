package services

import (
	"context"
	"errors"
	"fmt"
)

// =============================================================================
// Platform Fallback Poster Service
// Handles posting to social platforms with fallback logic (Bluesky → Threads)
// =============================================================================

// Error definitions for platform fallback posting
var (
	ErrNoPlatformConnected = errors.New("no social platform connected - please connect Bluesky or Threads first")
	ErrPostFailed          = errors.New("failed to post to platform")
)

// PlatformFallbackPoster handles posting to social platforms with fallback logic.
// It tries Bluesky first (if connected), then falls back to Threads.
type PlatformFallbackPoster struct {
	credentialStore CredentialStore
	clientFactory   SocialClientFactory
}

// NewPlatformFallbackPoster creates a new PlatformFallbackPoster instance.
func NewPlatformFallbackPoster(credStore CredentialStore, factory SocialClientFactory) *PlatformFallbackPoster {
	return &PlatformFallbackPoster{
		credentialStore: credStore,
		clientFactory:   factory,
	}
}

// PlatformPostResult contains the result of a successful post operation with platform info
type PlatformPostResult struct {
	PostURL  string
	Platform string
}

// Post attempts to post content using available connected platforms.
// It tries Bluesky first, then falls back to Threads if Bluesky is unavailable or fails.
// Returns the post URL and platform used on success.
func (p *PlatformFallbackPoster) Post(ctx context.Context, userID string, content PostContent) (*PlatformPostResult, error) {
	// Try Bluesky first
	bluskyCreds, bskyErr := p.credentialStore.GetCredentials(ctx, userID, PlatformBluesky)
	if bskyErr == nil && bluskyCreds != nil {
		bskyClient, err := p.clientFactory.CreateClient(ctx, PlatformBluesky, bluskyCreds)
		if err != nil {
			return nil, fmt.Errorf("failed to create Bluesky client: %w", err)
		}
		result, err := bskyClient.Post(ctx, content)
		if err != nil {
			return nil, fmt.Errorf("failed to post to Bluesky: %w", err)
		}
		return &PlatformPostResult{
			PostURL:  result.PostURL,
			Platform: PlatformBluesky,
		}, nil
	}

	// Fall back to Threads
	threadsCreds, threadsErr := p.credentialStore.GetCredentials(ctx, userID, PlatformThreads)
	if threadsErr == nil && threadsCreds != nil {
		threadsClient, err := p.clientFactory.CreateClient(ctx, PlatformThreads, threadsCreds)
		if err != nil {
			return nil, fmt.Errorf("failed to create Threads client: %w", err)
		}
		result, err := threadsClient.Post(ctx, content)
		if err != nil {
			return nil, fmt.Errorf("failed to post to Threads: %w", err)
		}
		return &PlatformPostResult{
			PostURL:  result.PostURL,
			Platform: PlatformThreads,
		}, nil
	}

	return nil, ErrNoPlatformConnected
}
