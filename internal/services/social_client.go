package services

import (
	"context"
	"time"
)

// =============================================================================
// SocialClient Interface and Types
// Abstract interface for multi-platform social media posting
// =============================================================================

// Media type constants
const (
	MediaTypeImage    = "image"
	MediaTypeVideo    = "video"
	MediaTypeDocument = "document"
)

// SocialClient defines the interface for social media platform clients.
// Each platform (LinkedIn, Twitter, Instagram, etc.) implements this interface
// to provide consistent posting capabilities across platforms.
type SocialClient interface {
	// Post publishes content to the social media platform.
	// Returns a PostResult with the post ID and URL on success.
	Post(ctx context.Context, content PostContent) (*PostResult, error)

	// ValidateContent checks if the content meets platform-specific requirements.
	// Returns an error describing validation failures, or nil if valid.
	// Should be called before Post to catch issues early.
	ValidateContent(content PostContent) error

	// Platform returns the platform identifier (e.g., "linkedin", "twitter").
	// Use the Platform* constants defined in post_generator.go.
	Platform() string

	// GetRateLimits returns current rate limiting information for the platform.
	// Clients should check this before posting to avoid rate limit errors.
	GetRateLimits() RateLimitInfo
}

// PostContent represents the content to be posted to a social media platform.
type PostContent struct {
	// Text is the main text content of the post.
	Text string

	// Media contains optional media attachments (images, videos, documents).
	Media []MediaAttachment

	// ThreadID is an optional parent post ID for replies/threads.
	// Set this to create a reply or continue a thread.
	ThreadID *string

	// Metadata contains platform-specific options (e.g., visibility, hashtags).
	// The structure varies by platform.
	Metadata map[string]any
}

// PostResult represents the result of a successful post operation.
type PostResult struct {
	// PostID is the platform-specific identifier for the created post.
	PostID string

	// PostURL is the public URL to view the post.
	PostURL string

	// PlatformRaw contains the raw platform API response for advanced use cases.
	PlatformRaw map[string]any
}

// MediaAttachment represents a media file to attach to a post.
type MediaAttachment struct {
	// Type indicates the media type (use MediaType* constants).
	Type string

	// URL is the location of the media file.
	// Can be a local file path or remote URL depending on implementation.
	URL string

	// MimeType is the MIME type of the media (e.g., "image/png", "video/mp4").
	MimeType string

	// AltText is accessibility text describing the media content.
	AltText string

	// Data contains the raw bytes of the media (alternative to URL).
	// Used when media is provided directly rather than via URL.
	Data []byte
}

// RateLimitInfo contains rate limiting information for a platform.
type RateLimitInfo struct {
	// Limit is the maximum number of requests allowed in the window.
	Limit int

	// Remaining is the number of requests remaining in the current window.
	Remaining int

	// ResetAt is the time when the rate limit window resets.
	ResetAt time.Time
}

// IsLimited returns true if the rate limit has been exceeded.
func (r RateLimitInfo) IsLimited() bool {
	return r.Remaining <= 0
}

// TimeUntilReset returns the duration until the rate limit resets.
func (r RateLimitInfo) TimeUntilReset() time.Duration {
	if r.ResetAt.IsZero() {
		return 0
	}
	until := time.Until(r.ResetAt)
	if until < 0 {
		return 0
	}
	return until
}
