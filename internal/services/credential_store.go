package services

import (
	"context"
	"errors"
	"time"
)

// =============================================================================
// Platform Credential Management (TB-CRED)
// =============================================================================

// Platform credential constants
const (
	PlatformBluesky  = "bluesky"
	PlatformThreads  = "threads"
	PlatformTikTok   = "tiktok"
)

// Error definitions for credential management
var (
	ErrCredentialsNotFound = errors.New("credentials not found")
	ErrInvalidPlatform     = errors.New("invalid platform")
	ErrTokenExpired        = errors.New("token has expired")
	ErrEncryptionFailed    = errors.New("encryption failed")
	ErrDecryptionFailed    = errors.New("decryption failed")
)

// SupportedPlatforms lists all platforms that can have credentials stored
var SupportedPlatforms = map[string]bool{
	PlatformLinkedIn:  true,
	PlatformTwitter:   true,
	PlatformInstagram: true,
	PlatformYouTube:   true,
	PlatformBluesky:   true,
	PlatformThreads:   true,
	PlatformTikTok:    true,
	PlatformGitHub:    true,
}

// PlatformCredentials represents OAuth credentials for a platform
type PlatformCredentials struct {
	ID                 string     `json:"id"`
	UserID             string     `json:"user_id"`
	Platform           string     `json:"platform"`
	AccessToken        string     `json:"access_token"`        // Encrypted at rest
	RefreshToken       string     `json:"refresh_token"`       // Encrypted at rest, may be empty
	TokenExpiresAt     *time.Time `json:"token_expires_at"`    // nil if token doesn't expire
	PlatformUserID     string     `json:"platform_user_id"`    // e.g., LinkedIn URN, Twitter handle
	Scopes             string     `json:"scopes"`              // Comma-separated list of granted scopes
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	LastHealthCheck    *time.Time `json:"last_health_check"`   // Last time health was checked
	IsHealthy          bool       `json:"is_healthy"`          // Current health status
	HealthError        *string    `json:"health_error"`        // Error message if unhealthy
	LastSuccessfulPost *time.Time `json:"last_successful_post"` // Last successful post timestamp
}

// IsExpired returns true if the access token has expired
func (c *PlatformCredentials) IsExpired() bool {
	if c.TokenExpiresAt == nil {
		return false // Token doesn't expire
	}
	return time.Now().After(*c.TokenExpiresAt)
}

// ExpiresWithin returns true if the token expires within the given duration
func (c *PlatformCredentials) ExpiresWithin(d time.Duration) bool {
	if c.TokenExpiresAt == nil {
		return false // Token doesn't expire
	}
	return time.Now().Add(d).After(*c.TokenExpiresAt)
}

// HasRefreshToken returns true if a refresh token is available
func (c *PlatformCredentials) HasRefreshToken() bool {
	return c.RefreshToken != ""
}

// CredentialStore provides platform credential persistence operations
type CredentialStore interface {
	// GetCredentials retrieves credentials for a user and platform
	// Returns ErrCredentialsNotFound if not found
	GetCredentials(ctx context.Context, userID, platform string) (*PlatformCredentials, error)

	// SaveCredentials creates or updates credentials for a user and platform
	SaveCredentials(ctx context.Context, creds *PlatformCredentials) error

	// DeleteCredentials removes credentials for a user and platform
	DeleteCredentials(ctx context.Context, userID, platform string) error

	// GetCredentialsForUser retrieves all credentials for a user
	GetCredentialsForUser(ctx context.Context, userID string) ([]*PlatformCredentials, error)

	// GetExpiringCredentials retrieves credentials expiring within the given duration
	// Useful for background token refresh jobs
	GetExpiringCredentials(ctx context.Context, within time.Duration) ([]*PlatformCredentials, error)

	// UpdateTokens updates just the access and refresh tokens (and expiry)
	// Used after a token refresh operation
	UpdateTokens(ctx context.Context, userID, platform, accessToken, refreshToken string, expiresAt *time.Time) error

	// UpdateHealthStatus updates the health status of a credential
	// Called by the health check job after testing a connection
	UpdateHealthStatus(ctx context.Context, userID, platform string, isHealthy bool, healthError *string) error

	// GetCredentialsNeedingCheck retrieves credentials that haven't been checked
	// within the given duration (or have never been checked)
	GetCredentialsNeedingCheck(ctx context.Context, notCheckedWithin time.Duration) ([]*PlatformCredentials, error)
}

// ValidatePlatform checks if a platform string is valid
func ValidatePlatform(platform string) error {
	if !SupportedPlatforms[platform] {
		return ErrInvalidPlatform
	}
	return nil
}
