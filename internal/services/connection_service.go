package services

import (
	"context"
	"errors"
	"time"
)

// =============================================================================
// ConnectionService Interface and Types (TB-CONN)
// Manages platform OAuth connections for users
// =============================================================================

// Connection status constants
const (
	ConnectionStatusConnected    = "connected"
	ConnectionStatusDisconnected = "disconnected"
	ConnectionStatusExpired      = "expired"
	ConnectionStatusError        = "error"
)

// Error definitions for connection management
var (
	ErrConnectionNotFound = errors.New("connection not found")
	ErrOAuthStateInvalid  = errors.New("OAuth state is invalid or expired")
	ErrOAuthCodeInvalid   = errors.New("OAuth authorization code is invalid")
	ErrConnectionFailed   = errors.New("connection test failed")
	ErrPlatformDisabled   = errors.New("platform is disabled")
)

// Connection represents a user's connection to a social platform
type Connection struct {
	UserID         string     `json:"user_id"`
	Platform       string     `json:"platform"`
	Status         string     `json:"status"` // Use ConnectionStatus* constants
	PlatformUserID string     `json:"platform_user_id,omitempty"`
	DisplayName    string     `json:"display_name,omitempty"`
	ProfileURL     string     `json:"profile_url,omitempty"`
	Scopes         []string   `json:"scopes,omitempty"`
	ConnectedAt    *time.Time `json:"connected_at,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	LastTestedAt   *time.Time `json:"last_tested_at,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
}

// IsHealthy returns true if the connection is active and not expired
func (c *Connection) IsHealthy() bool {
	if c.Status != ConnectionStatusConnected {
		return false
	}
	if c.ExpiresAt != nil && time.Now().After(*c.ExpiresAt) {
		return false
	}
	return true
}

// ExpiresSoon returns true if the token expires within 7 days
func (c *Connection) ExpiresSoon() bool {
	if c.ExpiresAt == nil {
		return false
	}
	// Token is considered "expiring soon" if it expires within 7 days
	warningThreshold := 7 * 24 * time.Hour
	return time.Until(*c.ExpiresAt) <= warningThreshold && time.Until(*c.ExpiresAt) > 0
}

// OAuthInfo contains the information needed to redirect user for OAuth
type OAuthInfo struct {
	AuthURL     string    `json:"auth_url"`
	State       string    `json:"state"`
	ExpiresAt   time.Time `json:"expires_at"`
	Scopes      []string  `json:"scopes"`
	RedirectURI string    `json:"redirect_uri"`
}

// OAuthResult contains the result of a successful OAuth callback
type OAuthResult struct {
	Connection     *Connection `json:"connection"`
	IsNewConnection bool       `json:"is_new_connection"`
}

// ConnectionTestResult contains the result of testing a connection
type ConnectionTestResult struct {
	Platform   string        `json:"platform"`
	Success    bool          `json:"success"`
	Latency    time.Duration `json:"latency"`
	TestedAt   time.Time     `json:"tested_at"`
	Error      string        `json:"error,omitempty"`
	RateLimits *RateLimitInfo `json:"rate_limits,omitempty"`
}

// ConnectionService manages OAuth connections to social platforms
type ConnectionService interface {
	// ListConnections retrieves all platform connections for a user.
	// Returns empty slice if user has no connections.
	ListConnections(ctx context.Context, userID string) ([]*Connection, error)

	// GetConnection retrieves a single connection for a user and platform.
	// Returns ErrConnectionNotFound if no connection exists.
	GetConnection(ctx context.Context, userID, platform string) (*Connection, error)

	// InitiateOAuth generates an OAuth authorization URL for the platform.
	// The returned OAuthInfo includes the URL to redirect the user and state for validation.
	// Returns ErrInvalidPlatform if platform is not supported.
	// Returns ErrPlatformDisabled if platform OAuth is currently disabled.
	InitiateOAuth(ctx context.Context, userID, platform string) (*OAuthInfo, error)

	// HandleOAuthCallback processes the OAuth callback and stores credentials.
	// Validates the state parameter against the original OAuth request.
	// Returns ErrOAuthStateInvalid if state doesn't match or is expired.
	// Returns ErrOAuthCodeInvalid if the authorization code is invalid.
	HandleOAuthCallback(ctx context.Context, userID, platform, code, state string) (*OAuthResult, error)

	// Disconnect removes a platform connection for a user.
	// Deletes stored credentials and revokes platform access if possible.
	// Returns ErrConnectionNotFound if no connection exists.
	Disconnect(ctx context.Context, userID, platform string) error

	// TestConnection verifies that a connection is working.
	// Makes a lightweight API call to the platform to verify credentials.
	// Returns ErrConnectionNotFound if no connection exists.
	TestConnection(ctx context.Context, userID, platform string) (*ConnectionTestResult, error)

	// GetRateLimits retrieves current rate limit information for a platform.
	// Returns ErrConnectionNotFound if no connection exists.
	GetRateLimits(ctx context.Context, userID, platform string) (*RateLimitInfo, error)
}
