package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"
)

// =============================================================================
// OAuthProvider Interface and Types (TB-CONN)
// =============================================================================

// OAuthTokens contains tokens returned from OAuth exchange
type OAuthTokens struct {
	AccessToken    string
	RefreshToken   string
	ExpiresAt      *time.Time
	PlatformUserID string
	Scopes         string
}

// OAuthProvider defines platform-specific OAuth operations
type OAuthProvider interface {
	// Platform returns the platform identifier
	Platform() string

	// GetAuthURL generates an OAuth authorization URL
	GetAuthURL(state, redirectURL string) string

	// ExchangeCode exchanges an authorization code for tokens
	ExchangeCode(ctx context.Context, code, redirectURL string) (*OAuthTokens, error)

	// RefreshTokens refreshes expired tokens
	RefreshTokens(ctx context.Context, refreshToken string) (*OAuthTokens, error)

	// GetRequiredScopes returns the OAuth scopes needed for posting
	GetRequiredScopes() []string
}

// SocialClientFactory creates SocialClient instances for platforms
type SocialClientFactory interface {
	CreateClient(ctx context.Context, platform string, creds *PlatformCredentials) (SocialClient, error)
}

// =============================================================================
// ConnectionServiceImpl Implementation
// =============================================================================

// ConnectionServiceImpl implements ConnectionService using CredentialStore and OAuthProviders
type ConnectionServiceImpl struct {
	credStore     CredentialStore
	oauthStates   map[string]*oauthStateEntry // state -> entry
	providers     map[string]OAuthProvider    // platform -> provider
	clientFactory SocialClientFactory
	redirectURI   string
	stateTTL      time.Duration
}

// oauthStateEntry stores OAuth state with metadata
type oauthStateEntry struct {
	UserID    string
	Platform  string
	Scopes    []string
	ExpiresAt time.Time
}

// ConnectionServiceConfig configures ConnectionServiceImpl
type ConnectionServiceConfig struct {
	CredentialStore CredentialStore
	OAuthProviders  map[string]OAuthProvider
	ClientFactory   SocialClientFactory
	RedirectURI     string
	StateTTL        time.Duration
}

// NewConnectionService creates a new ConnectionService implementation
func NewConnectionService(cfg ConnectionServiceConfig) *ConnectionServiceImpl {
	stateTTL := cfg.StateTTL
	if stateTTL == 0 {
		stateTTL = 10 * time.Minute
	}

	return &ConnectionServiceImpl{
		credStore:     cfg.CredentialStore,
		providers:     cfg.OAuthProviders,
		clientFactory: cfg.ClientFactory,
		oauthStates:   make(map[string]*oauthStateEntry),
		redirectURI:   cfg.RedirectURI,
		stateTTL:      stateTTL,
	}
}

// ListConnections retrieves all platform connections for a user
func (s *ConnectionServiceImpl) ListConnections(ctx context.Context, userID string) ([]*Connection, error) {
	creds, err := s.credStore.GetCredentialsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	connections := make([]*Connection, 0, len(creds))
	for _, cred := range creds {
		conn := s.credentialsToConnection(cred)
		connections = append(connections, conn)
	}

	return connections, nil
}

// GetConnection retrieves a single connection for a user and platform
func (s *ConnectionServiceImpl) GetConnection(ctx context.Context, userID, platform string) (*Connection, error) {
	if err := ValidatePlatform(platform); err != nil {
		return nil, err
	}

	cred, err := s.credStore.GetCredentials(ctx, userID, platform)
	if err != nil {
		if err == ErrCredentialsNotFound {
			return nil, ErrConnectionNotFound
		}
		return nil, err
	}

	return s.credentialsToConnection(cred), nil
}

// InitiateOAuth generates an OAuth authorization URL for the platform
func (s *ConnectionServiceImpl) InitiateOAuth(ctx context.Context, userID, platform string) (*OAuthInfo, error) {
	if err := ValidatePlatform(platform); err != nil {
		return nil, err
	}

	provider, ok := s.providers[platform]
	if !ok {
		return nil, ErrPlatformDisabled
	}

	// Generate cryptographically random state
	state, err := generateState()
	if err != nil {
		return nil, err
	}

	scopes := provider.GetRequiredScopes()
	expiresAt := time.Now().Add(s.stateTTL)

	// Store state for validation
	s.oauthStates[state] = &oauthStateEntry{
		UserID:    userID,
		Platform:  platform,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
	}

	authURL := provider.GetAuthURL(state, s.redirectURI)

	return &OAuthInfo{
		AuthURL:     authURL,
		State:       state,
		ExpiresAt:   expiresAt,
		Scopes:      scopes,
		RedirectURI: s.redirectURI,
	}, nil
}

// HandleOAuthCallback processes the OAuth callback and stores credentials
func (s *ConnectionServiceImpl) HandleOAuthCallback(ctx context.Context, userID, platform, code, state string) (*OAuthResult, error) {
	if err := ValidatePlatform(platform); err != nil {
		return nil, err
	}

	// Validate state
	entry, ok := s.oauthStates[state]
	if !ok {
		return nil, ErrOAuthStateInvalid
	}

	// Check state hasn't expired
	if time.Now().After(entry.ExpiresAt) {
		delete(s.oauthStates, state)
		return nil, ErrOAuthStateInvalid
	}

	// Verify state matches user and platform
	if entry.UserID != userID || entry.Platform != platform {
		return nil, ErrOAuthStateInvalid
	}

	// Clean up state (single use)
	delete(s.oauthStates, state)

	// Exchange code for tokens
	provider, ok := s.providers[platform]
	if !ok {
		return nil, ErrPlatformDisabled
	}

	tokens, err := provider.ExchangeCode(ctx, code, s.redirectURI)
	if err != nil {
		return nil, ErrOAuthCodeInvalid
	}

	// Check if connection already exists
	_, existingErr := s.credStore.GetCredentials(ctx, userID, platform)
	isNew := existingErr == ErrCredentialsNotFound

	// Save credentials
	now := time.Now()
	creds := &PlatformCredentials{
		UserID:         userID,
		Platform:       platform,
		AccessToken:    tokens.AccessToken,
		RefreshToken:   tokens.RefreshToken,
		TokenExpiresAt: tokens.ExpiresAt,
		PlatformUserID: tokens.PlatformUserID,
		Scopes:         tokens.Scopes,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.credStore.SaveCredentials(ctx, creds); err != nil {
		return nil, err
	}

	conn := s.credentialsToConnection(creds)
	conn.ConnectedAt = &now

	return &OAuthResult{
		Connection:      conn,
		IsNewConnection: isNew,
	}, nil
}

// Disconnect removes a platform connection for a user
func (s *ConnectionServiceImpl) Disconnect(ctx context.Context, userID, platform string) error {
	if err := ValidatePlatform(platform); err != nil {
		return err
	}

	// Verify connection exists first
	_, err := s.credStore.GetCredentials(ctx, userID, platform)
	if err != nil {
		if err == ErrCredentialsNotFound {
			return ErrConnectionNotFound
		}
		return err
	}

	return s.credStore.DeleteCredentials(ctx, userID, platform)
}

// TestConnection verifies that a connection is working
func (s *ConnectionServiceImpl) TestConnection(ctx context.Context, userID, platform string) (*ConnectionTestResult, error) {
	if err := ValidatePlatform(platform); err != nil {
		return nil, err
	}

	creds, err := s.credStore.GetCredentials(ctx, userID, platform)
	if err != nil {
		if err == ErrCredentialsNotFound {
			return nil, ErrConnectionNotFound
		}
		return nil, err
	}

	start := time.Now()
	result := &ConnectionTestResult{
		Platform: platform,
		TestedAt: start,
	}

	// If no client factory, just verify credentials exist and aren't expired
	if s.clientFactory == nil {
		result.Success = !creds.IsExpired()
		result.Latency = time.Since(start)
		if creds.IsExpired() {
			result.Error = "credentials expired"
		}
		return result, nil
	}

	// Create client and test with a validation call
	client, err := s.clientFactory.CreateClient(ctx, platform, creds)
	if err != nil {
		result.Success = false
		result.Latency = time.Since(start)
		result.Error = err.Error()
		return result, nil
	}

	// Use ValidateContent as a lightweight API test
	err = client.ValidateContent(PostContent{Text: "test"})
	result.Latency = time.Since(start)

	if err != nil {
		// Validation errors are expected, connection errors are not
		// Only report actual API/auth errors
		if isAuthError(err) {
			result.Success = false
			result.Error = err.Error()
		} else {
			result.Success = true
		}
	} else {
		result.Success = true
	}

	result.RateLimits = ptrRateLimitInfo(client.GetRateLimits())

	return result, nil
}

// GetRateLimits retrieves current rate limit information for a platform
func (s *ConnectionServiceImpl) GetRateLimits(ctx context.Context, userID, platform string) (*RateLimitInfo, error) {
	if err := ValidatePlatform(platform); err != nil {
		return nil, err
	}

	creds, err := s.credStore.GetCredentials(ctx, userID, platform)
	if err != nil {
		if err == ErrCredentialsNotFound {
			return nil, ErrConnectionNotFound
		}
		return nil, err
	}

	// If no client factory, return default limits
	if s.clientFactory == nil {
		return &RateLimitInfo{
			Limit:     100,
			Remaining: 100,
			ResetAt:   time.Now().Add(time.Hour),
		}, nil
	}

	client, err := s.clientFactory.CreateClient(ctx, platform, creds)
	if err != nil {
		return nil, err
	}

	limits := client.GetRateLimits()
	return &limits, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// credentialsToConnection converts PlatformCredentials to Connection
func (s *ConnectionServiceImpl) credentialsToConnection(cred *PlatformCredentials) *Connection {
	conn := &Connection{
		UserID:         cred.UserID,
		Platform:       cred.Platform,
		PlatformUserID: cred.PlatformUserID,
		Scopes:         splitScopes(cred.Scopes),
		ExpiresAt:      cred.TokenExpiresAt,
	}

	// Determine status based on token state
	if cred.IsExpired() {
		conn.Status = ConnectionStatusExpired
	} else {
		conn.Status = ConnectionStatusConnected
	}

	return conn
}

// generateState creates a cryptographically random state string
func generateState() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// splitScopes splits a comma-separated scope string into a slice
func splitScopes(scopes string) []string {
	if scopes == "" {
		return nil
	}
	parts := strings.Split(scopes, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// isAuthError checks if an error is an authentication/authorization error
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "401") ||
		strings.Contains(msg, "403") ||
		strings.Contains(msg, "unauthorized") ||
		strings.Contains(msg, "forbidden") ||
		strings.Contains(msg, "invalid token") ||
		strings.Contains(msg, "expired")
}

// ptrRateLimitInfo returns a pointer to RateLimitInfo
func ptrRateLimitInfo(r RateLimitInfo) *RateLimitInfo {
	return &r
}

// Verify ConnectionServiceImpl implements ConnectionService
var _ ConnectionService = (*ConnectionServiceImpl)(nil)
