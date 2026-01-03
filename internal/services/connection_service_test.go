package services

import (
	"context"
	"errors"
	"testing"
	"time"
)

// =============================================================================
// ConnectionService Test Contracts
// These tests define the expected behavior of any ConnectionService implementation
// =============================================================================

// MockConnectionService implements ConnectionService for testing
type MockConnectionService struct {
	connections        map[string]map[string]*Connection // userID -> platform -> Connection
	oauthStates        map[string]*OAuthInfo              // state -> OAuthInfo
	testResults        map[string]*ConnectionTestResult   // platform -> result
	rateLimits         map[string]*RateLimitInfo          // platform -> limits
	disabledPlatforms  map[string]bool

	// Track method calls for verification
	disconnectCalls    []struct{ UserID, Platform string }
	callbackCalls      []struct{ UserID, Platform, Code, State string }
}

func NewMockConnectionService() *MockConnectionService {
	return &MockConnectionService{
		connections:       make(map[string]map[string]*Connection),
		oauthStates:       make(map[string]*OAuthInfo),
		testResults:       make(map[string]*ConnectionTestResult),
		rateLimits:        make(map[string]*RateLimitInfo),
		disabledPlatforms: make(map[string]bool),
	}
}

// AddConnection adds a connection to the mock store
func (m *MockConnectionService) AddConnection(c *Connection) {
	if m.connections[c.UserID] == nil {
		m.connections[c.UserID] = make(map[string]*Connection)
	}
	m.connections[c.UserID][c.Platform] = c
}

// SetTestResult sets the test result for a platform
func (m *MockConnectionService) SetTestResult(platform string, result *ConnectionTestResult) {
	m.testResults[platform] = result
}

// SetRateLimits sets rate limits for a platform
func (m *MockConnectionService) SetRateLimits(platform string, limits *RateLimitInfo) {
	m.rateLimits[platform] = limits
}

// DisablePlatform marks a platform as disabled for OAuth
func (m *MockConnectionService) DisablePlatform(platform string) {
	m.disabledPlatforms[platform] = true
}

// SetOAuthState sets an OAuth state for testing callbacks
func (m *MockConnectionService) SetOAuthState(state string, info *OAuthInfo) {
	m.oauthStates[state] = info
}

// ListConnections implements ConnectionService
func (m *MockConnectionService) ListConnections(ctx context.Context, userID string) ([]*Connection, error) {
	userConns := m.connections[userID]
	if userConns == nil {
		return []*Connection{}, nil
	}

	result := make([]*Connection, 0, len(userConns))
	for _, conn := range userConns {
		result = append(result, conn)
	}
	return result, nil
}

// GetConnection implements ConnectionService
func (m *MockConnectionService) GetConnection(ctx context.Context, userID, platform string) (*Connection, error) {
	if err := ValidatePlatform(platform); err != nil {
		return nil, err
	}

	userConns := m.connections[userID]
	if userConns == nil {
		return nil, ErrConnectionNotFound
	}

	conn, ok := userConns[platform]
	if !ok {
		return nil, ErrConnectionNotFound
	}
	return conn, nil
}

// InitiateOAuth implements ConnectionService
func (m *MockConnectionService) InitiateOAuth(ctx context.Context, userID, platform string) (*OAuthInfo, error) {
	if err := ValidatePlatform(platform); err != nil {
		return nil, err
	}

	if m.disabledPlatforms[platform] {
		return nil, ErrPlatformDisabled
	}

	// Generate OAuth info with platform-specific scopes
	scopes := getPlatformScopes(platform)
	state := "mock-state-" + userID + "-" + platform
	info := &OAuthInfo{
		AuthURL:     "https://oauth.example.com/authorize?platform=" + platform,
		State:       state,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Scopes:      scopes,
		RedirectURI: "https://app.example.com/oauth/callback",
	}
	m.oauthStates[state] = info
	return info, nil
}

// HandleOAuthCallback implements ConnectionService
func (m *MockConnectionService) HandleOAuthCallback(ctx context.Context, userID, platform, code, state string) (*OAuthResult, error) {
	m.callbackCalls = append(m.callbackCalls, struct{ UserID, Platform, Code, State string }{userID, platform, code, state})

	if err := ValidatePlatform(platform); err != nil {
		return nil, err
	}

	// Validate state
	storedInfo, ok := m.oauthStates[state]
	if !ok {
		return nil, ErrOAuthStateInvalid
	}
	if time.Now().After(storedInfo.ExpiresAt) {
		return nil, ErrOAuthStateInvalid
	}

	// Validate code
	if code == "" || code == "invalid" {
		return nil, ErrOAuthCodeInvalid
	}

	// Check if this is a new connection
	_, exists := m.connections[userID][platform]
	isNew := !exists

	// Create/update connection
	now := time.Now()
	expiresAt := now.Add(3600 * time.Second)
	conn := &Connection{
		UserID:         userID,
		Platform:       platform,
		Status:         ConnectionStatusConnected,
		PlatformUserID: "platform-user-123",
		DisplayName:    "Test User",
		Scopes:         storedInfo.Scopes,
		ConnectedAt:    &now,
		ExpiresAt:      &expiresAt,
	}
	m.AddConnection(conn)

	// Clean up used state
	delete(m.oauthStates, state)

	return &OAuthResult{
		Connection:      conn,
		IsNewConnection: isNew,
	}, nil
}

// Disconnect implements ConnectionService
func (m *MockConnectionService) Disconnect(ctx context.Context, userID, platform string) error {
	m.disconnectCalls = append(m.disconnectCalls, struct{ UserID, Platform string }{userID, platform})

	if err := ValidatePlatform(platform); err != nil {
		return err
	}

	userConns := m.connections[userID]
	if userConns == nil {
		return ErrConnectionNotFound
	}

	if _, ok := userConns[platform]; !ok {
		return ErrConnectionNotFound
	}

	delete(userConns, platform)
	return nil
}

// TestConnection implements ConnectionService
func (m *MockConnectionService) TestConnection(ctx context.Context, userID, platform string) (*ConnectionTestResult, error) {
	if err := ValidatePlatform(platform); err != nil {
		return nil, err
	}

	// Check connection exists
	userConns := m.connections[userID]
	if userConns == nil || userConns[platform] == nil {
		return nil, ErrConnectionNotFound
	}

	// Return preset result or default success
	if result, ok := m.testResults[platform]; ok {
		return result, nil
	}

	return &ConnectionTestResult{
		Platform: platform,
		Success:  true,
		Latency:  50 * time.Millisecond,
		TestedAt: time.Now(),
	}, nil
}

// GetRateLimits implements ConnectionService
func (m *MockConnectionService) GetRateLimits(ctx context.Context, userID, platform string) (*RateLimitInfo, error) {
	if err := ValidatePlatform(platform); err != nil {
		return nil, err
	}

	// Check connection exists
	userConns := m.connections[userID]
	if userConns == nil || userConns[platform] == nil {
		return nil, ErrConnectionNotFound
	}

	// Return preset limits or default
	if limits, ok := m.rateLimits[platform]; ok {
		return limits, nil
	}

	return &RateLimitInfo{
		Limit:     100,
		Remaining: 95,
		ResetAt:   time.Now().Add(time.Hour),
	}, nil
}

// getPlatformScopes returns the OAuth scopes for a platform
func getPlatformScopes(platform string) []string {
	switch platform {
	case PlatformLinkedIn:
		return []string{"r_liteprofile", "w_member_social"}
	case PlatformTwitter:
		return []string{"tweet.read", "tweet.write", "users.read"}
	case PlatformInstagram:
		return []string{"instagram_basic", "instagram_content_publish"}
	case PlatformYouTube:
		return []string{"youtube.upload", "youtube.readonly"}
	case PlatformBluesky:
		return []string{"atproto"} // Bluesky uses app passwords, not traditional OAuth
	case PlatformThreads:
		return []string{"threads_basic", "threads_content_publish"}
	case PlatformTikTok:
		return []string{"user.info.basic", "video.publish"}
	default:
		return []string{}
	}
}

// Verify MockConnectionService implements ConnectionService
var _ ConnectionService = (*MockConnectionService)(nil)

// =============================================================================
// Test Contracts
// =============================================================================

func TestConnectionService_ListConnections_Empty(t *testing.T) {
	svc := NewMockConnectionService()
	ctx := context.Background()

	connections, err := svc.ListConnections(ctx, "user-123")
	if err != nil {
		t.Fatalf("ListConnections() error = %v, want nil", err)
	}

	if len(connections) != 0 {
		t.Errorf("ListConnections() returned %d connections, want 0", len(connections))
	}
}

func TestConnectionService_ListConnections_Multiple(t *testing.T) {
	svc := NewMockConnectionService()
	ctx := context.Background()
	userID := "user-123"

	// Add connections with various statuses
	now := time.Now()
	expired := now.Add(-time.Hour)

	svc.AddConnection(&Connection{
		UserID:      userID,
		Platform:    PlatformLinkedIn,
		Status:      ConnectionStatusConnected,
		ConnectedAt: &now,
	})
	svc.AddConnection(&Connection{
		UserID:    userID,
		Platform:  PlatformTwitter,
		Status:    ConnectionStatusExpired,
		ExpiresAt: &expired,
	})
	svc.AddConnection(&Connection{
		UserID:   userID,
		Platform: PlatformInstagram,
		Status:   ConnectionStatusError,
		LastError: "token refresh failed",
	})

	connections, err := svc.ListConnections(ctx, userID)
	if err != nil {
		t.Fatalf("ListConnections() error = %v, want nil", err)
	}

	if len(connections) != 3 {
		t.Errorf("ListConnections() returned %d connections, want 3", len(connections))
	}

	// Verify we can find each status
	statusCounts := make(map[string]int)
	for _, conn := range connections {
		statusCounts[conn.Status]++
	}

	if statusCounts[ConnectionStatusConnected] != 1 {
		t.Error("Expected 1 connected connection")
	}
	if statusCounts[ConnectionStatusExpired] != 1 {
		t.Error("Expected 1 expired connection")
	}
	if statusCounts[ConnectionStatusError] != 1 {
		t.Error("Expected 1 error connection")
	}
}

func TestConnectionService_GetConnection_NotFound(t *testing.T) {
	svc := NewMockConnectionService()
	ctx := context.Background()

	_, err := svc.GetConnection(ctx, "user-123", PlatformLinkedIn)
	if !errors.Is(err, ErrConnectionNotFound) {
		t.Errorf("GetConnection() error = %v, want %v", err, ErrConnectionNotFound)
	}
}

func TestConnectionService_GetConnection_InvalidPlatform(t *testing.T) {
	svc := NewMockConnectionService()
	ctx := context.Background()

	_, err := svc.GetConnection(ctx, "user-123", "fakebook")
	if !errors.Is(err, ErrInvalidPlatform) {
		t.Errorf("GetConnection() error = %v, want %v", err, ErrInvalidPlatform)
	}
}

func TestConnectionService_InitiateOAuth_IncludesScopes(t *testing.T) {
	svc := NewMockConnectionService()
	ctx := context.Background()

	tests := []struct {
		platform      string
		expectScopes  []string
	}{
		{
			platform:     PlatformLinkedIn,
			expectScopes: []string{"r_liteprofile", "w_member_social"},
		},
		{
			platform:     PlatformTwitter,
			expectScopes: []string{"tweet.read", "tweet.write", "users.read"},
		},
		{
			platform:     PlatformInstagram,
			expectScopes: []string{"instagram_basic", "instagram_content_publish"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.platform, func(t *testing.T) {
			info, err := svc.InitiateOAuth(ctx, "user-123", tt.platform)
			if err != nil {
				t.Fatalf("InitiateOAuth() error = %v", err)
			}

			if info.AuthURL == "" {
				t.Error("InitiateOAuth() returned empty AuthURL")
			}
			if info.State == "" {
				t.Error("InitiateOAuth() returned empty State")
			}
			if info.ExpiresAt.IsZero() {
				t.Error("InitiateOAuth() returned zero ExpiresAt")
			}

			// Verify scopes are included
			if len(info.Scopes) != len(tt.expectScopes) {
				t.Errorf("InitiateOAuth() scopes = %v, want %v", info.Scopes, tt.expectScopes)
			}
			for i, scope := range info.Scopes {
				if scope != tt.expectScopes[i] {
					t.Errorf("InitiateOAuth() scope[%d] = %q, want %q", i, scope, tt.expectScopes[i])
				}
			}
		})
	}
}

func TestConnectionService_InitiateOAuth_InvalidPlatform(t *testing.T) {
	svc := NewMockConnectionService()
	ctx := context.Background()

	_, err := svc.InitiateOAuth(ctx, "user-123", "fakebook")
	if !errors.Is(err, ErrInvalidPlatform) {
		t.Errorf("InitiateOAuth() error = %v, want %v", err, ErrInvalidPlatform)
	}
}

func TestConnectionService_InitiateOAuth_DisabledPlatform(t *testing.T) {
	svc := NewMockConnectionService()
	svc.DisablePlatform(PlatformLinkedIn)
	ctx := context.Background()

	_, err := svc.InitiateOAuth(ctx, "user-123", PlatformLinkedIn)
	if !errors.Is(err, ErrPlatformDisabled) {
		t.Errorf("InitiateOAuth() error = %v, want %v", err, ErrPlatformDisabled)
	}
}

func TestConnectionService_HandleOAuthCallback_StoresCredentials(t *testing.T) {
	svc := NewMockConnectionService()
	ctx := context.Background()
	userID := "user-123"

	// First initiate OAuth to get a valid state
	info, err := svc.InitiateOAuth(ctx, userID, PlatformLinkedIn)
	if err != nil {
		t.Fatalf("InitiateOAuth() error = %v", err)
	}

	// Handle callback with valid code
	result, err := svc.HandleOAuthCallback(ctx, userID, PlatformLinkedIn, "valid-code-123", info.State)
	if err != nil {
		t.Fatalf("HandleOAuthCallback() error = %v", err)
	}

	// Verify connection was created
	if result.Connection == nil {
		t.Fatal("HandleOAuthCallback() returned nil connection")
	}
	if result.Connection.Status != ConnectionStatusConnected {
		t.Errorf("Connection status = %q, want %q", result.Connection.Status, ConnectionStatusConnected)
	}
	if result.Connection.UserID != userID {
		t.Errorf("Connection userID = %q, want %q", result.Connection.UserID, userID)
	}
	if result.Connection.Platform != PlatformLinkedIn {
		t.Errorf("Connection platform = %q, want %q", result.Connection.Platform, PlatformLinkedIn)
	}
	if !result.IsNewConnection {
		t.Error("Expected IsNewConnection to be true for first connection")
	}

	// Verify connection is now stored
	conn, err := svc.GetConnection(ctx, userID, PlatformLinkedIn)
	if err != nil {
		t.Fatalf("GetConnection() after callback error = %v", err)
	}
	if conn.Status != ConnectionStatusConnected {
		t.Errorf("Stored connection status = %q, want %q", conn.Status, ConnectionStatusConnected)
	}
}

func TestConnectionService_HandleOAuthCallback_InvalidState(t *testing.T) {
	svc := NewMockConnectionService()
	ctx := context.Background()

	_, err := svc.HandleOAuthCallback(ctx, "user-123", PlatformLinkedIn, "code", "invalid-state")
	if !errors.Is(err, ErrOAuthStateInvalid) {
		t.Errorf("HandleOAuthCallback() error = %v, want %v", err, ErrOAuthStateInvalid)
	}
}

func TestConnectionService_HandleOAuthCallback_InvalidCode(t *testing.T) {
	svc := NewMockConnectionService()
	ctx := context.Background()
	userID := "user-123"

	// First initiate OAuth to get a valid state
	info, err := svc.InitiateOAuth(ctx, userID, PlatformLinkedIn)
	if err != nil {
		t.Fatalf("InitiateOAuth() error = %v", err)
	}

	// Handle callback with invalid code
	_, err = svc.HandleOAuthCallback(ctx, userID, PlatformLinkedIn, "invalid", info.State)
	if !errors.Is(err, ErrOAuthCodeInvalid) {
		t.Errorf("HandleOAuthCallback() error = %v, want %v", err, ErrOAuthCodeInvalid)
	}
}

func TestConnectionService_Disconnect_RemovesCredentials(t *testing.T) {
	svc := NewMockConnectionService()
	ctx := context.Background()
	userID := "user-123"

	// Add a connection first
	now := time.Now()
	svc.AddConnection(&Connection{
		UserID:      userID,
		Platform:    PlatformLinkedIn,
		Status:      ConnectionStatusConnected,
		ConnectedAt: &now,
	})

	// Verify connection exists
	_, err := svc.GetConnection(ctx, userID, PlatformLinkedIn)
	if err != nil {
		t.Fatalf("GetConnection() before disconnect error = %v", err)
	}

	// Disconnect
	err = svc.Disconnect(ctx, userID, PlatformLinkedIn)
	if err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}

	// Verify connection is removed
	_, err = svc.GetConnection(ctx, userID, PlatformLinkedIn)
	if !errors.Is(err, ErrConnectionNotFound) {
		t.Errorf("GetConnection() after disconnect error = %v, want %v", err, ErrConnectionNotFound)
	}

	// Verify disconnect was called
	if len(svc.disconnectCalls) != 1 {
		t.Errorf("Expected 1 disconnect call, got %d", len(svc.disconnectCalls))
	}
	if svc.disconnectCalls[0].UserID != userID {
		t.Errorf("Disconnect call userID = %q, want %q", svc.disconnectCalls[0].UserID, userID)
	}
	if svc.disconnectCalls[0].Platform != PlatformLinkedIn {
		t.Errorf("Disconnect call platform = %q, want %q", svc.disconnectCalls[0].Platform, PlatformLinkedIn)
	}
}

func TestConnectionService_Disconnect_NotFound(t *testing.T) {
	svc := NewMockConnectionService()
	ctx := context.Background()

	err := svc.Disconnect(ctx, "user-123", PlatformLinkedIn)
	if !errors.Is(err, ErrConnectionNotFound) {
		t.Errorf("Disconnect() error = %v, want %v", err, ErrConnectionNotFound)
	}
}

func TestConnectionService_TestConnection_UsesPlatformClient(t *testing.T) {
	svc := NewMockConnectionService()
	ctx := context.Background()
	userID := "user-123"

	// Add a connection
	now := time.Now()
	svc.AddConnection(&Connection{
		UserID:      userID,
		Platform:    PlatformLinkedIn,
		Status:      ConnectionStatusConnected,
		ConnectedAt: &now,
	})

	// Set a specific test result
	svc.SetTestResult(PlatformLinkedIn, &ConnectionTestResult{
		Platform: PlatformLinkedIn,
		Success:  true,
		Latency:  75 * time.Millisecond,
		TestedAt: time.Now(),
	})

	result, err := svc.TestConnection(ctx, userID, PlatformLinkedIn)
	if err != nil {
		t.Fatalf("TestConnection() error = %v", err)
	}

	if !result.Success {
		t.Error("TestConnection() Success = false, want true")
	}
	if result.Latency != 75*time.Millisecond {
		t.Errorf("TestConnection() Latency = %v, want %v", result.Latency, 75*time.Millisecond)
	}
	if result.TestedAt.IsZero() {
		t.Error("TestConnection() TestedAt is zero")
	}
}

func TestConnectionService_TestConnection_Failure(t *testing.T) {
	svc := NewMockConnectionService()
	ctx := context.Background()
	userID := "user-123"

	// Add a connection
	now := time.Now()
	svc.AddConnection(&Connection{
		UserID:      userID,
		Platform:    PlatformTwitter,
		Status:      ConnectionStatusConnected,
		ConnectedAt: &now,
	})

	// Set a failing test result
	svc.SetTestResult(PlatformTwitter, &ConnectionTestResult{
		Platform: PlatformTwitter,
		Success:  false,
		Latency:  100 * time.Millisecond,
		TestedAt: time.Now(),
		Error:    "API returned 401 Unauthorized",
	})

	result, err := svc.TestConnection(ctx, userID, PlatformTwitter)
	if err != nil {
		t.Fatalf("TestConnection() error = %v", err)
	}

	if result.Success {
		t.Error("TestConnection() Success = true, want false")
	}
	if result.Error == "" {
		t.Error("TestConnection() Error is empty, expected error message")
	}
}

func TestConnectionService_TestConnection_NotFound(t *testing.T) {
	svc := NewMockConnectionService()
	ctx := context.Background()

	_, err := svc.TestConnection(ctx, "user-123", PlatformLinkedIn)
	if !errors.Is(err, ErrConnectionNotFound) {
		t.Errorf("TestConnection() error = %v, want %v", err, ErrConnectionNotFound)
	}
}

func TestConnectionService_GetRateLimits_Aggregation(t *testing.T) {
	svc := NewMockConnectionService()
	ctx := context.Background()
	userID := "user-123"

	// Add connections for multiple platforms
	now := time.Now()
	svc.AddConnection(&Connection{
		UserID:      userID,
		Platform:    PlatformLinkedIn,
		Status:      ConnectionStatusConnected,
		ConnectedAt: &now,
	})
	svc.AddConnection(&Connection{
		UserID:      userID,
		Platform:    PlatformTwitter,
		Status:      ConnectionStatusConnected,
		ConnectedAt: &now,
	})

	// Set different rate limits for each platform
	resetTime := time.Now().Add(time.Hour)
	svc.SetRateLimits(PlatformLinkedIn, &RateLimitInfo{
		Limit:     100,
		Remaining: 50,
		ResetAt:   resetTime,
	})
	svc.SetRateLimits(PlatformTwitter, &RateLimitInfo{
		Limit:     300,
		Remaining: 250,
		ResetAt:   resetTime,
	})

	// Test LinkedIn limits
	linkedInLimits, err := svc.GetRateLimits(ctx, userID, PlatformLinkedIn)
	if err != nil {
		t.Fatalf("GetRateLimits(linkedin) error = %v", err)
	}
	if linkedInLimits.Limit != 100 {
		t.Errorf("LinkedIn Limit = %d, want 100", linkedInLimits.Limit)
	}
	if linkedInLimits.Remaining != 50 {
		t.Errorf("LinkedIn Remaining = %d, want 50", linkedInLimits.Remaining)
	}

	// Test Twitter limits
	twitterLimits, err := svc.GetRateLimits(ctx, userID, PlatformTwitter)
	if err != nil {
		t.Fatalf("GetRateLimits(twitter) error = %v", err)
	}
	if twitterLimits.Limit != 300 {
		t.Errorf("Twitter Limit = %d, want 300", twitterLimits.Limit)
	}
	if twitterLimits.Remaining != 250 {
		t.Errorf("Twitter Remaining = %d, want 250", twitterLimits.Remaining)
	}
}

func TestConnectionService_GetRateLimits_NotFound(t *testing.T) {
	svc := NewMockConnectionService()
	ctx := context.Background()

	_, err := svc.GetRateLimits(ctx, "user-123", PlatformLinkedIn)
	if !errors.Is(err, ErrConnectionNotFound) {
		t.Errorf("GetRateLimits() error = %v, want %v", err, ErrConnectionNotFound)
	}
}

func TestConnection_IsHealthy(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)

	tests := []struct {
		name string
		conn Connection
		want bool
	}{
		{
			name: "connected with future expiry is healthy",
			conn: Connection{Status: ConnectionStatusConnected, ExpiresAt: &future},
			want: true,
		},
		{
			name: "connected with no expiry is healthy",
			conn: Connection{Status: ConnectionStatusConnected, ExpiresAt: nil},
			want: true,
		},
		{
			name: "connected but expired is not healthy",
			conn: Connection{Status: ConnectionStatusConnected, ExpiresAt: &past},
			want: false,
		},
		{
			name: "disconnected is not healthy",
			conn: Connection{Status: ConnectionStatusDisconnected},
			want: false,
		},
		{
			name: "expired status is not healthy",
			conn: Connection{Status: ConnectionStatusExpired},
			want: false,
		},
		{
			name: "error status is not healthy",
			conn: Connection{Status: ConnectionStatusError},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.conn.IsHealthy(); got != tt.want {
				t.Errorf("IsHealthy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConnectionService_HandleOAuthCallback_UpdatesExistingConnection(t *testing.T) {
	svc := NewMockConnectionService()
	ctx := context.Background()
	userID := "user-123"

	// Add an existing connection (maybe expired)
	oldTime := time.Now().Add(-time.Hour)
	svc.AddConnection(&Connection{
		UserID:      userID,
		Platform:    PlatformLinkedIn,
		Status:      ConnectionStatusExpired,
		ConnectedAt: &oldTime,
	})

	// Initiate new OAuth to reconnect
	info, err := svc.InitiateOAuth(ctx, userID, PlatformLinkedIn)
	if err != nil {
		t.Fatalf("InitiateOAuth() error = %v", err)
	}

	// Handle callback
	result, err := svc.HandleOAuthCallback(ctx, userID, PlatformLinkedIn, "valid-code", info.State)
	if err != nil {
		t.Fatalf("HandleOAuthCallback() error = %v", err)
	}

	// Should indicate this is NOT a new connection (it's a reconnection)
	if result.IsNewConnection {
		t.Error("Expected IsNewConnection to be false for reconnection")
	}

	// Connection should now be connected
	if result.Connection.Status != ConnectionStatusConnected {
		t.Errorf("Connection status = %q, want %q", result.Connection.Status, ConnectionStatusConnected)
	}
}

// =============================================================================
// ConnectionServiceImpl Tests
// =============================================================================

// MockCredentialStore implements CredentialStore for testing
type MockCredentialStore struct {
	credentials map[string]map[string]*PlatformCredentials // userID -> platform -> creds
	saveError   error
	deleteError error
}

func NewMockCredentialStore() *MockCredentialStore {
	return &MockCredentialStore{
		credentials: make(map[string]map[string]*PlatformCredentials),
	}
}

func (m *MockCredentialStore) SetSaveError(err error) {
	m.saveError = err
}

func (m *MockCredentialStore) SetDeleteError(err error) {
	m.deleteError = err
}

func (m *MockCredentialStore) GetCredentials(ctx context.Context, userID, platform string) (*PlatformCredentials, error) {
	if userCreds, ok := m.credentials[userID]; ok {
		if cred, ok := userCreds[platform]; ok {
			return cred, nil
		}
	}
	return nil, ErrCredentialsNotFound
}

func (m *MockCredentialStore) SaveCredentials(ctx context.Context, creds *PlatformCredentials) error {
	if m.saveError != nil {
		return m.saveError
	}
	if m.credentials[creds.UserID] == nil {
		m.credentials[creds.UserID] = make(map[string]*PlatformCredentials)
	}
	m.credentials[creds.UserID][creds.Platform] = creds
	return nil
}

func (m *MockCredentialStore) DeleteCredentials(ctx context.Context, userID, platform string) error {
	if m.deleteError != nil {
		return m.deleteError
	}
	if userCreds, ok := m.credentials[userID]; ok {
		delete(userCreds, platform)
	}
	return nil
}

func (m *MockCredentialStore) GetCredentialsForUser(ctx context.Context, userID string) ([]*PlatformCredentials, error) {
	userCreds := m.credentials[userID]
	if userCreds == nil {
		return []*PlatformCredentials{}, nil
	}
	result := make([]*PlatformCredentials, 0, len(userCreds))
	for _, cred := range userCreds {
		result = append(result, cred)
	}
	return result, nil
}

func (m *MockCredentialStore) GetExpiringCredentials(ctx context.Context, within time.Duration) ([]*PlatformCredentials, error) {
	var result []*PlatformCredentials
	threshold := time.Now().Add(within)
	for _, userCreds := range m.credentials {
		for _, cred := range userCreds {
			if cred.TokenExpiresAt != nil && cred.TokenExpiresAt.Before(threshold) {
				result = append(result, cred)
			}
		}
	}
	return result, nil
}

func (m *MockCredentialStore) UpdateTokens(ctx context.Context, userID, platform, accessToken, refreshToken string, expiresAt *time.Time) error {
	if userCreds, ok := m.credentials[userID]; ok {
		if cred, ok := userCreds[platform]; ok {
			cred.AccessToken = accessToken
			cred.RefreshToken = refreshToken
			cred.TokenExpiresAt = expiresAt
			cred.UpdatedAt = time.Now()
			return nil
		}
	}
	return ErrCredentialsNotFound
}

// MockOAuthProvider implements OAuthProvider for testing
type MockOAuthProvider struct {
	platform      string
	scopes        []string
	exchangeError error
	tokens        *OAuthTokens
}

func NewMockOAuthProvider(platform string) *MockOAuthProvider {
	return &MockOAuthProvider{
		platform: platform,
		scopes:   getPlatformScopes(platform),
		tokens: &OAuthTokens{
			AccessToken:    "mock-access-token",
			RefreshToken:   "mock-refresh-token",
			PlatformUserID: "mock-platform-user",
			Scopes:         "scope1,scope2",
		},
	}
}

func (m *MockOAuthProvider) SetExchangeError(err error) {
	m.exchangeError = err
}

func (m *MockOAuthProvider) SetTokens(tokens *OAuthTokens) {
	m.tokens = tokens
}

func (m *MockOAuthProvider) Platform() string {
	return m.platform
}

func (m *MockOAuthProvider) GetAuthURL(state, redirectURL string) string {
	return "https://oauth.example.com/authorize?platform=" + m.platform + "&state=" + state + "&redirect_uri=" + redirectURL
}

func (m *MockOAuthProvider) ExchangeCode(ctx context.Context, code, redirectURL string) (*OAuthTokens, error) {
	if m.exchangeError != nil {
		return nil, m.exchangeError
	}
	if code == "" || code == "invalid" {
		return nil, errors.New("invalid code")
	}
	return m.tokens, nil
}

func (m *MockOAuthProvider) RefreshTokens(ctx context.Context, refreshToken string) (*OAuthTokens, error) {
	if refreshToken == "" {
		return nil, errors.New("no refresh token")
	}
	return m.tokens, nil
}

func (m *MockOAuthProvider) GetRequiredScopes() []string {
	return m.scopes
}

// Test ConnectionServiceImpl.ListConnections
func TestConnectionServiceImpl_ListConnections(t *testing.T) {
	credStore := NewMockCredentialStore()
	svc := NewConnectionService(ConnectionServiceConfig{
		CredentialStore: credStore,
	})

	ctx := context.Background()
	userID := "user-123"

	// Test empty list
	conns, err := svc.ListConnections(ctx, userID)
	if err != nil {
		t.Fatalf("ListConnections() error = %v", err)
	}
	if len(conns) != 0 {
		t.Errorf("ListConnections() = %d, want 0", len(conns))
	}

	// Add credentials
	now := time.Now()
	future := now.Add(time.Hour)
	credStore.SaveCredentials(ctx, &PlatformCredentials{
		UserID:         userID,
		Platform:       PlatformLinkedIn,
		AccessToken:    "token1",
		TokenExpiresAt: &future,
	})
	credStore.SaveCredentials(ctx, &PlatformCredentials{
		UserID:         userID,
		Platform:       PlatformTwitter,
		AccessToken:    "token2",
		TokenExpiresAt: &future,
	})

	// Test with credentials
	conns, err = svc.ListConnections(ctx, userID)
	if err != nil {
		t.Fatalf("ListConnections() error = %v", err)
	}
	if len(conns) != 2 {
		t.Errorf("ListConnections() = %d, want 2", len(conns))
	}
}

// Test ConnectionServiceImpl.GetConnection
func TestConnectionServiceImpl_GetConnection(t *testing.T) {
	credStore := NewMockCredentialStore()
	svc := NewConnectionService(ConnectionServiceConfig{
		CredentialStore: credStore,
	})

	ctx := context.Background()
	userID := "user-123"

	// Test not found
	_, err := svc.GetConnection(ctx, userID, PlatformLinkedIn)
	if !errors.Is(err, ErrConnectionNotFound) {
		t.Errorf("GetConnection() error = %v, want %v", err, ErrConnectionNotFound)
	}

	// Test invalid platform
	_, err = svc.GetConnection(ctx, userID, "invalid")
	if !errors.Is(err, ErrInvalidPlatform) {
		t.Errorf("GetConnection() error = %v, want %v", err, ErrInvalidPlatform)
	}

	// Add credentials and test success
	now := time.Now()
	future := now.Add(time.Hour)
	credStore.SaveCredentials(ctx, &PlatformCredentials{
		UserID:         userID,
		Platform:       PlatformLinkedIn,
		AccessToken:    "token1",
		TokenExpiresAt: &future,
		PlatformUserID: "linkedin-user-123",
	})

	conn, err := svc.GetConnection(ctx, userID, PlatformLinkedIn)
	if err != nil {
		t.Fatalf("GetConnection() error = %v", err)
	}
	if conn.Platform != PlatformLinkedIn {
		t.Errorf("Platform = %q, want %q", conn.Platform, PlatformLinkedIn)
	}
	if conn.Status != ConnectionStatusConnected {
		t.Errorf("Status = %q, want %q", conn.Status, ConnectionStatusConnected)
	}
	if conn.PlatformUserID != "linkedin-user-123" {
		t.Errorf("PlatformUserID = %q, want %q", conn.PlatformUserID, "linkedin-user-123")
	}
}

// Test ConnectionServiceImpl.InitiateOAuth
func TestConnectionServiceImpl_InitiateOAuth(t *testing.T) {
	credStore := NewMockCredentialStore()
	provider := NewMockOAuthProvider(PlatformLinkedIn)
	svc := NewConnectionService(ConnectionServiceConfig{
		CredentialStore: credStore,
		OAuthProviders:  map[string]OAuthProvider{PlatformLinkedIn: provider},
		RedirectURI:     "https://app.example.com/callback",
	})

	ctx := context.Background()
	userID := "user-123"

	// Test successful initiation
	info, err := svc.InitiateOAuth(ctx, userID, PlatformLinkedIn)
	if err != nil {
		t.Fatalf("InitiateOAuth() error = %v", err)
	}
	if info.AuthURL == "" {
		t.Error("AuthURL is empty")
	}
	if info.State == "" {
		t.Error("State is empty")
	}
	if len(info.State) != 64 { // 32 bytes hex encoded
		t.Errorf("State length = %d, want 64", len(info.State))
	}
	if info.RedirectURI != "https://app.example.com/callback" {
		t.Errorf("RedirectURI = %q, want %q", info.RedirectURI, "https://app.example.com/callback")
	}

	// Test platform with no provider (disabled)
	_, err = svc.InitiateOAuth(ctx, userID, PlatformTwitter)
	if !errors.Is(err, ErrPlatformDisabled) {
		t.Errorf("InitiateOAuth() error = %v, want %v", err, ErrPlatformDisabled)
	}

	// Test invalid platform
	_, err = svc.InitiateOAuth(ctx, userID, "invalid")
	if !errors.Is(err, ErrInvalidPlatform) {
		t.Errorf("InitiateOAuth() error = %v, want %v", err, ErrInvalidPlatform)
	}
}

// Test ConnectionServiceImpl.HandleOAuthCallback
func TestConnectionServiceImpl_HandleOAuthCallback(t *testing.T) {
	credStore := NewMockCredentialStore()
	provider := NewMockOAuthProvider(PlatformLinkedIn)
	expiry := time.Now().Add(time.Hour)
	provider.SetTokens(&OAuthTokens{
		AccessToken:    "new-access-token",
		RefreshToken:   "new-refresh-token",
		ExpiresAt:      &expiry,
		PlatformUserID: "linkedin-user-456",
		Scopes:         "r_liteprofile,w_member_social",
	})
	svc := NewConnectionService(ConnectionServiceConfig{
		CredentialStore: credStore,
		OAuthProviders:  map[string]OAuthProvider{PlatformLinkedIn: provider},
		RedirectURI:     "https://app.example.com/callback",
	})

	ctx := context.Background()
	userID := "user-123"

	// First initiate OAuth
	info, err := svc.InitiateOAuth(ctx, userID, PlatformLinkedIn)
	if err != nil {
		t.Fatalf("InitiateOAuth() error = %v", err)
	}

	// Test successful callback
	result, err := svc.HandleOAuthCallback(ctx, userID, PlatformLinkedIn, "valid-code", info.State)
	if err != nil {
		t.Fatalf("HandleOAuthCallback() error = %v", err)
	}
	if !result.IsNewConnection {
		t.Error("Expected IsNewConnection = true")
	}
	if result.Connection.Status != ConnectionStatusConnected {
		t.Errorf("Status = %q, want %q", result.Connection.Status, ConnectionStatusConnected)
	}
	if result.Connection.PlatformUserID != "linkedin-user-456" {
		t.Errorf("PlatformUserID = %q, want %q", result.Connection.PlatformUserID, "linkedin-user-456")
	}

	// Verify credentials were stored
	creds, err := credStore.GetCredentials(ctx, userID, PlatformLinkedIn)
	if err != nil {
		t.Fatalf("GetCredentials() error = %v", err)
	}
	if creds.AccessToken != "new-access-token" {
		t.Errorf("AccessToken = %q, want %q", creds.AccessToken, "new-access-token")
	}
}

// Test ConnectionServiceImpl.HandleOAuthCallback with invalid state
func TestConnectionServiceImpl_HandleOAuthCallback_InvalidState(t *testing.T) {
	credStore := NewMockCredentialStore()
	provider := NewMockOAuthProvider(PlatformLinkedIn)
	svc := NewConnectionService(ConnectionServiceConfig{
		CredentialStore: credStore,
		OAuthProviders:  map[string]OAuthProvider{PlatformLinkedIn: provider},
	})

	ctx := context.Background()

	// Test with invalid state
	_, err := svc.HandleOAuthCallback(ctx, "user-123", PlatformLinkedIn, "code", "invalid-state")
	if !errors.Is(err, ErrOAuthStateInvalid) {
		t.Errorf("HandleOAuthCallback() error = %v, want %v", err, ErrOAuthStateInvalid)
	}
}

// Test ConnectionServiceImpl.HandleOAuthCallback with expired state
func TestConnectionServiceImpl_HandleOAuthCallback_ExpiredState(t *testing.T) {
	credStore := NewMockCredentialStore()
	provider := NewMockOAuthProvider(PlatformLinkedIn)
	svc := NewConnectionService(ConnectionServiceConfig{
		CredentialStore: credStore,
		OAuthProviders:  map[string]OAuthProvider{PlatformLinkedIn: provider},
		StateTTL:        1 * time.Millisecond, // Very short TTL
	})

	ctx := context.Background()
	userID := "user-123"

	// Initiate OAuth
	info, err := svc.InitiateOAuth(ctx, userID, PlatformLinkedIn)
	if err != nil {
		t.Fatalf("InitiateOAuth() error = %v", err)
	}

	// Wait for state to expire
	time.Sleep(10 * time.Millisecond)

	// Try callback with expired state
	_, err = svc.HandleOAuthCallback(ctx, userID, PlatformLinkedIn, "code", info.State)
	if !errors.Is(err, ErrOAuthStateInvalid) {
		t.Errorf("HandleOAuthCallback() error = %v, want %v", err, ErrOAuthStateInvalid)
	}
}

// Test ConnectionServiceImpl.Disconnect
func TestConnectionServiceImpl_Disconnect(t *testing.T) {
	credStore := NewMockCredentialStore()
	svc := NewConnectionService(ConnectionServiceConfig{
		CredentialStore: credStore,
	})

	ctx := context.Background()
	userID := "user-123"

	// Test disconnect when not connected
	err := svc.Disconnect(ctx, userID, PlatformLinkedIn)
	if !errors.Is(err, ErrConnectionNotFound) {
		t.Errorf("Disconnect() error = %v, want %v", err, ErrConnectionNotFound)
	}

	// Add credentials
	credStore.SaveCredentials(ctx, &PlatformCredentials{
		UserID:      userID,
		Platform:    PlatformLinkedIn,
		AccessToken: "token",
	})

	// Test successful disconnect
	err = svc.Disconnect(ctx, userID, PlatformLinkedIn)
	if err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}

	// Verify credentials were deleted
	_, err = credStore.GetCredentials(ctx, userID, PlatformLinkedIn)
	if !errors.Is(err, ErrCredentialsNotFound) {
		t.Errorf("GetCredentials() error = %v, want %v", err, ErrCredentialsNotFound)
	}
}

// Test ConnectionServiceImpl.TestConnection without client factory
func TestConnectionServiceImpl_TestConnection_NoClientFactory(t *testing.T) {
	credStore := NewMockCredentialStore()
	svc := NewConnectionService(ConnectionServiceConfig{
		CredentialStore: credStore,
	})

	ctx := context.Background()
	userID := "user-123"

	// Test with no connection
	_, err := svc.TestConnection(ctx, userID, PlatformLinkedIn)
	if !errors.Is(err, ErrConnectionNotFound) {
		t.Errorf("TestConnection() error = %v, want %v", err, ErrConnectionNotFound)
	}

	// Add valid credentials
	future := time.Now().Add(time.Hour)
	credStore.SaveCredentials(ctx, &PlatformCredentials{
		UserID:         userID,
		Platform:       PlatformLinkedIn,
		AccessToken:    "token",
		TokenExpiresAt: &future,
	})

	// Test should succeed (just checks expiry without client factory)
	result, err := svc.TestConnection(ctx, userID, PlatformLinkedIn)
	if err != nil {
		t.Fatalf("TestConnection() error = %v", err)
	}
	if !result.Success {
		t.Error("Expected Success = true")
	}

	// Add expired credentials
	past := time.Now().Add(-time.Hour)
	credStore.SaveCredentials(ctx, &PlatformCredentials{
		UserID:         userID,
		Platform:       PlatformTwitter,
		AccessToken:    "expired-token",
		TokenExpiresAt: &past,
	})

	// Test should fail for expired token
	result, err = svc.TestConnection(ctx, userID, PlatformTwitter)
	if err != nil {
		t.Fatalf("TestConnection() error = %v", err)
	}
	if result.Success {
		t.Error("Expected Success = false for expired token")
	}
	if result.Error == "" {
		t.Error("Expected Error message for expired token")
	}
}

// Test ConnectionServiceImpl.GetRateLimits without client factory
func TestConnectionServiceImpl_GetRateLimits_NoClientFactory(t *testing.T) {
	credStore := NewMockCredentialStore()
	svc := NewConnectionService(ConnectionServiceConfig{
		CredentialStore: credStore,
	})

	ctx := context.Background()
	userID := "user-123"

	// Test with no connection
	_, err := svc.GetRateLimits(ctx, userID, PlatformLinkedIn)
	if !errors.Is(err, ErrConnectionNotFound) {
		t.Errorf("GetRateLimits() error = %v, want %v", err, ErrConnectionNotFound)
	}

	// Add credentials
	credStore.SaveCredentials(ctx, &PlatformCredentials{
		UserID:      userID,
		Platform:    PlatformLinkedIn,
		AccessToken: "token",
	})

	// Test should return default limits
	limits, err := svc.GetRateLimits(ctx, userID, PlatformLinkedIn)
	if err != nil {
		t.Fatalf("GetRateLimits() error = %v", err)
	}
	if limits.Limit != 100 {
		t.Errorf("Limit = %d, want 100", limits.Limit)
	}
	if limits.Remaining != 100 {
		t.Errorf("Remaining = %d, want 100", limits.Remaining)
	}
}

// Test expired credentials return ConnectionStatusExpired
func TestConnectionServiceImpl_ExpiredCredentials(t *testing.T) {
	credStore := NewMockCredentialStore()
	svc := NewConnectionService(ConnectionServiceConfig{
		CredentialStore: credStore,
	})

	ctx := context.Background()
	userID := "user-123"

	// Add expired credentials
	past := time.Now().Add(-time.Hour)
	credStore.SaveCredentials(ctx, &PlatformCredentials{
		UserID:         userID,
		Platform:       PlatformLinkedIn,
		AccessToken:    "expired-token",
		TokenExpiresAt: &past,
	})

	conn, err := svc.GetConnection(ctx, userID, PlatformLinkedIn)
	if err != nil {
		t.Fatalf("GetConnection() error = %v", err)
	}
	if conn.Status != ConnectionStatusExpired {
		t.Errorf("Status = %q, want %q", conn.Status, ConnectionStatusExpired)
	}
}
