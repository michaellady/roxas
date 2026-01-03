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
