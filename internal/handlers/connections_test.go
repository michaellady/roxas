package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mikelady/roxas/internal/auth"
	"github.com/mikelady/roxas/internal/services"
)

// =============================================================================
// Mock ConnectionService for testing
// =============================================================================

type MockConnectionService struct {
	connections     map[string]map[string]*services.Connection // userID -> platform -> connection
	oauthStates     map[string]*services.OAuthInfo
	testResults     map[string]*services.ConnectionTestResult
	rateLimits      map[string]*services.RateLimitInfo
	disabled        map[string]bool
	disconnectCalls []struct{ UserID, Platform string }
}

func NewMockConnectionService() *MockConnectionService {
	return &MockConnectionService{
		connections: make(map[string]map[string]*services.Connection),
		oauthStates: make(map[string]*services.OAuthInfo),
		testResults: make(map[string]*services.ConnectionTestResult),
		rateLimits:  make(map[string]*services.RateLimitInfo),
		disabled:    make(map[string]bool),
	}
}

func (m *MockConnectionService) AddConnection(conn *services.Connection) {
	if m.connections[conn.UserID] == nil {
		m.connections[conn.UserID] = make(map[string]*services.Connection)
	}
	m.connections[conn.UserID][conn.Platform] = conn
}

func (m *MockConnectionService) SetTestResult(platform string, result *services.ConnectionTestResult) {
	m.testResults[platform] = result
}

func (m *MockConnectionService) SetRateLimits(platform string, limits *services.RateLimitInfo) {
	m.rateLimits[platform] = limits
}

func (m *MockConnectionService) DisablePlatform(platform string) {
	m.disabled[platform] = true
}

func (m *MockConnectionService) ListConnections(ctx context.Context, userID string) ([]*services.Connection, error) {
	userConns := m.connections[userID]
	if userConns == nil {
		return []*services.Connection{}, nil
	}
	result := make([]*services.Connection, 0, len(userConns))
	for _, conn := range userConns {
		result = append(result, conn)
	}
	return result, nil
}

func (m *MockConnectionService) GetConnection(ctx context.Context, userID, platform string) (*services.Connection, error) {
	if err := services.ValidatePlatform(platform); err != nil {
		return nil, err
	}
	userConns := m.connections[userID]
	if userConns == nil {
		return nil, services.ErrConnectionNotFound
	}
	conn, ok := userConns[platform]
	if !ok {
		return nil, services.ErrConnectionNotFound
	}
	return conn, nil
}

func (m *MockConnectionService) InitiateOAuth(ctx context.Context, userID, platform string) (*services.OAuthInfo, error) {
	if err := services.ValidatePlatform(platform); err != nil {
		return nil, err
	}
	if m.disabled[platform] {
		return nil, services.ErrPlatformDisabled
	}
	state := "mock-state-" + userID + "-" + platform
	info := &services.OAuthInfo{
		AuthURL:   "https://oauth.example.com/authorize?platform=" + platform + "&state=" + state,
		State:     state,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	m.oauthStates[state] = info
	return info, nil
}

func (m *MockConnectionService) HandleOAuthCallback(ctx context.Context, userID, platform, code, state string) (*services.OAuthResult, error) {
	if err := services.ValidatePlatform(platform); err != nil {
		return nil, err
	}
	if _, ok := m.oauthStates[state]; !ok {
		return nil, services.ErrOAuthStateInvalid
	}
	if code == "" || code == "invalid" {
		return nil, services.ErrOAuthCodeInvalid
	}
	now := time.Now()
	conn := &services.Connection{
		UserID:      userID,
		Platform:    platform,
		Status:      services.ConnectionStatusConnected,
		ConnectedAt: &now,
	}
	m.AddConnection(conn)
	delete(m.oauthStates, state)
	return &services.OAuthResult{Connection: conn, IsNewConnection: true}, nil
}

func (m *MockConnectionService) Disconnect(ctx context.Context, userID, platform string) error {
	m.disconnectCalls = append(m.disconnectCalls, struct{ UserID, Platform string }{userID, platform})
	if err := services.ValidatePlatform(platform); err != nil {
		return err
	}
	userConns := m.connections[userID]
	if userConns == nil {
		return services.ErrConnectionNotFound
	}
	if _, ok := userConns[platform]; !ok {
		return services.ErrConnectionNotFound
	}
	delete(userConns, platform)
	return nil
}

func (m *MockConnectionService) TestConnection(ctx context.Context, userID, platform string) (*services.ConnectionTestResult, error) {
	if err := services.ValidatePlatform(platform); err != nil {
		return nil, err
	}
	userConns := m.connections[userID]
	if userConns == nil || userConns[platform] == nil {
		return nil, services.ErrConnectionNotFound
	}
	if result, ok := m.testResults[platform]; ok {
		return result, nil
	}
	return &services.ConnectionTestResult{
		Platform: platform,
		Success:  true,
		Latency:  50 * time.Millisecond,
		TestedAt: time.Now(),
	}, nil
}

func (m *MockConnectionService) GetRateLimits(ctx context.Context, userID, platform string) (*services.RateLimitInfo, error) {
	if err := services.ValidatePlatform(platform); err != nil {
		return nil, err
	}
	userConns := m.connections[userID]
	if userConns == nil || userConns[platform] == nil {
		return nil, services.ErrConnectionNotFound
	}
	if limits, ok := m.rateLimits[platform]; ok {
		return limits, nil
	}
	return &services.RateLimitInfo{
		Limit:     100,
		Remaining: 95,
		ResetAt:   time.Now().Add(time.Hour),
	}, nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func generateTestToken(userID, email string) string {
	token, _ := auth.GenerateToken(userID, email)
	return token
}

func addAuthCookie(req *http.Request, token string) {
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
}

func addAuthHeader(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
}

// =============================================================================
// Test: List Connections
// =============================================================================

func TestConnectionHandler_ListConnections_Unauthorized(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	rr := httptest.NewRecorder()

	handler.ListConnections(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}

	var resp ErrorResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Error != "unauthorized" {
		t.Errorf("Expected error 'unauthorized', got '%s'", resp.Error)
	}
}

func TestConnectionHandler_ListConnections_EmptyForNewUser(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	token := generateTestToken("user-123", "test@example.com")
	req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.ListConnections(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ConnectionListResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if len(resp.Connections) != 0 {
		t.Errorf("Expected 0 connections, got %d", len(resp.Connections))
	}
}

func TestConnectionHandler_ListConnections_ReturnsConnections(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	now := time.Now()
	userID := "user-123"

	// Add connections
	svc.AddConnection(&services.Connection{
		UserID:      userID,
		Platform:    "linkedin",
		Status:      services.ConnectionStatusConnected,
		DisplayName: "John Doe",
		ConnectedAt: &now,
	})
	svc.AddConnection(&services.Connection{
		UserID:   userID,
		Platform: "twitter",
		Status:   services.ConnectionStatusExpired,
	})

	token := generateTestToken(userID, "test@example.com")
	req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.ListConnections(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ConnectionListResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if len(resp.Connections) != 2 {
		t.Errorf("Expected 2 connections, got %d", len(resp.Connections))
	}

	// Verify statuses are correct
	statusCounts := make(map[string]int)
	for _, conn := range resp.Connections {
		statusCounts[conn.Status]++
	}
	if statusCounts[services.ConnectionStatusConnected] != 1 {
		t.Error("Expected 1 connected connection")
	}
	if statusCounts[services.ConnectionStatusExpired] != 1 {
		t.Error("Expected 1 expired connection")
	}
}

func TestConnectionHandler_ListConnections_WithBearerToken(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	token := generateTestToken("user-123", "test@example.com")
	req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	addAuthHeader(req, token)
	rr := httptest.NewRecorder()

	handler.ListConnections(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 with Bearer token, got %d", rr.Code)
	}
}

// =============================================================================
// Test: Get Single Connection
// =============================================================================

func TestConnectionHandler_GetConnection_Unauthorized(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	req := httptest.NewRequest(http.MethodGet, "/api/connections/linkedin", nil)
	rr := httptest.NewRecorder()

	handler.GetConnection(rr, req, "linkedin")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestConnectionHandler_GetConnection_NotFound(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	token := generateTestToken("user-123", "test@example.com")
	req := httptest.NewRequest(http.MethodGet, "/api/connections/linkedin", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.GetConnection(rr, req, "linkedin")

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestConnectionHandler_GetConnection_InvalidPlatform(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	token := generateTestToken("user-123", "test@example.com")
	req := httptest.NewRequest(http.MethodGet, "/api/connections/fakebook", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.GetConnection(rr, req, "fakebook")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid platform, got %d", rr.Code)
	}
}

func TestConnectionHandler_GetConnection_Success(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	userID := "user-123"
	now := time.Now()
	svc.AddConnection(&services.Connection{
		UserID:      userID,
		Platform:    "linkedin",
		Status:      services.ConnectionStatusConnected,
		DisplayName: "John Doe",
		ProfileURL:  "https://linkedin.com/in/johndoe",
		ConnectedAt: &now,
	})

	token := generateTestToken(userID, "test@example.com")
	req := httptest.NewRequest(http.MethodGet, "/api/connections/linkedin", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.GetConnection(rr, req, "linkedin")

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ConnectionDetailResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Connection.Platform != "linkedin" {
		t.Errorf("Expected platform 'linkedin', got '%s'", resp.Connection.Platform)
	}
	if resp.Connection.DisplayName != "John Doe" {
		t.Errorf("Expected display name 'John Doe', got '%s'", resp.Connection.DisplayName)
	}
	if resp.RateLimits == nil {
		t.Error("Expected rate limits to be included")
	}
}

// =============================================================================
// Test: Connect (Initiate OAuth)
// =============================================================================

func TestConnectionHandler_Connect_Unauthorized(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	req := httptest.NewRequest(http.MethodPost, "/api/connections/linkedin/connect", nil)
	rr := httptest.NewRecorder()

	handler.Connect(rr, req, "linkedin")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestConnectionHandler_Connect_InvalidPlatform(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	token := generateTestToken("user-123", "test@example.com")
	req := httptest.NewRequest(http.MethodPost, "/api/connections/fakebook/connect", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.Connect(rr, req, "fakebook")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

func TestConnectionHandler_Connect_PlatformDisabled(t *testing.T) {
	svc := NewMockConnectionService()
	svc.DisablePlatform("linkedin")
	handler := NewConnectionHandler(svc, "https://app.example.com")

	token := generateTestToken("user-123", "test@example.com")
	req := httptest.NewRequest(http.MethodPost, "/api/connections/linkedin/connect", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.Connect(rr, req, "linkedin")

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503 for disabled platform, got %d", rr.Code)
	}
}

func TestConnectionHandler_Connect_ReturnsOAuthURL(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	token := generateTestToken("user-123", "test@example.com")
	req := httptest.NewRequest(http.MethodPost, "/api/connections/linkedin/connect", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.Connect(rr, req, "linkedin")

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ConnectResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.AuthURL == "" {
		t.Error("Expected non-empty auth_url")
	}
	if resp.AuthURL[0:8] != "https://" {
		t.Errorf("Expected auth_url to be HTTPS, got '%s'", resp.AuthURL)
	}
}

// =============================================================================
// Test: OAuth Callback
// =============================================================================

func TestConnectionHandler_OAuthCallback_Unauthorized(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	req := httptest.NewRequest(http.MethodGet, "/oauth/linkedin/callback?code=abc&state=xyz", nil)
	rr := httptest.NewRecorder()

	handler.OAuthCallback(rr, req, "linkedin")

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status 303, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/login?error=unauthorized" {
		t.Errorf("Expected redirect to /login?error=unauthorized, got '%s'", loc)
	}
}

func TestConnectionHandler_OAuthCallback_MissingCode(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	token := generateTestToken("user-123", "test@example.com")
	req := httptest.NewRequest(http.MethodGet, "/oauth/linkedin/callback?state=xyz", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.OAuthCallback(rr, req, "linkedin")

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status 303, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/connections?error=missing_code" {
		t.Errorf("Expected redirect with missing_code error, got '%s'", loc)
	}
}

func TestConnectionHandler_OAuthCallback_InvalidState(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	token := generateTestToken("user-123", "test@example.com")
	req := httptest.NewRequest(http.MethodGet, "/oauth/linkedin/callback?code=abc&state=invalid", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.OAuthCallback(rr, req, "linkedin")

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status 303, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/connections?error=invalid_state" {
		t.Errorf("Expected redirect with invalid_state error, got '%s'", loc)
	}
}

func TestConnectionHandler_OAuthCallback_Success(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	userID := "user-123"
	// First initiate OAuth to get a valid state
	oauthInfo, _ := svc.InitiateOAuth(context.Background(), userID, "linkedin")

	token := generateTestToken(userID, "test@example.com")
	req := httptest.NewRequest(http.MethodGet, "/oauth/linkedin/callback?code=valid-code&state="+oauthInfo.State, nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.OAuthCallback(rr, req, "linkedin")

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status 303, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/connections?success=linkedin" {
		t.Errorf("Expected redirect with success, got '%s'", loc)
	}

	// Verify connection was created
	conn, err := svc.GetConnection(context.Background(), userID, "linkedin")
	if err != nil {
		t.Fatalf("Expected connection to be created: %v", err)
	}
	if conn.Status != services.ConnectionStatusConnected {
		t.Errorf("Expected connected status, got '%s'", conn.Status)
	}
}

// =============================================================================
// Test: Disconnect
// =============================================================================

func TestConnectionHandler_Disconnect_Unauthorized(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	req := httptest.NewRequest(http.MethodDelete, "/api/connections/linkedin", nil)
	rr := httptest.NewRecorder()

	handler.Disconnect(rr, req, "linkedin")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestConnectionHandler_Disconnect_NotFound(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	token := generateTestToken("user-123", "test@example.com")
	req := httptest.NewRequest(http.MethodDelete, "/api/connections/linkedin", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.Disconnect(rr, req, "linkedin")

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestConnectionHandler_Disconnect_Success(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	userID := "user-123"
	now := time.Now()
	svc.AddConnection(&services.Connection{
		UserID:      userID,
		Platform:    "linkedin",
		Status:      services.ConnectionStatusConnected,
		ConnectedAt: &now,
	})

	token := generateTestToken(userID, "test@example.com")
	req := httptest.NewRequest(http.MethodDelete, "/api/connections/linkedin", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.Disconnect(rr, req, "linkedin")

	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify connection was removed
	_, err := svc.GetConnection(context.Background(), userID, "linkedin")
	if err != services.ErrConnectionNotFound {
		t.Errorf("Expected connection to be removed, got error: %v", err)
	}
}

// =============================================================================
// Test: Test Connection
// =============================================================================

func TestConnectionHandler_TestConnection_Unauthorized(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	req := httptest.NewRequest(http.MethodPost, "/api/connections/linkedin/test", nil)
	rr := httptest.NewRecorder()

	handler.TestConnection(rr, req, "linkedin")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestConnectionHandler_TestConnection_NotFound(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	token := generateTestToken("user-123", "test@example.com")
	req := httptest.NewRequest(http.MethodPost, "/api/connections/linkedin/test", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.TestConnection(rr, req, "linkedin")

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestConnectionHandler_TestConnection_Healthy(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	userID := "user-123"
	now := time.Now()
	svc.AddConnection(&services.Connection{
		UserID:      userID,
		Platform:    "linkedin",
		Status:      services.ConnectionStatusConnected,
		ConnectedAt: &now,
	})

	token := generateTestToken(userID, "test@example.com")
	req := httptest.NewRequest(http.MethodPost, "/api/connections/linkedin/test", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.TestConnection(rr, req, "linkedin")

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp TestConnectionResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if !resp.Healthy {
		t.Error("Expected healthy=true")
	}
	if resp.LatencyMs <= 0 {
		t.Error("Expected positive latency")
	}
}

func TestConnectionHandler_TestConnection_Unhealthy(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	userID := "user-123"
	now := time.Now()
	svc.AddConnection(&services.Connection{
		UserID:      userID,
		Platform:    "linkedin",
		Status:      services.ConnectionStatusConnected,
		ConnectedAt: &now,
	})
	svc.SetTestResult("linkedin", &services.ConnectionTestResult{
		Platform: "linkedin",
		Success:  false,
		Latency:  100 * time.Millisecond,
		TestedAt: time.Now(),
		Error:    "token expired",
	})

	token := generateTestToken(userID, "test@example.com")
	req := httptest.NewRequest(http.MethodPost, "/api/connections/linkedin/test", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.TestConnection(rr, req, "linkedin")

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp TestConnectionResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Healthy {
		t.Error("Expected healthy=false")
	}
	if resp.Error != "token expired" {
		t.Errorf("Expected error 'token expired', got '%s'", resp.Error)
	}
}

// =============================================================================
// Test: Get Rate Limits
// =============================================================================

func TestConnectionHandler_GetRateLimits_Unauthorized(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	req := httptest.NewRequest(http.MethodGet, "/api/connections/linkedin/rate-limits", nil)
	rr := httptest.NewRecorder()

	handler.GetRateLimits(rr, req, "linkedin")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestConnectionHandler_GetRateLimits_NotFound(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	token := generateTestToken("user-123", "test@example.com")
	req := httptest.NewRequest(http.MethodGet, "/api/connections/linkedin/rate-limits", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.GetRateLimits(rr, req, "linkedin")

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestConnectionHandler_GetRateLimits_Success(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	userID := "user-123"
	now := time.Now()
	resetTime := now.Add(time.Hour)
	svc.AddConnection(&services.Connection{
		UserID:      userID,
		Platform:    "linkedin",
		Status:      services.ConnectionStatusConnected,
		ConnectedAt: &now,
	})
	svc.SetRateLimits("linkedin", &services.RateLimitInfo{
		Limit:     100,
		Remaining: 75,
		ResetAt:   resetTime,
	})

	token := generateTestToken(userID, "test@example.com")
	req := httptest.NewRequest(http.MethodGet, "/api/connections/linkedin/rate-limits", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.GetRateLimits(rr, req, "linkedin")

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp RateLimitResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Limit != 100 {
		t.Errorf("Expected limit 100, got %d", resp.Limit)
	}
	if resp.Remaining != 75 {
		t.Errorf("Expected remaining 75, got %d", resp.Remaining)
	}
}

// =============================================================================
// E2E HTTP Tests - Full Request/Response Cycle
// =============================================================================

func TestConnectionHandler_E2E_FullConnectionFlow(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	userID := "e2e-user-123"
	token := generateTestToken(userID, "e2e@example.com")

	// Step 1: List connections (should be empty)
	t.Run("Step1_ListEmpty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
		addAuthCookie(req, token)
		rr := httptest.NewRecorder()
		handler.ListConnections(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d", rr.Code)
		}
		var resp ConnectionListResponse
		json.NewDecoder(rr.Body).Decode(&resp)
		if len(resp.Connections) != 0 {
			t.Fatalf("Expected 0 connections, got %d", len(resp.Connections))
		}
	})

	// Step 2: Initiate OAuth for LinkedIn
	var oauthURL string
	t.Run("Step2_InitiateOAuth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/connections/linkedin/connect", nil)
		addAuthCookie(req, token)
		rr := httptest.NewRecorder()
		handler.Connect(rr, req, "linkedin")

		if rr.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		var resp ConnectResponse
		json.NewDecoder(rr.Body).Decode(&resp)
		if resp.AuthURL == "" {
			t.Fatal("Expected non-empty auth_url")
		}
		oauthURL = resp.AuthURL
	})

	// Step 3: Simulate OAuth callback
	t.Run("Step3_OAuthCallback", func(t *testing.T) {
		// Extract state from OAuth URL
		state := "mock-state-" + userID + "-linkedin"
		req := httptest.NewRequest(http.MethodGet, "/oauth/linkedin/callback?code=valid-code&state="+state, nil)
		addAuthCookie(req, token)
		rr := httptest.NewRecorder()
		handler.OAuthCallback(rr, req, "linkedin")

		if rr.Code != http.StatusSeeOther {
			t.Fatalf("Expected 303, got %d", rr.Code)
		}
		loc := rr.Header().Get("Location")
		if loc != "/connections?success=linkedin" {
			t.Fatalf("Expected success redirect, got '%s'", loc)
		}
	})

	// Step 4: Verify connection appears in list
	t.Run("Step4_VerifyConnectionInList", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
		addAuthCookie(req, token)
		rr := httptest.NewRecorder()
		handler.ListConnections(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d", rr.Code)
		}
		var resp ConnectionListResponse
		json.NewDecoder(rr.Body).Decode(&resp)
		if len(resp.Connections) != 1 {
			t.Fatalf("Expected 1 connection, got %d", len(resp.Connections))
		}
		if resp.Connections[0].Platform != "linkedin" {
			t.Errorf("Expected linkedin platform, got '%s'", resp.Connections[0].Platform)
		}
		if resp.Connections[0].Status != services.ConnectionStatusConnected {
			t.Errorf("Expected connected status, got '%s'", resp.Connections[0].Status)
		}
	})

	// Step 5: Test connection health
	t.Run("Step5_TestConnection", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/connections/linkedin/test", nil)
		addAuthCookie(req, token)
		rr := httptest.NewRecorder()
		handler.TestConnection(rr, req, "linkedin")

		if rr.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		var resp TestConnectionResponse
		json.NewDecoder(rr.Body).Decode(&resp)
		if !resp.Healthy {
			t.Error("Expected healthy=true")
		}
	})

	// Step 6: Get rate limits
	t.Run("Step6_GetRateLimits", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/connections/linkedin/rate-limits", nil)
		addAuthCookie(req, token)
		rr := httptest.NewRecorder()
		handler.GetRateLimits(rr, req, "linkedin")

		if rr.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		var resp RateLimitResponse
		json.NewDecoder(rr.Body).Decode(&resp)
		if resp.Limit <= 0 {
			t.Error("Expected positive rate limit")
		}
	})

	// Step 7: Disconnect
	t.Run("Step7_Disconnect", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/connections/linkedin", nil)
		addAuthCookie(req, token)
		rr := httptest.NewRecorder()
		handler.Disconnect(rr, req, "linkedin")

		if rr.Code != http.StatusNoContent {
			t.Fatalf("Expected 204, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	// Step 8: Verify connection removed
	t.Run("Step8_VerifyDisconnected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
		addAuthCookie(req, token)
		rr := httptest.NewRecorder()
		handler.ListConnections(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d", rr.Code)
		}
		var resp ConnectionListResponse
		json.NewDecoder(rr.Body).Decode(&resp)
		if len(resp.Connections) != 0 {
			t.Errorf("Expected 0 connections after disconnect, got %d", len(resp.Connections))
		}
	})

	// Test with OAuth URL from step 2
	_ = oauthURL
}

// =============================================================================
// Token Expiration UI Tests (alice-94: TDD Red Phase)
// These tests verify the API provides data needed for token expiration UI:
// 1. "Expiring soon" warning when token expires within 7 days
// 2. Proper status for "Reconnect" button on expired tokens
// 3. Posting blocked when token is expired
// =============================================================================

// TestConnectionHandler_ListConnections_ExpiringSoon tests that connections
// expiring within 7 days include an ExpiresSoon indicator for UI warning.
func TestConnectionHandler_ListConnections_ExpiringSoon(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	userID := "user-123"
	now := time.Now()
	// Token expires in 5 days - should trigger "expiring soon" warning
	expiresIn5Days := now.Add(5 * 24 * time.Hour)

	svc.AddConnection(&services.Connection{
		UserID:      userID,
		Platform:    "linkedin",
		Status:      services.ConnectionStatusConnected,
		DisplayName: "John Doe",
		ConnectedAt: &now,
		ExpiresAt:   &expiresIn5Days,
	})

	token := generateTestToken(userID, "test@example.com")
	req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.ListConnections(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Parse response to check for ExpiresSoon field
	var rawResp map[string][]map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&rawResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	connections := rawResp["connections"]
	if len(connections) != 1 {
		t.Fatalf("Expected 1 connection, got %d", len(connections))
	}

	conn := connections[0]

	// TDD RED: This test should FAIL because ExpiresSoon is not implemented
	expiresSoon, ok := conn["expires_soon"]
	if !ok {
		t.Fatal("Expected expires_soon field in response - UI needs this to show warning")
	}
	if expiresSoon != true {
		t.Errorf("Expected expires_soon=true for token expiring in 5 days, got %v", expiresSoon)
	}
}

// TestConnectionHandler_ListConnections_NotExpiringSoon tests that connections
// with plenty of time remaining do NOT have ExpiresSoon set.
func TestConnectionHandler_ListConnections_NotExpiringSoon(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	userID := "user-123"
	now := time.Now()
	// Token expires in 30 days - should NOT trigger warning
	expiresIn30Days := now.Add(30 * 24 * time.Hour)

	svc.AddConnection(&services.Connection{
		UserID:      userID,
		Platform:    "linkedin",
		Status:      services.ConnectionStatusConnected,
		DisplayName: "John Doe",
		ConnectedAt: &now,
		ExpiresAt:   &expiresIn30Days,
	})

	token := generateTestToken(userID, "test@example.com")
	req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.ListConnections(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var rawResp map[string][]map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&rawResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	connections := rawResp["connections"]
	if len(connections) != 1 {
		t.Fatalf("Expected 1 connection, got %d", len(connections))
	}

	conn := connections[0]

	// TDD RED: This test should FAIL because ExpiresSoon is not implemented
	expiresSoon, ok := conn["expires_soon"]
	if !ok {
		t.Fatal("Expected expires_soon field in response - UI needs this for consistency")
	}
	if expiresSoon != false {
		t.Errorf("Expected expires_soon=false for token expiring in 30 days, got %v", expiresSoon)
	}
}

// TestConnectionHandler_GetConnection_ExpiredShowsReconnect tests that an
// expired connection returns proper data for the UI to show a Reconnect button.
func TestConnectionHandler_GetConnection_ExpiredShowsReconnect(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	userID := "user-123"
	now := time.Now()
	// Token expired yesterday
	expiredYesterday := now.Add(-24 * time.Hour)

	svc.AddConnection(&services.Connection{
		UserID:      userID,
		Platform:    "linkedin",
		Status:      services.ConnectionStatusExpired,
		DisplayName: "John Doe",
		ConnectedAt: &now,
		ExpiresAt:   &expiredYesterday,
	})

	token := generateTestToken(userID, "test@example.com")
	req := httptest.NewRequest(http.MethodGet, "/api/connections/linkedin", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.GetConnection(rr, req, "linkedin")

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ConnectionDetailResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify fields needed for "Reconnect" button UI
	if resp.Connection.Status != services.ConnectionStatusExpired {
		t.Errorf("Expected status 'expired', got '%s'", resp.Connection.Status)
	}
	if resp.Connection.IsHealthy {
		t.Error("Expected IsHealthy=false for expired connection")
	}
	if resp.Connection.ExpiresAt == nil {
		t.Error("Expected ExpiresAt to be set for expired connection")
	}
}

// TestConnectionHandler_ListConnections_ExpiredHasReconnectData tests that
// listing connections returns all data needed to show Reconnect for expired tokens.
func TestConnectionHandler_ListConnections_ExpiredHasReconnectData(t *testing.T) {
	svc := NewMockConnectionService()
	handler := NewConnectionHandler(svc, "https://app.example.com")

	userID := "user-123"
	now := time.Now()
	expiredYesterday := now.Add(-24 * time.Hour)

	svc.AddConnection(&services.Connection{
		UserID:      userID,
		Platform:    "threads",
		Status:      services.ConnectionStatusExpired,
		DisplayName: "Expired Account",
		ConnectedAt: &now,
		ExpiresAt:   &expiredYesterday,
	})

	token := generateTestToken(userID, "test@example.com")
	req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	addAuthCookie(req, token)
	rr := httptest.NewRecorder()

	handler.ListConnections(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ConnectionListResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(resp.Connections) != 1 {
		t.Fatalf("Expected 1 connection, got %d", len(resp.Connections))
	}

	conn := resp.Connections[0]

	// UI needs these fields to show "Reconnect" button
	if conn.Status != services.ConnectionStatusExpired {
		t.Errorf("Expected status 'expired', got '%s'", conn.Status)
	}
	if conn.IsHealthy {
		t.Error("Expected IsHealthy=false for expired connection - UI uses this to show warning")
	}
	if conn.Platform != "threads" {
		t.Errorf("Expected platform 'threads', got '%s'", conn.Platform)
	}
}
