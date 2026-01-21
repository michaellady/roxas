package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/mikelady/roxas/internal/auth"
	"github.com/mikelady/roxas/internal/services"
)

// ConnectionService defines the interface for connection operations
type ConnectionService interface {
	ListConnections(ctx context.Context, userID string) ([]*services.Connection, error)
	GetConnection(ctx context.Context, userID, platform string) (*services.Connection, error)
	InitiateOAuth(ctx context.Context, userID, platform string) (*services.OAuthInfo, error)
	HandleOAuthCallback(ctx context.Context, userID, platform, code, state string) (*services.OAuthResult, error)
	Disconnect(ctx context.Context, userID, platform string) error
	TestConnection(ctx context.Context, userID, platform string) (*services.ConnectionTestResult, error)
	GetRateLimits(ctx context.Context, userID, platform string) (*services.RateLimitInfo, error)
}

// ConnectionHandler handles connection management endpoints
type ConnectionHandler struct {
	service     ConnectionService
	callbackURL string // base URL for OAuth callback
}

// NewConnectionHandler creates a new connection handler
func NewConnectionHandler(service ConnectionService, callbackURL string) *ConnectionHandler {
	return &ConnectionHandler{
		service:     service,
		callbackURL: callbackURL,
	}
}

// =============================================================================
// Response Types
// =============================================================================

// ConnectionResponse represents a single connection in API responses
type ConnectionResponse struct {
	Platform       string     `json:"platform"`
	Status         string     `json:"status"`
	DisplayName    string     `json:"display_name,omitempty"`
	ProfileURL     string     `json:"profile_url,omitempty"`
	ConnectedAt    *time.Time `json:"connected_at,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	IsHealthy      bool       `json:"is_healthy"`
	ExpiresSoon    bool       `json:"expires_soon"`
}

// ConnectionListResponse represents the list connections response
type ConnectionListResponse struct {
	Connections []ConnectionResponse `json:"connections"`
}

// ConnectionDetailResponse represents a single connection with rate limits
type ConnectionDetailResponse struct {
	Connection ConnectionResponse      `json:"connection"`
	RateLimits *RateLimitResponse      `json:"rate_limits,omitempty"`
}

// ConnectResponse represents the OAuth initiation response
type ConnectResponse struct {
	AuthURL string `json:"auth_url"`
}

// TestConnectionResponse represents the test result
type TestConnectionResponse struct {
	Healthy    bool    `json:"healthy"`
	LatencyMs  int64   `json:"latency_ms,omitempty"`
	Error      string  `json:"error,omitempty"`
}

// RateLimitResponse represents rate limit info
type RateLimitResponse struct {
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	ResetAt   time.Time `json:"reset_at"`
}

// =============================================================================
// HTTP Handlers
// =============================================================================

// ListConnections handles GET /api/connections
func (h *ConnectionHandler) ListConnections(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.getUserID(r)
	if !ok {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	connections, err := h.service.ListConnections(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to list connections")
		return
	}

	resp := ConnectionListResponse{
		Connections: make([]ConnectionResponse, 0, len(connections)),
	}

	for _, conn := range connections {
		resp.Connections = append(resp.Connections, h.toConnectionResponse(conn))
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// GetConnection handles GET /api/connections/:platform
func (h *ConnectionHandler) GetConnection(w http.ResponseWriter, r *http.Request, platform string) {
	userID, ok := h.getUserID(r)
	if !ok {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	conn, err := h.service.GetConnection(r.Context(), userID, platform)
	if err != nil {
		if errors.Is(err, services.ErrConnectionNotFound) {
			h.writeError(w, http.StatusNotFound, "connection not found")
			return
		}
		if errors.Is(err, services.ErrInvalidPlatform) {
			h.writeError(w, http.StatusBadRequest, "invalid platform")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "failed to get connection")
		return
	}

	resp := ConnectionDetailResponse{
		Connection: h.toConnectionResponse(conn),
	}

	// Try to get rate limits too
	limits, err := h.service.GetRateLimits(r.Context(), userID, platform)
	if err == nil && limits != nil {
		resp.RateLimits = &RateLimitResponse{
			Limit:     limits.Limit,
			Remaining: limits.Remaining,
			ResetAt:   limits.ResetAt,
		}
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// Connect handles POST /api/connections/:platform/connect
func (h *ConnectionHandler) Connect(w http.ResponseWriter, r *http.Request, platform string) {
	userID, ok := h.getUserID(r)
	if !ok {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	oauthInfo, err := h.service.InitiateOAuth(r.Context(), userID, platform)
	if err != nil {
		if errors.Is(err, services.ErrInvalidPlatform) {
			h.writeError(w, http.StatusBadRequest, "invalid platform")
			return
		}
		if errors.Is(err, services.ErrPlatformDisabled) {
			h.writeError(w, http.StatusServiceUnavailable, "platform is currently disabled")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "failed to initiate OAuth")
		return
	}

	h.writeJSON(w, http.StatusOK, ConnectResponse{AuthURL: oauthInfo.AuthURL})
}

// OAuthCallback handles GET /oauth/:platform/callback
func (h *ConnectionHandler) OAuthCallback(w http.ResponseWriter, r *http.Request, platform string) {
	userID, ok := h.getUserID(r)
	if !ok {
		http.Redirect(w, r, "/login?error=unauthorized", http.StatusSeeOther)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		// Check for error from OAuth provider
		oauthError := r.URL.Query().Get("error")
		if oauthError != "" {
			http.Redirect(w, r, "/connections?error="+oauthError, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/connections?error=missing_code", http.StatusSeeOther)
		return
	}

	_, err := h.service.HandleOAuthCallback(r.Context(), userID, platform, code, state)
	if err != nil {
		if errors.Is(err, services.ErrOAuthStateInvalid) {
			http.Redirect(w, r, "/connections?error=invalid_state", http.StatusSeeOther)
			return
		}
		if errors.Is(err, services.ErrOAuthCodeInvalid) {
			http.Redirect(w, r, "/connections?error=invalid_code", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/connections?error=callback_failed", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/connections?success="+platform, http.StatusSeeOther)
}

// Disconnect handles DELETE /api/connections/:platform
func (h *ConnectionHandler) Disconnect(w http.ResponseWriter, r *http.Request, platform string) {
	userID, ok := h.getUserID(r)
	if !ok {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	err := h.service.Disconnect(r.Context(), userID, platform)
	if err != nil {
		if errors.Is(err, services.ErrConnectionNotFound) {
			h.writeError(w, http.StatusNotFound, "connection not found")
			return
		}
		if errors.Is(err, services.ErrInvalidPlatform) {
			h.writeError(w, http.StatusBadRequest, "invalid platform")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "failed to disconnect")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// TestConnection handles POST /api/connections/:platform/test
func (h *ConnectionHandler) TestConnection(w http.ResponseWriter, r *http.Request, platform string) {
	userID, ok := h.getUserID(r)
	if !ok {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	result, err := h.service.TestConnection(r.Context(), userID, platform)
	if err != nil {
		if errors.Is(err, services.ErrConnectionNotFound) {
			h.writeError(w, http.StatusNotFound, "connection not found")
			return
		}
		if errors.Is(err, services.ErrInvalidPlatform) {
			h.writeError(w, http.StatusBadRequest, "invalid platform")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "failed to test connection")
		return
	}

	resp := TestConnectionResponse{
		Healthy:   result.Success,
		LatencyMs: result.Latency.Milliseconds(),
	}
	if !result.Success {
		resp.Error = result.Error
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// GetRateLimits handles GET /api/connections/:platform/rate-limits
func (h *ConnectionHandler) GetRateLimits(w http.ResponseWriter, r *http.Request, platform string) {
	userID, ok := h.getUserID(r)
	if !ok {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	limits, err := h.service.GetRateLimits(r.Context(), userID, platform)
	if err != nil {
		if errors.Is(err, services.ErrConnectionNotFound) {
			h.writeError(w, http.StatusNotFound, "connection not found")
			return
		}
		if errors.Is(err, services.ErrInvalidPlatform) {
			h.writeError(w, http.StatusBadRequest, "invalid platform")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "failed to get rate limits")
		return
	}

	h.writeJSON(w, http.StatusOK, RateLimitResponse{
		Limit:     limits.Limit,
		Remaining: limits.Remaining,
		ResetAt:   limits.ResetAt,
	})
}

// =============================================================================
// Helper Methods
// =============================================================================

// getUserID extracts user ID from auth context (JWT token)
func (h *ConnectionHandler) getUserID(r *http.Request) (string, bool) {
	// Check for auth cookie
	cookie, err := r.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		// Also check Authorization header for API clients
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			return "", false
		}
		// Extract Bearer token
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return "", false
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := auth.ValidateToken(token)
		if err != nil {
			return "", false
		}
		return claims.UserID, true
	}

	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil {
		return "", false
	}
	return claims.UserID, true
}

func (h *ConnectionHandler) toConnectionResponse(conn *services.Connection) ConnectionResponse {
	return ConnectionResponse{
		Platform:    conn.Platform,
		Status:      conn.Status,
		DisplayName: conn.DisplayName,
		ProfileURL:  conn.ProfileURL,
		ConnectedAt: conn.ConnectedAt,
		ExpiresAt:   conn.ExpiresAt,
		IsHealthy:   conn.IsHealthy(),
		ExpiresSoon: conn.ExpiresSoon(),
	}
}

func (h *ConnectionHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *ConnectionHandler) writeError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, ErrorResponse{Error: message})
}
