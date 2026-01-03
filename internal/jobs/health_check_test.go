package jobs

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mikelady/roxas/internal/services"
)

// =============================================================================
// Mock implementations for testing
// =============================================================================

type mockCredentialStore struct {
	credentials       []*services.PlatformCredentials
	expiringCreds     []*services.PlatformCredentials
	healthUpdates     []HealthUpdate
	getExpiringError  error
	getNeedingError   error
	updateHealthError error
}

type HealthUpdate struct {
	UserID      string
	Platform    string
	IsHealthy   bool
	HealthError string
}

func (m *mockCredentialStore) GetAllCredentials(ctx context.Context) ([]*services.PlatformCredentials, error) {
	return m.credentials, nil
}

func (m *mockCredentialStore) GetExpiringCredentials(ctx context.Context, within time.Duration) ([]*services.PlatformCredentials, error) {
	if m.getExpiringError != nil {
		return nil, m.getExpiringError
	}
	return m.expiringCreds, nil
}

func (m *mockCredentialStore) UpdateHealthStatus(ctx context.Context, userID, platform string, isHealthy bool, healthError string) error {
	if m.updateHealthError != nil {
		return m.updateHealthError
	}
	m.healthUpdates = append(m.healthUpdates, HealthUpdate{
		UserID:      userID,
		Platform:    platform,
		IsHealthy:   isHealthy,
		HealthError: healthError,
	})
	return nil
}

func (m *mockCredentialStore) GetCredentialsNeedingCheck(ctx context.Context, since time.Duration) ([]*services.PlatformCredentials, error) {
	if m.getNeedingError != nil {
		return nil, m.getNeedingError
	}
	var result []*services.PlatformCredentials
	for _, c := range m.credentials {
		result = append(result, c)
	}
	return result, nil
}

type mockConnectionTester struct {
	healthyPlatforms map[string]bool
	testErrors       map[string]error
}

func (m *mockConnectionTester) TestConnection(ctx context.Context, creds *services.PlatformCredentials) error {
	if err, ok := m.testErrors[creds.Platform]; ok {
		return err
	}
	if healthy, ok := m.healthyPlatforms[creds.Platform]; ok && !healthy {
		return errors.New("connection failed")
	}
	return nil
}

// =============================================================================
// HealthCheckJob Tests
// =============================================================================

func TestHealthCheckJob_CheckExpiringTokens(t *testing.T) {
	expiresIn3Days := time.Now().Add(3 * 24 * time.Hour)

	tests := []struct {
		name          string
		expiringCreds []*services.PlatformCredentials
		wantExpiring  int
	}{
		{
			name:          "no credentials",
			expiringCreds: nil,
			wantExpiring:  0,
		},
		{
			name: "token expiring within 7 days",
			expiringCreds: []*services.PlatformCredentials{
				{UserID: "user1", Platform: "threads", TokenExpiresAt: &expiresIn3Days},
			},
			wantExpiring: 1,
		},
		{
			name:          "no tokens expiring soon",
			expiringCreds: nil,
			wantExpiring:  0,
		},
		{
			name: "multiple tokens expiring",
			expiringCreds: []*services.PlatformCredentials{
				{UserID: "user1", Platform: "threads", TokenExpiresAt: &expiresIn3Days},
				{UserID: "user2", Platform: "linkedin", TokenExpiresAt: &expiresIn3Days},
			},
			wantExpiring: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockCredentialStore{
				expiringCreds: tt.expiringCreds,
			}
			tester := &mockConnectionTester{healthyPlatforms: make(map[string]bool)}

			job := NewHealthCheckJob(store, tester, HealthCheckConfig{
				ExpiryWarningWindow: 7 * 24 * time.Hour,
			})

			result := job.CheckExpiringTokens(context.Background())

			if result.TokensExpiringSoon != tt.wantExpiring {
				t.Errorf("TokensExpiringSoon = %d, want %d", result.TokensExpiringSoon, tt.wantExpiring)
			}
		})
	}
}

func TestHealthCheckJob_TestConnections(t *testing.T) {
	tests := []struct {
		name             string
		credentials      []*services.PlatformCredentials
		healthyPlatforms map[string]bool
		testErrors       map[string]error
		wantHealthy      int
		wantUnhealthy    int
	}{
		{
			name:          "no credentials",
			credentials:   nil,
			wantHealthy:   0,
			wantUnhealthy: 0,
		},
		{
			name: "all healthy",
			credentials: []*services.PlatformCredentials{
				{UserID: "user1", Platform: "threads"},
				{UserID: "user2", Platform: "linkedin"},
			},
			healthyPlatforms: map[string]bool{"threads": true, "linkedin": true},
			wantHealthy:      2,
			wantUnhealthy:    0,
		},
		{
			name: "one unhealthy",
			credentials: []*services.PlatformCredentials{
				{UserID: "user1", Platform: "threads"},
				{UserID: "user2", Platform: "linkedin"},
			},
			healthyPlatforms: map[string]bool{"threads": true, "linkedin": false},
			wantHealthy:      1,
			wantUnhealthy:    1,
		},
		{
			name: "connection test error",
			credentials: []*services.PlatformCredentials{
				{UserID: "user1", Platform: "threads"},
			},
			testErrors:    map[string]error{"threads": errors.New("API error")},
			wantHealthy:   0,
			wantUnhealthy: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockCredentialStore{
				credentials: tt.credentials,
			}
			tester := &mockConnectionTester{
				healthyPlatforms: tt.healthyPlatforms,
				testErrors:       tt.testErrors,
			}

			job := NewHealthCheckJob(store, tester, HealthCheckConfig{
				CheckInterval: 24 * time.Hour,
			})

			result := job.TestConnections(context.Background())

			if result.HealthyConnections != tt.wantHealthy {
				t.Errorf("HealthyConnections = %d, want %d", result.HealthyConnections, tt.wantHealthy)
			}
			if result.UnhealthyConnections != tt.wantUnhealthy {
				t.Errorf("UnhealthyConnections = %d, want %d", result.UnhealthyConnections, tt.wantUnhealthy)
			}
		})
	}
}

func TestHealthCheckJob_Run(t *testing.T) {
	expiresIn3Days := time.Now().Add(3 * 24 * time.Hour)

	store := &mockCredentialStore{
		credentials: []*services.PlatformCredentials{
			{UserID: "user1", Platform: "threads"},
			{UserID: "user2", Platform: "linkedin"},
		},
		expiringCreds: []*services.PlatformCredentials{
			{UserID: "user3", Platform: "twitter", TokenExpiresAt: &expiresIn3Days},
		},
	}
	tester := &mockConnectionTester{
		healthyPlatforms: map[string]bool{"threads": true, "linkedin": false},
	}

	job := NewHealthCheckJob(store, tester, HealthCheckConfig{
		ExpiryWarningWindow: 7 * 24 * time.Hour,
		CheckInterval:       24 * time.Hour,
	})

	result, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.TokensExpiringSoon != 1 {
		t.Errorf("TokensExpiringSoon = %d, want 1", result.TokensExpiringSoon)
	}
	if result.HealthyConnections != 1 {
		t.Errorf("HealthyConnections = %d, want 1", result.HealthyConnections)
	}
	if result.UnhealthyConnections != 1 {
		t.Errorf("UnhealthyConnections = %d, want 1", result.UnhealthyConnections)
	}
}

func TestHealthCheckJob_ContinuesOnError(t *testing.T) {
	store := &mockCredentialStore{
		credentials: []*services.PlatformCredentials{
			{UserID: "user1", Platform: "threads"},
			{UserID: "user2", Platform: "linkedin"},
			{UserID: "user3", Platform: "twitter"},
		},
	}
	tester := &mockConnectionTester{
		healthyPlatforms: map[string]bool{"threads": true, "twitter": true},
		testErrors:       map[string]error{"linkedin": errors.New("API error")},
	}

	job := NewHealthCheckJob(store, tester, HealthCheckConfig{})

	result := job.TestConnections(context.Background())

	total := result.HealthyConnections + result.UnhealthyConnections
	if total != 3 {
		t.Errorf("Total processed = %d, want 3 (job should continue after errors)", total)
	}
}

func TestHealthCheckJob_UpdatesHealthStatus(t *testing.T) {
	store := &mockCredentialStore{
		credentials: []*services.PlatformCredentials{
			{UserID: "user1", Platform: "threads"},
			{UserID: "user2", Platform: "linkedin"},
		},
	}
	tester := &mockConnectionTester{
		healthyPlatforms: map[string]bool{"threads": true},
		testErrors:       map[string]error{"linkedin": errors.New("token expired")},
	}

	job := NewHealthCheckJob(store, tester, HealthCheckConfig{})

	job.TestConnections(context.Background())

	if len(store.healthUpdates) != 2 {
		t.Fatalf("Expected 2 health updates, got %d", len(store.healthUpdates))
	}

	var threadsUpdate, linkedinUpdate *HealthUpdate
	for i := range store.healthUpdates {
		u := &store.healthUpdates[i]
		switch u.Platform {
		case "threads":
			threadsUpdate = u
		case "linkedin":
			linkedinUpdate = u
		}
	}

	if threadsUpdate == nil || !threadsUpdate.IsHealthy {
		t.Error("threads should be marked healthy")
	}
	if linkedinUpdate == nil || linkedinUpdate.IsHealthy {
		t.Error("linkedin should be marked unhealthy")
	}
	if linkedinUpdate != nil && linkedinUpdate.HealthError != "token expired" {
		t.Errorf("Expected health error 'token expired', got '%s'", linkedinUpdate.HealthError)
	}
}

// =============================================================================
// Error Context Tests (hq-1aig)
// =============================================================================

func TestHealthCheckJob_UpdateHealthStatusError_IncludesCredentialContext(t *testing.T) {
	// This test verifies that when UpdateHealthStatus fails,
	// the error message includes user and platform context for debugging
	store := &mockCredentialStore{
		credentials: []*services.PlatformCredentials{
			{UserID: "user-abc123", Platform: "threads"},
		},
		updateHealthError: errors.New("database connection lost"),
	}
	tester := &mockConnectionTester{
		healthyPlatforms: map[string]bool{"threads": true},
	}

	job := NewHealthCheckJob(store, tester, HealthCheckConfig{})

	result := job.TestConnections(context.Background())

	// Should have recorded an error
	if len(result.Errors) != 1 {
		t.Fatalf("Expected 1 error, got %d", len(result.Errors))
	}

	errMsg := result.Errors[0].Error()

	// Error should include credential context (hq-1aig fix)
	if !strings.Contains(errMsg, "user=user-abc123") {
		t.Errorf("Error should include user context, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "platform=threads") {
		t.Errorf("Error should include platform context, got: %s", errMsg)
	}
	// Should also include the underlying error
	if !strings.Contains(errMsg, "database connection lost") {
		t.Errorf("Error should include underlying error, got: %s", errMsg)
	}
}

func TestHealthCheckJob_GetExpiringCredentialsError_IncludesContext(t *testing.T) {
	store := &mockCredentialStore{
		getExpiringError: errors.New("query timeout"),
	}
	tester := &mockConnectionTester{}

	job := NewHealthCheckJob(store, tester, HealthCheckConfig{})

	result := job.CheckExpiringTokens(context.Background())

	if len(result.Errors) != 1 {
		t.Fatalf("Expected 1 error, got %d", len(result.Errors))
	}

	errMsg := result.Errors[0].Error()

	// Error should have context about what operation failed
	if !strings.Contains(errMsg, "expiring credentials") {
		t.Errorf("Error should include operation context, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "query timeout") {
		t.Errorf("Error should include underlying error, got: %s", errMsg)
	}
}

func TestHealthCheckJob_GetCredentialsNeedingCheckError_IncludesContext(t *testing.T) {
	store := &mockCredentialStore{
		getNeedingError: errors.New("connection refused"),
	}
	tester := &mockConnectionTester{}

	job := NewHealthCheckJob(store, tester, HealthCheckConfig{})

	result := job.TestConnections(context.Background())

	if len(result.Errors) != 1 {
		t.Fatalf("Expected 1 error, got %d", len(result.Errors))
	}

	errMsg := result.Errors[0].Error()

	// Error should have context about what operation failed
	if !strings.Contains(errMsg, "needing check") {
		t.Errorf("Error should include operation context, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "connection refused") {
		t.Errorf("Error should include underlying error, got: %s", errMsg)
	}
}
