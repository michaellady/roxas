package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mikelady/roxas/internal/services"
)

// MockCredentialStore is a mock implementation of services.CredentialStore for testing
type MockCredentialStore struct {
	credentials         []*services.PlatformCredentials
	expiringCredentials []*services.PlatformCredentials
	needingCheck        []*services.PlatformCredentials
	healthUpdates       []HealthUpdate
	getExpiringErr      error
	getNeedingCheckErr  error
	updateHealthErr     error
}

type HealthUpdate struct {
	UserID      string
	Platform    string
	IsHealthy   bool
	HealthError *string
}

func (m *MockCredentialStore) GetCredentials(ctx context.Context, userID, platform string) (*services.PlatformCredentials, error) {
	for _, c := range m.credentials {
		if c.UserID == userID && c.Platform == platform {
			return c, nil
		}
	}
	return nil, services.ErrCredentialsNotFound
}

func (m *MockCredentialStore) SaveCredentials(ctx context.Context, creds *services.PlatformCredentials) error {
	return nil
}

func (m *MockCredentialStore) DeleteCredentials(ctx context.Context, userID, platform string) error {
	return nil
}

func (m *MockCredentialStore) GetCredentialsForUser(ctx context.Context, userID string) ([]*services.PlatformCredentials, error) {
	var result []*services.PlatformCredentials
	for _, c := range m.credentials {
		if c.UserID == userID {
			result = append(result, c)
		}
	}
	return result, nil
}

func (m *MockCredentialStore) GetExpiringCredentials(ctx context.Context, within time.Duration) ([]*services.PlatformCredentials, error) {
	if m.getExpiringErr != nil {
		return nil, m.getExpiringErr
	}
	return m.expiringCredentials, nil
}

func (m *MockCredentialStore) UpdateTokens(ctx context.Context, userID, platform, accessToken, refreshToken string, expiresAt *time.Time) error {
	return nil
}

func (m *MockCredentialStore) UpdateHealthStatus(ctx context.Context, userID, platform string, isHealthy bool, healthError *string) error {
	if m.updateHealthErr != nil {
		return m.updateHealthErr
	}
	m.healthUpdates = append(m.healthUpdates, HealthUpdate{
		UserID:      userID,
		Platform:    platform,
		IsHealthy:   isHealthy,
		HealthError: healthError,
	})
	return nil
}

func (m *MockCredentialStore) GetCredentialsNeedingCheck(ctx context.Context, notCheckedWithin time.Duration) ([]*services.PlatformCredentials, error) {
	if m.getNeedingCheckErr != nil {
		return nil, m.getNeedingCheckErr
	}
	return m.needingCheck, nil
}

// MockConnectionTester is a mock for testing platform connections
type MockConnectionTester struct {
	results map[string]error // platform -> error (nil = healthy)
}

func NewMockConnectionTester() *MockConnectionTester {
	return &MockConnectionTester{
		results: make(map[string]error),
	}
}

func (m *MockConnectionTester) SetResult(platform string, err error) {
	m.results[platform] = err
}

func (m *MockConnectionTester) TestConnection(ctx context.Context, creds *services.PlatformCredentials) error {
	if err, ok := m.results[creds.Platform]; ok {
		return err
	}
	return nil // Healthy by default
}

// TestHealthCheckJob_ProcessesAllConnections tests that the job processes all connections
func TestHealthCheckJob_ProcessesAllConnections(t *testing.T) {
	store := &MockCredentialStore{
		needingCheck: []*services.PlatformCredentials{
			{UserID: "user1", Platform: "threads"},
			{UserID: "user2", Platform: "linkedin"},
			{UserID: "user3", Platform: "bluesky"},
		},
	}
	tester := NewMockConnectionTester()

	job := NewHealthCheckJob(store, tester, DefaultConfig())
	result := job.Run(context.Background())

	if result.Err != nil {
		t.Errorf("Expected no error, got: %v", result.Err)
	}
	if result.Checked != 3 {
		t.Errorf("Expected 3 checked, got %d", result.Checked)
	}
	if result.Healthy != 3 {
		t.Errorf("Expected 3 healthy, got %d", result.Healthy)
	}
	if len(store.healthUpdates) != 3 {
		t.Errorf("Expected 3 health updates, got %d", len(store.healthUpdates))
	}
}

// TestHealthCheckJob_UnhealthyConnectionsLogged tests that unhealthy connections are marked
func TestHealthCheckJob_UnhealthyConnectionsLogged(t *testing.T) {
	store := &MockCredentialStore{
		needingCheck: []*services.PlatformCredentials{
			{UserID: "user1", Platform: "threads"},
			{UserID: "user2", Platform: "linkedin"},
		},
	}
	tester := NewMockConnectionTester()
	tester.SetResult("linkedin", errors.New("connection refused"))

	job := NewHealthCheckJob(store, tester, DefaultConfig())
	result := job.Run(context.Background())

	if result.Err != nil {
		t.Errorf("Expected no error, got: %v", result.Err)
	}
	if result.Checked != 2 {
		t.Errorf("Expected 2 checked, got %d", result.Checked)
	}
	if result.Healthy != 1 {
		t.Errorf("Expected 1 healthy, got %d", result.Healthy)
	}
	if result.Unhealthy != 1 {
		t.Errorf("Expected 1 unhealthy, got %d", result.Unhealthy)
	}

	// Verify the unhealthy update
	var foundUnhealthy bool
	for _, update := range store.healthUpdates {
		if update.Platform == "linkedin" {
			foundUnhealthy = true
			if update.IsHealthy {
				t.Error("LinkedIn should be marked unhealthy")
			}
			if update.HealthError == nil || *update.HealthError != "connection refused" {
				t.Error("Expected health error message")
			}
		}
	}
	if !foundUnhealthy {
		t.Error("Should have found LinkedIn in health updates")
	}
}

// TestHealthCheckJob_ExpiringTokensFlagged tests that expiring tokens are flagged
func TestHealthCheckJob_ExpiringTokensFlagged(t *testing.T) {
	expiresIn3Days := time.Now().Add(3 * 24 * time.Hour)
	expiresIn10Days := time.Now().Add(10 * 24 * time.Hour)

	store := &MockCredentialStore{
		needingCheck: []*services.PlatformCredentials{
			{UserID: "user1", Platform: "threads", TokenExpiresAt: &expiresIn3Days},
			{UserID: "user2", Platform: "linkedin", TokenExpiresAt: &expiresIn10Days},
		},
		expiringCredentials: []*services.PlatformCredentials{
			{UserID: "user1", Platform: "threads", TokenExpiresAt: &expiresIn3Days},
		},
	}
	tester := NewMockConnectionTester()

	job := NewHealthCheckJob(store, tester, DefaultConfig())
	result := job.Run(context.Background())

	if result.Err != nil {
		t.Errorf("Expected no error, got: %v", result.Err)
	}
	if result.ExpiringTokens != 1 {
		t.Errorf("Expected 1 expiring token, got %d", result.ExpiringTokens)
	}
}

// TestHealthCheckJob_HandlesErrorsGracefully tests that one failure doesn't stop others
func TestHealthCheckJob_HandlesErrorsGracefully(t *testing.T) {
	store := &MockCredentialStore{
		needingCheck: []*services.PlatformCredentials{
			{UserID: "user1", Platform: "threads"},
			{UserID: "user2", Platform: "linkedin"},
			{UserID: "user3", Platform: "bluesky"},
		},
	}
	tester := NewMockConnectionTester()
	// Middle one fails
	tester.SetResult("linkedin", errors.New("API error"))

	job := NewHealthCheckJob(store, tester, DefaultConfig())
	result := job.Run(context.Background())

	// Should still check all 3, even though one failed
	if result.Checked != 3 {
		t.Errorf("Expected 3 checked, got %d", result.Checked)
	}
	// The error should not be propagated to result.Err
	if result.Err != nil {
		t.Errorf("Expected no error, got: %v", result.Err)
	}
	// But we should have recorded the failures
	if result.Unhealthy != 1 {
		t.Errorf("Expected 1 unhealthy, got %d", result.Unhealthy)
	}
	if result.Healthy != 2 {
		t.Errorf("Expected 2 healthy, got %d", result.Healthy)
	}
}

// TestHealthCheckJob_RespectsCheckInterval tests that only stale connections are checked
func TestHealthCheckJob_RespectsCheckInterval(t *testing.T) {
	store := &MockCredentialStore{
		needingCheck: []*services.PlatformCredentials{
			// Only credentials needing check are returned
			{UserID: "stale-user", Platform: "threads"},
		},
	}
	tester := NewMockConnectionTester()

	cfg := DefaultConfig()
	cfg.CheckInterval = 24 * time.Hour

	job := NewHealthCheckJob(store, tester, cfg)
	result := job.Run(context.Background())

	if result.Checked != 1 {
		t.Errorf("Expected 1 checked (only stale one), got %d", result.Checked)
	}
}

// TestHealthCheckJob_GetCredentialsError tests handling of GetCredentialsNeedingCheck error
func TestHealthCheckJob_GetCredentialsError(t *testing.T) {
	store := &MockCredentialStore{
		getNeedingCheckErr: errors.New("database connection failed"),
	}
	tester := NewMockConnectionTester()

	job := NewHealthCheckJob(store, tester, DefaultConfig())
	result := job.Run(context.Background())

	if result.Err == nil {
		t.Error("Expected error when GetCredentialsNeedingCheck fails")
	}
}

// TestHealthCheckJob_UpdateHealthError tests handling of UpdateHealthStatus error
func TestHealthCheckJob_UpdateHealthError(t *testing.T) {
	store := &MockCredentialStore{
		needingCheck: []*services.PlatformCredentials{
			{UserID: "user1", Platform: "threads"},
			{UserID: "user2", Platform: "linkedin"},
		},
		updateHealthErr: errors.New("update failed"),
	}
	tester := NewMockConnectionTester()

	job := NewHealthCheckJob(store, tester, DefaultConfig())
	result := job.Run(context.Background())

	// Job should continue despite update errors
	if result.Checked != 2 {
		t.Errorf("Expected 2 checked, got %d", result.Checked)
	}
	// Update errors are tracked
	if result.UpdateErrors != 2 {
		t.Errorf("Expected 2 update errors, got %d", result.UpdateErrors)
	}
}

// TestDefaultConfig tests default configuration values
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.CheckInterval != 24*time.Hour {
		t.Errorf("Expected 24h check interval, got %v", cfg.CheckInterval)
	}
	if cfg.ExpiryWarningDays != 7 {
		t.Errorf("Expected 7 days expiry warning, got %d", cfg.ExpiryWarningDays)
	}
}
