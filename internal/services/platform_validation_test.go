package services

import (
	"context"
	"errors"
	"testing"
	"time"
)

// =============================================================================
// Platform Validation Tests (Task 10.2)
// Tests for Requirements 7.1, 7.2:
// - 7.1: WHEN a user clicks "Post It", THE System SHALL validate that at least
//        one platform is selected
// - 7.2: WHEN no platforms are selected, THE System SHALL display an error message
// =============================================================================

// Error definitions for platform validation
var (
	ErrNoPlatformsConnected = errors.New("no platforms connected")
)

// PlatformValidator validates that user has required platform connections
type PlatformValidator interface {
	// ValidateHasConnectedPlatform checks that the user has at least one
	// healthy platform connection. Returns ErrNoPlatformsConnected if no
	// platforms are connected, or another error if the check fails.
	ValidateHasConnectedPlatform(ctx context.Context, userID string) error

	// GetConnectedPlatforms returns a list of platform names that the user
	// has healthy connections to. Returns an empty slice if none.
	GetConnectedPlatforms(ctx context.Context, userID string) ([]string, error)
}

// platformValidator implements PlatformValidator using ConnectionService
type platformValidator struct {
	connectionService ConnectionService
}

// NewPlatformValidator creates a new PlatformValidator
func NewPlatformValidator(cs ConnectionService) PlatformValidator {
	return &platformValidator{connectionService: cs}
}

// ValidateHasConnectedPlatform implements PlatformValidator
func (v *platformValidator) ValidateHasConnectedPlatform(ctx context.Context, userID string) error {
	connections, err := v.connectionService.ListConnections(ctx, userID)
	if err != nil {
		return err
	}

	// Check if any connection is healthy
	for _, conn := range connections {
		if conn.IsHealthy() {
			return nil
		}
	}

	return ErrNoPlatformsConnected
}

// GetConnectedPlatforms implements PlatformValidator
func (v *platformValidator) GetConnectedPlatforms(ctx context.Context, userID string) ([]string, error) {
	connections, err := v.connectionService.ListConnections(ctx, userID)
	if err != nil {
		return nil, err
	}

	var platforms []string
	for _, conn := range connections {
		if conn.IsHealthy() {
			platforms = append(platforms, conn.Platform)
		}
	}

	return platforms, nil
}

// =============================================================================
// Test: Error when no platforms are connected
// Requirement 7.2: When no platforms are selected, display an error message
// =============================================================================

func TestValidateHasConnectedPlatform_NoPlatforms_ReturnsError(t *testing.T) {
	// Arrange: User with no platform connections
	connService := NewMockConnectionService()
	validator := NewPlatformValidator(connService)
	ctx := context.Background()
	userID := "user-with-no-connections"

	// Act: Validate platform connection
	err := validator.ValidateHasConnectedPlatform(ctx, userID)

	// Assert: Should return ErrNoPlatformsConnected
	if !errors.Is(err, ErrNoPlatformsConnected) {
		t.Errorf("ValidateHasConnectedPlatform() error = %v, want %v", err, ErrNoPlatformsConnected)
	}
}

func TestValidateHasConnectedPlatform_AllDisconnected_ReturnsError(t *testing.T) {
	// Arrange: User with connections but all are disconnected
	connService := NewMockConnectionService()
	validator := NewPlatformValidator(connService)
	ctx := context.Background()
	userID := "user-disconnected-platforms"

	// Add disconnected connections
	connService.AddConnection(&Connection{
		UserID:   userID,
		Platform: PlatformBluesky,
		Status:   ConnectionStatusDisconnected,
	})
	connService.AddConnection(&Connection{
		UserID:   userID,
		Platform: PlatformThreads,
		Status:   ConnectionStatusDisconnected,
	})

	// Act: Validate platform connection
	err := validator.ValidateHasConnectedPlatform(ctx, userID)

	// Assert: Should return ErrNoPlatformsConnected
	if !errors.Is(err, ErrNoPlatformsConnected) {
		t.Errorf("ValidateHasConnectedPlatform() error = %v, want %v", err, ErrNoPlatformsConnected)
	}
}

func TestValidateHasConnectedPlatform_AllExpired_ReturnsError(t *testing.T) {
	// Arrange: User with connections but all tokens are expired
	connService := NewMockConnectionService()
	validator := NewPlatformValidator(connService)
	ctx := context.Background()
	userID := "user-expired-tokens"

	// Add expired connections
	expiredTime := time.Now().Add(-24 * time.Hour)
	connService.AddConnection(&Connection{
		UserID:    userID,
		Platform:  PlatformBluesky,
		Status:    ConnectionStatusExpired,
		ExpiresAt: &expiredTime,
	})

	// Act: Validate platform connection
	err := validator.ValidateHasConnectedPlatform(ctx, userID)

	// Assert: Should return ErrNoPlatformsConnected
	if !errors.Is(err, ErrNoPlatformsConnected) {
		t.Errorf("ValidateHasConnectedPlatform() error = %v, want %v", err, ErrNoPlatformsConnected)
	}
}

func TestValidateHasConnectedPlatform_AllInErrorState_ReturnsError(t *testing.T) {
	// Arrange: User with connections but all are in error state
	connService := NewMockConnectionService()
	validator := NewPlatformValidator(connService)
	ctx := context.Background()
	userID := "user-error-connections"

	// Add connections in error state
	connService.AddConnection(&Connection{
		UserID:    userID,
		Platform:  PlatformBluesky,
		Status:    ConnectionStatusError,
		LastError: "API returned 500",
	})

	// Act: Validate platform connection
	err := validator.ValidateHasConnectedPlatform(ctx, userID)

	// Assert: Should return ErrNoPlatformsConnected
	if !errors.Is(err, ErrNoPlatformsConnected) {
		t.Errorf("ValidateHasConnectedPlatform() error = %v, want %v", err, ErrNoPlatformsConnected)
	}
}

// =============================================================================
// Test: Success when at least one platform is connected
// Requirement 7.1: Validate that at least one platform is selected
// =============================================================================

func TestValidateHasConnectedPlatform_OneHealthyPlatform_ReturnsNil(t *testing.T) {
	// Arrange: User with one healthy platform connection
	connService := NewMockConnectionService()
	validator := NewPlatformValidator(connService)
	ctx := context.Background()
	userID := "user-one-platform"

	// Add one healthy connection
	now := time.Now()
	futureExpiry := now.Add(30 * 24 * time.Hour)
	connService.AddConnection(&Connection{
		UserID:      userID,
		Platform:    PlatformBluesky,
		Status:      ConnectionStatusConnected,
		ConnectedAt: &now,
		ExpiresAt:   &futureExpiry,
	})

	// Act: Validate platform connection
	err := validator.ValidateHasConnectedPlatform(ctx, userID)

	// Assert: Should return nil (success)
	if err != nil {
		t.Errorf("ValidateHasConnectedPlatform() error = %v, want nil", err)
	}
}

func TestValidateHasConnectedPlatform_MultipleHealthyPlatforms_ReturnsNil(t *testing.T) {
	// Arrange: User with multiple healthy platform connections
	connService := NewMockConnectionService()
	validator := NewPlatformValidator(connService)
	ctx := context.Background()
	userID := "user-multiple-platforms"

	// Add multiple healthy connections
	now := time.Now()
	futureExpiry := now.Add(30 * 24 * time.Hour)
	connService.AddConnection(&Connection{
		UserID:      userID,
		Platform:    PlatformBluesky,
		Status:      ConnectionStatusConnected,
		ConnectedAt: &now,
		ExpiresAt:   &futureExpiry,
	})
	connService.AddConnection(&Connection{
		UserID:      userID,
		Platform:    PlatformThreads,
		Status:      ConnectionStatusConnected,
		ConnectedAt: &now,
		ExpiresAt:   &futureExpiry,
	})

	// Act: Validate platform connection
	err := validator.ValidateHasConnectedPlatform(ctx, userID)

	// Assert: Should return nil (success)
	if err != nil {
		t.Errorf("ValidateHasConnectedPlatform() error = %v, want nil", err)
	}
}

func TestValidateHasConnectedPlatform_OneHealthyAmongUnhealthy_ReturnsNil(t *testing.T) {
	// Arrange: User with one healthy connection among several unhealthy ones
	connService := NewMockConnectionService()
	validator := NewPlatformValidator(connService)
	ctx := context.Background()
	userID := "user-mixed-connections"

	now := time.Now()
	futureExpiry := now.Add(30 * 24 * time.Hour)
	expiredTime := now.Add(-24 * time.Hour)

	// Add one healthy connection
	connService.AddConnection(&Connection{
		UserID:      userID,
		Platform:    PlatformBluesky,
		Status:      ConnectionStatusConnected,
		ConnectedAt: &now,
		ExpiresAt:   &futureExpiry,
	})
	// Add expired connection
	connService.AddConnection(&Connection{
		UserID:    userID,
		Platform:  PlatformThreads,
		Status:    ConnectionStatusExpired,
		ExpiresAt: &expiredTime,
	})
	// Add disconnected connection
	connService.AddConnection(&Connection{
		UserID:   userID,
		Platform: PlatformLinkedIn,
		Status:   ConnectionStatusDisconnected,
	})

	// Act: Validate platform connection
	err := validator.ValidateHasConnectedPlatform(ctx, userID)

	// Assert: Should return nil (success) because Bluesky is healthy
	if err != nil {
		t.Errorf("ValidateHasConnectedPlatform() error = %v, want nil", err)
	}
}

func TestValidateHasConnectedPlatform_NoExpiryToken_ReturnsNil(t *testing.T) {
	// Arrange: User with a connection that has no expiry (like Bluesky app passwords)
	connService := NewMockConnectionService()
	validator := NewPlatformValidator(connService)
	ctx := context.Background()
	userID := "user-no-expiry"

	now := time.Now()
	// Bluesky app passwords don't expire
	connService.AddConnection(&Connection{
		UserID:      userID,
		Platform:    PlatformBluesky,
		Status:      ConnectionStatusConnected,
		ConnectedAt: &now,
		ExpiresAt:   nil, // No expiry
	})

	// Act: Validate platform connection
	err := validator.ValidateHasConnectedPlatform(ctx, userID)

	// Assert: Should return nil (success)
	if err != nil {
		t.Errorf("ValidateHasConnectedPlatform() error = %v, want nil", err)
	}
}

// =============================================================================
// Test: Proper error message returned
// Requirement 7.2: Display an error message when no platforms are selected
// =============================================================================

func TestErrNoPlatformsConnected_HasDescriptiveMessage(t *testing.T) {
	// Assert: Error message should be clear and actionable
	expected := "no platforms connected"
	if ErrNoPlatformsConnected.Error() != expected {
		t.Errorf("ErrNoPlatformsConnected.Error() = %q, want %q",
			ErrNoPlatformsConnected.Error(), expected)
	}
}

func TestValidateHasConnectedPlatform_ErrorIsCheckable(t *testing.T) {
	// Arrange: User with no connections
	connService := NewMockConnectionService()
	validator := NewPlatformValidator(connService)
	ctx := context.Background()
	userID := "user-no-connections"

	// Act: Validate platform connection
	err := validator.ValidateHasConnectedPlatform(ctx, userID)

	// Assert: Error should be checkable with errors.Is
	if !errors.Is(err, ErrNoPlatformsConnected) {
		t.Error("Error should be checkable with errors.Is(err, ErrNoPlatformsConnected)")
	}
}

// =============================================================================
// Test: GetConnectedPlatforms helper function
// =============================================================================

func TestGetConnectedPlatforms_NoPlatforms_ReturnsEmptySlice(t *testing.T) {
	// Arrange
	connService := NewMockConnectionService()
	validator := NewPlatformValidator(connService)
	ctx := context.Background()
	userID := "user-no-platforms"

	// Act
	platforms, err := validator.GetConnectedPlatforms(ctx, userID)

	// Assert
	if err != nil {
		t.Fatalf("GetConnectedPlatforms() error = %v, want nil", err)
	}
	if len(platforms) != 0 {
		t.Errorf("GetConnectedPlatforms() = %v, want empty slice", platforms)
	}
}

func TestGetConnectedPlatforms_OnlyHealthyPlatforms_ReturnsHealthyPlatforms(t *testing.T) {
	// Arrange
	connService := NewMockConnectionService()
	validator := NewPlatformValidator(connService)
	ctx := context.Background()
	userID := "user-mixed-platforms"

	now := time.Now()
	futureExpiry := now.Add(30 * 24 * time.Hour)
	expiredTime := now.Add(-24 * time.Hour)

	// Add healthy Bluesky
	connService.AddConnection(&Connection{
		UserID:      userID,
		Platform:    PlatformBluesky,
		Status:      ConnectionStatusConnected,
		ConnectedAt: &now,
		ExpiresAt:   &futureExpiry,
	})
	// Add expired Threads
	connService.AddConnection(&Connection{
		UserID:    userID,
		Platform:  PlatformThreads,
		Status:    ConnectionStatusExpired,
		ExpiresAt: &expiredTime,
	})

	// Act
	platforms, err := validator.GetConnectedPlatforms(ctx, userID)

	// Assert
	if err != nil {
		t.Fatalf("GetConnectedPlatforms() error = %v, want nil", err)
	}
	if len(platforms) != 1 {
		t.Errorf("GetConnectedPlatforms() returned %d platforms, want 1", len(platforms))
	}
	if len(platforms) > 0 && platforms[0] != PlatformBluesky {
		t.Errorf("GetConnectedPlatforms()[0] = %q, want %q", platforms[0], PlatformBluesky)
	}
}

func TestGetConnectedPlatforms_MultipleHealthy_ReturnsAll(t *testing.T) {
	// Arrange
	connService := NewMockConnectionService()
	validator := NewPlatformValidator(connService)
	ctx := context.Background()
	userID := "user-multiple-healthy"

	now := time.Now()
	futureExpiry := now.Add(30 * 24 * time.Hour)

	connService.AddConnection(&Connection{
		UserID:      userID,
		Platform:    PlatformBluesky,
		Status:      ConnectionStatusConnected,
		ConnectedAt: &now,
		ExpiresAt:   &futureExpiry,
	})
	connService.AddConnection(&Connection{
		UserID:      userID,
		Platform:    PlatformThreads,
		Status:      ConnectionStatusConnected,
		ConnectedAt: &now,
		ExpiresAt:   &futureExpiry,
	})

	// Act
	platforms, err := validator.GetConnectedPlatforms(ctx, userID)

	// Assert
	if err != nil {
		t.Fatalf("GetConnectedPlatforms() error = %v, want nil", err)
	}
	if len(platforms) != 2 {
		t.Errorf("GetConnectedPlatforms() returned %d platforms, want 2", len(platforms))
	}
}

// =============================================================================
// Test: Connection status expired but status says connected
// Edge case: Token expired but status wasn't updated yet
// =============================================================================

func TestValidateHasConnectedPlatform_ConnectedButTokenExpired_ReturnsError(t *testing.T) {
	// Arrange: Connection status is "connected" but token is actually expired
	// This can happen if the health check hasn't run yet
	connService := NewMockConnectionService()
	validator := NewPlatformValidator(connService)
	ctx := context.Background()
	userID := "user-stale-status"

	now := time.Now()
	expiredTime := now.Add(-24 * time.Hour)

	// Status says connected but token is expired
	connService.AddConnection(&Connection{
		UserID:      userID,
		Platform:    PlatformBluesky,
		Status:      ConnectionStatusConnected, // Status not updated yet
		ConnectedAt: &now,
		ExpiresAt:   &expiredTime, // But token is expired
	})

	// Act: Validate platform connection
	err := validator.ValidateHasConnectedPlatform(ctx, userID)

	// Assert: Should return error because IsHealthy() checks expiry
	if !errors.Is(err, ErrNoPlatformsConnected) {
		t.Errorf("ValidateHasConnectedPlatform() error = %v, want %v", err, ErrNoPlatformsConnected)
	}
}
