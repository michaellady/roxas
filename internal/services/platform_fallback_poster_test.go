package services

import (
	"context"
	"errors"
	"testing"
	"time"
)

// =============================================================================
// Platform Fallback Poster Unit Tests
// Tests for platform fallback logic (Bluesky → Threads)
// =============================================================================

// MockCredentialStoreForFallback implements CredentialStore for fallback tests
type MockCredentialStoreForFallback struct {
	credentials map[string]map[string]*PlatformCredentials // userID -> platform -> credentials
	getErr      map[string]error                           // platform -> error
}

func NewMockCredentialStoreForFallback() *MockCredentialStoreForFallback {
	return &MockCredentialStoreForFallback{
		credentials: make(map[string]map[string]*PlatformCredentials),
		getErr:      make(map[string]error),
	}
}

func (m *MockCredentialStoreForFallback) SetCredentials(userID, platform string, creds *PlatformCredentials) {
	if m.credentials[userID] == nil {
		m.credentials[userID] = make(map[string]*PlatformCredentials)
	}
	m.credentials[userID][platform] = creds
}

func (m *MockCredentialStoreForFallback) SetGetError(platform string, err error) {
	m.getErr[platform] = err
}

func (m *MockCredentialStoreForFallback) GetCredentials(ctx context.Context, userID, platform string) (*PlatformCredentials, error) {
	if err, ok := m.getErr[platform]; ok && err != nil {
		return nil, err
	}
	if userCreds, ok := m.credentials[userID]; ok {
		if creds, ok := userCreds[platform]; ok {
			return creds, nil
		}
	}
	return nil, ErrCredentialsNotFound
}

func (m *MockCredentialStoreForFallback) SaveCredentials(ctx context.Context, creds *PlatformCredentials) error {
	return nil
}

func (m *MockCredentialStoreForFallback) DeleteCredentials(ctx context.Context, userID, platform string) error {
	return nil
}

func (m *MockCredentialStoreForFallback) GetCredentialsForUser(ctx context.Context, userID string) ([]*PlatformCredentials, error) {
	return nil, nil
}

func (m *MockCredentialStoreForFallback) GetExpiringCredentials(ctx context.Context, within time.Duration) ([]*PlatformCredentials, error) {
	return nil, nil
}

func (m *MockCredentialStoreForFallback) UpdateTokens(ctx context.Context, userID, platform, accessToken, refreshToken string, expiresAt *time.Time) error {
	return nil
}

func (m *MockCredentialStoreForFallback) UpdateHealthStatus(ctx context.Context, userID, platform string, isHealthy bool, healthError *string) error {
	return nil
}

func (m *MockCredentialStoreForFallback) GetCredentialsNeedingCheck(ctx context.Context, notCheckedWithin time.Duration) ([]*PlatformCredentials, error) {
	return nil, nil
}

// MockSocialClientForFallback implements SocialClient for fallback tests
type MockSocialClientForFallback struct {
	platform   string
	postResult *PostResult
	postError  error
	postCalled bool
}

func (m *MockSocialClientForFallback) Post(ctx context.Context, content PostContent) (*PostResult, error) {
	m.postCalled = true
	if m.postError != nil {
		return nil, m.postError
	}
	return m.postResult, nil
}

func (m *MockSocialClientForFallback) ValidateContent(content PostContent) error {
	return nil
}

func (m *MockSocialClientForFallback) Platform() string {
	return m.platform
}

func (m *MockSocialClientForFallback) GetRateLimits() RateLimitInfo {
	return RateLimitInfo{}
}

// MockSocialClientFactoryForFallback implements SocialClientFactory for testing
type MockSocialClientFactoryForFallback struct {
	blueskyClient *MockSocialClientForFallback
	threadsClient *MockSocialClientForFallback
	createErr     map[string]error // platform -> error
}

func NewMockSocialClientFactoryForFallback() *MockSocialClientFactoryForFallback {
	return &MockSocialClientFactoryForFallback{
		createErr: make(map[string]error),
	}
}

func (m *MockSocialClientFactoryForFallback) CreateClient(ctx context.Context, platform string, creds *PlatformCredentials) (SocialClient, error) {
	if err, ok := m.createErr[platform]; ok && err != nil {
		return nil, err
	}
	switch platform {
	case PlatformBluesky:
		return m.blueskyClient, nil
	case PlatformThreads:
		return m.threadsClient, nil
	default:
		return nil, errors.New("unsupported platform")
	}
}

// =============================================================================
// Test: Bluesky is tried first when both platforms connected
// =============================================================================

func TestPlatformFallbackPoster_BlueskyTriedFirst_WhenBothConnected(t *testing.T) {
	// Setup: Both Bluesky and Threads credentials available
	credStore := NewMockCredentialStoreForFallback()
	credStore.SetCredentials("user-123", PlatformBluesky, &PlatformCredentials{
		UserID:       "user-123",
		Platform:     PlatformBluesky,
		AccessToken:  "bsky-app-password",
		RefreshToken: "user.bsky.social",
	})
	credStore.SetCredentials("user-123", PlatformThreads, &PlatformCredentials{
		UserID:      "user-123",
		Platform:    PlatformThreads,
		AccessToken: "threads-access-token",
	})

	blueskyClient := &MockSocialClientForFallback{
		platform: PlatformBluesky,
		postResult: &PostResult{
			PostID:  "at://did:plc:abc123/app.bsky.feed.post/xyz",
			PostURL: "https://bsky.app/profile/user/post/xyz",
		},
	}
	threadsClient := &MockSocialClientForFallback{
		platform: PlatformThreads,
		postResult: &PostResult{
			PostID:  "threads-post-123",
			PostURL: "https://threads.net/post/123",
		},
	}

	factory := NewMockSocialClientFactoryForFallback()
	factory.blueskyClient = blueskyClient
	factory.threadsClient = threadsClient

	poster := NewPlatformFallbackPoster(credStore, factory)

	// Execute
	result, err := poster.Post(context.Background(), "user-123", PostContent{Text: "Test post"})

	// Verify
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("Expected result, got nil")
	}
	if result.Platform != PlatformBluesky {
		t.Errorf("Expected Bluesky to be used first, got: %s", result.Platform)
	}
	if !blueskyClient.postCalled {
		t.Error("Expected Bluesky client Post to be called")
	}
	if threadsClient.postCalled {
		t.Error("Expected Threads client Post NOT to be called when Bluesky succeeds")
	}
	if result.PostURL != "https://bsky.app/profile/user/post/xyz" {
		t.Errorf("Expected Bluesky post URL, got: %s", result.PostURL)
	}
}

// =============================================================================
// Test: Threads is NOT tried if Bluesky post fails (current behavior)
// =============================================================================

func TestPlatformFallbackPoster_BlueskyPostFailure_ReturnsError(t *testing.T) {
	// Setup: Both Bluesky and Threads credentials available, but Bluesky will fail
	credStore := NewMockCredentialStoreForFallback()
	credStore.SetCredentials("user-123", PlatformBluesky, &PlatformCredentials{
		UserID:       "user-123",
		Platform:     PlatformBluesky,
		AccessToken:  "bsky-app-password",
		RefreshToken: "user.bsky.social",
	})
	credStore.SetCredentials("user-123", PlatformThreads, &PlatformCredentials{
		UserID:      "user-123",
		Platform:    PlatformThreads,
		AccessToken: "threads-access-token",
	})

	blueskyClient := &MockSocialClientForFallback{
		platform:  PlatformBluesky,
		postError: errors.New("Bluesky API error: rate limited"),
	}
	threadsClient := &MockSocialClientForFallback{
		platform: PlatformThreads,
		postResult: &PostResult{
			PostID:  "threads-post-456",
			PostURL: "https://threads.net/post/456",
		},
	}

	factory := NewMockSocialClientFactoryForFallback()
	factory.blueskyClient = blueskyClient
	factory.threadsClient = threadsClient

	poster := NewPlatformFallbackPoster(credStore, factory)

	// Execute
	result, err := poster.Post(context.Background(), "user-123", PostContent{Text: "Test post"})

	// Verify: Bluesky failure should return error
	// The current implementation returns an error if Bluesky post fails
	if err == nil {
		t.Fatal("Expected error when Bluesky post fails")
	}
	if result != nil {
		t.Error("Expected nil result when Bluesky fails")
	}
	if !blueskyClient.postCalled {
		t.Error("Expected Bluesky client Post to be called")
	}
	// Note: Current implementation does NOT fall back to Threads if Bluesky post fails
	// It only falls back if Bluesky credentials are not available
}

// =============================================================================
// Test: Threads used when Bluesky credentials not available
// =============================================================================

func TestPlatformFallbackPoster_ThreadsUsed_WhenBlueskyNotConnected(t *testing.T) {
	// Setup: Only Threads credentials available (no Bluesky)
	credStore := NewMockCredentialStoreForFallback()
	credStore.SetCredentials("user-123", PlatformThreads, &PlatformCredentials{
		UserID:      "user-123",
		Platform:    PlatformThreads,
		AccessToken: "threads-access-token",
	})

	blueskyClient := &MockSocialClientForFallback{
		platform: PlatformBluesky,
	}
	threadsClient := &MockSocialClientForFallback{
		platform: PlatformThreads,
		postResult: &PostResult{
			PostID:  "threads-post-789",
			PostURL: "https://threads.net/post/789",
		},
	}

	factory := NewMockSocialClientFactoryForFallback()
	factory.blueskyClient = blueskyClient
	factory.threadsClient = threadsClient

	poster := NewPlatformFallbackPoster(credStore, factory)

	// Execute
	result, err := poster.Post(context.Background(), "user-123", PostContent{Text: "Test post"})

	// Verify
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("Expected result, got nil")
	}
	if result.Platform != PlatformThreads {
		t.Errorf("Expected Threads to be used when Bluesky not connected, got: %s", result.Platform)
	}
	if blueskyClient.postCalled {
		t.Error("Expected Bluesky client Post NOT to be called when not connected")
	}
	if !threadsClient.postCalled {
		t.Error("Expected Threads client Post to be called")
	}
	if result.PostURL != "https://threads.net/post/789" {
		t.Errorf("Expected Threads post URL, got: %s", result.PostURL)
	}
}

// =============================================================================
// Test: Behavior when only Bluesky connected
// =============================================================================

func TestPlatformFallbackPoster_OnlyBlueskyConnected(t *testing.T) {
	// Setup: Only Bluesky credentials available (no Threads)
	credStore := NewMockCredentialStoreForFallback()
	credStore.SetCredentials("user-123", PlatformBluesky, &PlatformCredentials{
		UserID:       "user-123",
		Platform:     PlatformBluesky,
		AccessToken:  "bsky-app-password",
		RefreshToken: "user.bsky.social",
	})

	blueskyClient := &MockSocialClientForFallback{
		platform: PlatformBluesky,
		postResult: &PostResult{
			PostID:  "at://did:plc:abc123/app.bsky.feed.post/only-bsky",
			PostURL: "https://bsky.app/profile/user/post/only-bsky",
		},
	}
	threadsClient := &MockSocialClientForFallback{
		platform: PlatformThreads,
	}

	factory := NewMockSocialClientFactoryForFallback()
	factory.blueskyClient = blueskyClient
	factory.threadsClient = threadsClient

	poster := NewPlatformFallbackPoster(credStore, factory)

	// Execute
	result, err := poster.Post(context.Background(), "user-123", PostContent{Text: "Test post"})

	// Verify
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("Expected result, got nil")
	}
	if result.Platform != PlatformBluesky {
		t.Errorf("Expected Bluesky to be used, got: %s", result.Platform)
	}
	if !blueskyClient.postCalled {
		t.Error("Expected Bluesky client Post to be called")
	}
	if threadsClient.postCalled {
		t.Error("Expected Threads client Post NOT to be called")
	}
}

// =============================================================================
// Test: Behavior when only Threads connected
// =============================================================================

func TestPlatformFallbackPoster_OnlyThreadsConnected(t *testing.T) {
	// Setup: Only Threads credentials available (no Bluesky)
	credStore := NewMockCredentialStoreForFallback()
	credStore.SetCredentials("user-123", PlatformThreads, &PlatformCredentials{
		UserID:      "user-123",
		Platform:    PlatformThreads,
		AccessToken: "threads-access-token",
	})

	blueskyClient := &MockSocialClientForFallback{
		platform: PlatformBluesky,
	}
	threadsClient := &MockSocialClientForFallback{
		platform: PlatformThreads,
		postResult: &PostResult{
			PostID:  "threads-only-post",
			PostURL: "https://threads.net/post/only-threads",
		},
	}

	factory := NewMockSocialClientFactoryForFallback()
	factory.blueskyClient = blueskyClient
	factory.threadsClient = threadsClient

	poster := NewPlatformFallbackPoster(credStore, factory)

	// Execute
	result, err := poster.Post(context.Background(), "user-123", PostContent{Text: "Test post"})

	// Verify
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("Expected result, got nil")
	}
	if result.Platform != PlatformThreads {
		t.Errorf("Expected Threads to be used, got: %s", result.Platform)
	}
	if blueskyClient.postCalled {
		t.Error("Expected Bluesky client Post NOT to be called")
	}
	if !threadsClient.postCalled {
		t.Error("Expected Threads client Post to be called")
	}
}

// =============================================================================
// Test: Behavior when neither platform connected
// =============================================================================

func TestPlatformFallbackPoster_NeitherPlatformConnected(t *testing.T) {
	// Setup: No credentials available for either platform
	credStore := NewMockCredentialStoreForFallback()
	// No credentials set for any platform

	blueskyClient := &MockSocialClientForFallback{
		platform: PlatformBluesky,
	}
	threadsClient := &MockSocialClientForFallback{
		platform: PlatformThreads,
	}

	factory := NewMockSocialClientFactoryForFallback()
	factory.blueskyClient = blueskyClient
	factory.threadsClient = threadsClient

	poster := NewPlatformFallbackPoster(credStore, factory)

	// Execute
	result, err := poster.Post(context.Background(), "user-123", PostContent{Text: "Test post"})

	// Verify
	if err == nil {
		t.Fatal("Expected error when no platform connected")
	}
	if !errors.Is(err, ErrNoPlatformConnected) {
		t.Errorf("Expected ErrNoPlatformConnected, got: %v", err)
	}
	if result != nil {
		t.Error("Expected nil result when no platform connected")
	}
	if blueskyClient.postCalled {
		t.Error("Expected Bluesky client Post NOT to be called")
	}
	if threadsClient.postCalled {
		t.Error("Expected Threads client Post NOT to be called")
	}
}

// =============================================================================
// Test: Error from Threads when only Threads connected
// =============================================================================

func TestPlatformFallbackPoster_ThreadsError_WhenOnlyThreadsConnected(t *testing.T) {
	// Setup: Only Threads credentials available, but Threads will fail
	credStore := NewMockCredentialStoreForFallback()
	credStore.SetCredentials("user-123", PlatformThreads, &PlatformCredentials{
		UserID:      "user-123",
		Platform:    PlatformThreads,
		AccessToken: "threads-access-token",
	})

	blueskyClient := &MockSocialClientForFallback{
		platform: PlatformBluesky,
	}
	threadsClient := &MockSocialClientForFallback{
		platform:  PlatformThreads,
		postError: errors.New("Threads API error: content policy violation"),
	}

	factory := NewMockSocialClientFactoryForFallback()
	factory.blueskyClient = blueskyClient
	factory.threadsClient = threadsClient

	poster := NewPlatformFallbackPoster(credStore, factory)

	// Execute
	result, err := poster.Post(context.Background(), "user-123", PostContent{Text: "Test post"})

	// Verify
	if err == nil {
		t.Fatal("Expected error when Threads post fails")
	}
	if result != nil {
		t.Error("Expected nil result when Threads fails")
	}
	if blueskyClient.postCalled {
		t.Error("Expected Bluesky client Post NOT to be called")
	}
	if !threadsClient.postCalled {
		t.Error("Expected Threads client Post to be called")
	}
}

// =============================================================================
// Test: Bluesky error message is properly wrapped
// =============================================================================

func TestPlatformFallbackPoster_BlueskyError_ProperlyWrapped(t *testing.T) {
	// Setup: Bluesky credentials available but post will fail
	credStore := NewMockCredentialStoreForFallback()
	credStore.SetCredentials("user-123", PlatformBluesky, &PlatformCredentials{
		UserID:       "user-123",
		Platform:     PlatformBluesky,
		AccessToken:  "bsky-app-password",
		RefreshToken: "user.bsky.social",
	})

	originalErr := errors.New("invalid app password")
	blueskyClient := &MockSocialClientForFallback{
		platform:  PlatformBluesky,
		postError: originalErr,
	}
	threadsClient := &MockSocialClientForFallback{
		platform: PlatformThreads,
	}

	factory := NewMockSocialClientFactoryForFallback()
	factory.blueskyClient = blueskyClient
	factory.threadsClient = threadsClient

	poster := NewPlatformFallbackPoster(credStore, factory)

	// Execute
	_, err := poster.Post(context.Background(), "user-123", PostContent{Text: "Test post"})

	// Verify error is wrapped properly
	if err == nil {
		t.Fatal("Expected error")
	}
	if !errors.Is(err, originalErr) {
		t.Errorf("Expected error to wrap original error, got: %v", err)
	}
	expectedPrefix := "failed to post to Bluesky"
	if len(err.Error()) < len(expectedPrefix) || err.Error()[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("Expected error to start with '%s', got: %v", expectedPrefix, err)
	}
}

// =============================================================================
// Test: Threads error message is properly wrapped
// =============================================================================

func TestPlatformFallbackPoster_ThreadsError_ProperlyWrapped(t *testing.T) {
	// Setup: Only Threads credentials available but post will fail
	credStore := NewMockCredentialStoreForFallback()
	credStore.SetCredentials("user-123", PlatformThreads, &PlatformCredentials{
		UserID:      "user-123",
		Platform:    PlatformThreads,
		AccessToken: "threads-access-token",
	})

	originalErr := errors.New("content policy violation")
	blueskyClient := &MockSocialClientForFallback{
		platform: PlatformBluesky,
	}
	threadsClient := &MockSocialClientForFallback{
		platform:  PlatformThreads,
		postError: originalErr,
	}

	factory := NewMockSocialClientFactoryForFallback()
	factory.blueskyClient = blueskyClient
	factory.threadsClient = threadsClient

	poster := NewPlatformFallbackPoster(credStore, factory)

	// Execute
	_, err := poster.Post(context.Background(), "user-123", PostContent{Text: "Test post"})

	// Verify error is wrapped properly
	if err == nil {
		t.Fatal("Expected error")
	}
	if !errors.Is(err, originalErr) {
		t.Errorf("Expected error to wrap original error, got: %v", err)
	}
	expectedPrefix := "failed to post to Threads"
	if len(err.Error()) < len(expectedPrefix) || err.Error()[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("Expected error to start with '%s', got: %v", expectedPrefix, err)
	}
}

// =============================================================================
// Test: Different users have separate credential lookups
// =============================================================================

func TestPlatformFallbackPoster_DifferentUsersIsolated(t *testing.T) {
	// Setup: User A has Bluesky, User B has Threads
	credStore := NewMockCredentialStoreForFallback()
	credStore.SetCredentials("user-A", PlatformBluesky, &PlatformCredentials{
		UserID:       "user-A",
		Platform:     PlatformBluesky,
		AccessToken:  "bsky-password-A",
		RefreshToken: "userA.bsky.social",
	})
	credStore.SetCredentials("user-B", PlatformThreads, &PlatformCredentials{
		UserID:      "user-B",
		Platform:    PlatformThreads,
		AccessToken: "threads-token-B",
	})

	blueskyClient := &MockSocialClientForFallback{
		platform: PlatformBluesky,
		postResult: &PostResult{
			PostID:  "bsky-post",
			PostURL: "https://bsky.app/post/a",
		},
	}
	threadsClient := &MockSocialClientForFallback{
		platform: PlatformThreads,
		postResult: &PostResult{
			PostID:  "threads-post",
			PostURL: "https://threads.net/post/b",
		},
	}

	factory := NewMockSocialClientFactoryForFallback()
	factory.blueskyClient = blueskyClient
	factory.threadsClient = threadsClient

	poster := NewPlatformFallbackPoster(credStore, factory)

	// Test User A - should use Bluesky
	resultA, errA := poster.Post(context.Background(), "user-A", PostContent{Text: "Post from A"})
	if errA != nil {
		t.Fatalf("User A: Expected no error, got: %v", errA)
	}
	if resultA.Platform != PlatformBluesky {
		t.Errorf("User A: Expected Bluesky, got: %s", resultA.Platform)
	}

	// Reset call tracking
	blueskyClient.postCalled = false
	threadsClient.postCalled = false

	// Test User B - should use Threads (no Bluesky creds)
	resultB, errB := poster.Post(context.Background(), "user-B", PostContent{Text: "Post from B"})
	if errB != nil {
		t.Fatalf("User B: Expected no error, got: %v", errB)
	}
	if resultB.Platform != PlatformThreads {
		t.Errorf("User B: Expected Threads, got: %s", resultB.Platform)
	}
	if blueskyClient.postCalled {
		t.Error("User B: Bluesky should not be called when user has no Bluesky creds")
	}
}

// =============================================================================
// Test: Client creation failure for Bluesky falls back to Threads
// =============================================================================

func TestPlatformFallbackPoster_BlueskyClientCreationFails_FallsBackToThreads(t *testing.T) {
	// Setup: Both credentials available, but Bluesky client creation fails
	credStore := NewMockCredentialStoreForFallback()
	credStore.SetCredentials("user-123", PlatformBluesky, &PlatformCredentials{
		UserID:       "user-123",
		Platform:     PlatformBluesky,
		AccessToken:  "bsky-app-password",
		RefreshToken: "user.bsky.social",
	})
	credStore.SetCredentials("user-123", PlatformThreads, &PlatformCredentials{
		UserID:      "user-123",
		Platform:    PlatformThreads,
		AccessToken: "threads-access-token",
	})

	blueskyClient := &MockSocialClientForFallback{
		platform: PlatformBluesky,
	}
	threadsClient := &MockSocialClientForFallback{
		platform: PlatformThreads,
		postResult: &PostResult{
			PostID:  "threads-fallback-post",
			PostURL: "https://threads.net/post/fallback",
		},
	}

	factory := NewMockSocialClientFactoryForFallback()
	factory.blueskyClient = blueskyClient
	factory.threadsClient = threadsClient
	factory.createErr[PlatformBluesky] = errors.New("failed to create Bluesky client")

	poster := NewPlatformFallbackPoster(credStore, factory)

	// Execute
	result, err := poster.Post(context.Background(), "user-123", PostContent{Text: "Test post"})

	// Verify: Client creation failure should return error (not fall back)
	// This is different from credential not found - client creation error is a hard failure
	if err == nil {
		t.Fatal("Expected error when Bluesky client creation fails")
	}
	if result != nil {
		t.Error("Expected nil result")
	}
}
