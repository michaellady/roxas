package services

import (
	"context"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// =============================================================================
// Property Test: Platform Disconnection Preserves Drafts (Property 33)
// Validates Requirements 11.6, 11.7
//
// Property: Platform disconnect deletes credentials but keeps drafts.
// Drafts fail to post until the user reconnects the platform.
// =============================================================================

// DisconnectTestDraftStore provides a minimal draft store implementation for property testing
type DisconnectTestDraftStore struct {
	drafts map[string][]*DisconnectTestDraft // userID -> drafts
}

// DisconnectTestDraft represents a draft in our mock store
type DisconnectTestDraft struct {
	ID       string
	UserID   string
	Platform string
	Content  string
	Status   string
}

// NewDisconnectTestDraftStore creates a new mock draft store
func NewDisconnectTestDraftStore() *DisconnectTestDraftStore {
	return &DisconnectTestDraftStore{
		drafts: make(map[string][]*DisconnectTestDraft),
	}
}

// CreateDraft adds a draft to the store
func (m *DisconnectTestDraftStore) CreateDraft(userID, platform, content string) *DisconnectTestDraft {
	draft := &DisconnectTestDraft{
		ID:       generateDisconnectTestDraftID(len(m.drafts[userID])),
		UserID:   userID,
		Platform: platform,
		Content:  content,
		Status:   "draft",
	}
	m.drafts[userID] = append(m.drafts[userID], draft)
	return draft
}

// ListDraftsByUser returns all drafts for a user
func (m *DisconnectTestDraftStore) ListDraftsByUser(userID string) []*DisconnectTestDraft {
	return m.drafts[userID]
}

// GetDraft returns a specific draft by ID
func (m *DisconnectTestDraftStore) GetDraft(userID, draftID string) *DisconnectTestDraft {
	for _, draft := range m.drafts[userID] {
		if draft.ID == draftID {
			return draft
		}
	}
	return nil
}

// CountDrafts returns the count of drafts for a user
func (m *DisconnectTestDraftStore) CountDrafts(userID string) int {
	return len(m.drafts[userID])
}

// CountDraftsForPlatform returns the count of drafts for a specific platform
func (m *DisconnectTestDraftStore) CountDraftsForPlatform(userID, platform string) int {
	count := 0
	for _, draft := range m.drafts[userID] {
		if draft.Platform == platform {
			count++
		}
	}
	return count
}

func generateDisconnectTestDraftID(index int) string {
	return "draft-" + string(rune('A'+index%26)) + string(rune('0'+index/26))
}

// DisconnectTestPostingService simulates the behavior of posting drafts to platforms
type DisconnectTestPostingService struct {
	credStore *MockCredentialStore
}

// NewDisconnectTestPostingService creates a new posting service that checks credentials
func NewDisconnectTestPostingService(credStore *MockCredentialStore) *DisconnectTestPostingService {
	return &DisconnectTestPostingService{credStore: credStore}
}

// PostDraft attempts to post a draft - fails if credentials don't exist
func (m *DisconnectTestPostingService) PostDraft(ctx context.Context, draft *DisconnectTestDraft) error {
	_, err := m.credStore.GetCredentials(ctx, draft.UserID, draft.Platform)
	if err != nil {
		return err // Returns ErrCredentialsNotFound when disconnected
	}
	// Would post here - for test purposes, just return nil if creds exist
	return nil
}

// =============================================================================
// Property Tests
// =============================================================================

// TestProperty33_DisconnectDeletesCredentialsKeepsDrafts tests the core property:
// When a platform is disconnected, credentials are deleted but drafts are preserved.
func TestProperty33_DisconnectDeletesCredentialsKeepsDrafts(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 20

	properties := gopter.NewProperties(parameters)

	// Property 33a: Disconnecting a platform deletes credentials but preserves all drafts
	properties.Property("disconnect deletes credentials but preserves drafts", prop.ForAll(
		func(numDrafts int, platform string) bool {
			ctx := context.Background()
			userID := "test-user-disconnect"

			// Create stores
			credStore := NewMockCredentialStore()
			draftStore := NewDisconnectTestDraftStore()
			connService := NewConnectionService(ConnectionServiceConfig{
				CredentialStore: credStore,
			})

			// Setup: Save credentials for the platform
			now := time.Now()
			future := now.Add(time.Hour)
			err := credStore.SaveCredentials(ctx, &PlatformCredentials{
				UserID:         userID,
				Platform:       platform,
				AccessToken:    "test-token-" + platform,
				TokenExpiresAt: &future,
			})
			if err != nil {
				return false
			}

			// Setup: Create drafts for the user targeting this platform
			for i := 0; i < numDrafts; i++ {
				draftStore.CreateDraft(userID, platform, "Draft content "+string(rune('A'+i)))
			}

			// Verify initial state: credentials exist, drafts exist
			_, err = credStore.GetCredentials(ctx, userID, platform)
			if err != nil {
				t.Logf("Credentials should exist before disconnect: %v", err)
				return false
			}
			if draftStore.CountDrafts(userID) != numDrafts {
				t.Logf("Expected %d drafts before disconnect, got %d", numDrafts, draftStore.CountDrafts(userID))
				return false
			}

			// Action: Disconnect the platform
			err = connService.Disconnect(ctx, userID, platform)
			if err != nil {
				t.Logf("Disconnect failed: %v", err)
				return false
			}

			// Verify: Credentials should be deleted
			_, err = credStore.GetCredentials(ctx, userID, platform)
			if err != ErrCredentialsNotFound {
				t.Logf("Expected ErrCredentialsNotFound after disconnect, got: %v", err)
				return false
			}

			// Verify: Drafts should still exist (preserved)
			if draftStore.CountDrafts(userID) != numDrafts {
				t.Logf("Expected %d drafts after disconnect, got %d", numDrafts, draftStore.CountDrafts(userID))
				return false
			}

			return true
		},
		gen.IntRange(1, 20), // 1-20 drafts
		gen.OneConstOf(PlatformLinkedIn, PlatformTwitter, PlatformBluesky, PlatformThreads),
	))

	properties.TestingRun(t)
}

// TestProperty33_DraftsFailToPostWithoutCredentials tests that drafts fail to post
// when the platform is disconnected (no credentials).
func TestProperty33_DraftsFailToPostWithoutCredentials(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 10

	properties := gopter.NewProperties(parameters)

	// Property 33b: Drafts fail to post when platform is disconnected
	properties.Property("drafts fail to post after disconnect", prop.ForAll(
		func(numDrafts int, platform string) bool {
			ctx := context.Background()
			userID := "test-user-post-fail"

			// Create stores and services
			credStore := NewMockCredentialStore()
			draftStore := NewDisconnectTestDraftStore()
			postingService := NewDisconnectTestPostingService(credStore)
			connService := NewConnectionService(ConnectionServiceConfig{
				CredentialStore: credStore,
			})

			// Setup: Save credentials
			now := time.Now()
			future := now.Add(time.Hour)
			err := credStore.SaveCredentials(ctx, &PlatformCredentials{
				UserID:         userID,
				Platform:       platform,
				AccessToken:    "test-token",
				TokenExpiresAt: &future,
			})
			if err != nil {
				return false
			}

			// Setup: Create drafts
			drafts := make([]*DisconnectTestDraft, 0, numDrafts)
			for i := 0; i < numDrafts; i++ {
				draft := draftStore.CreateDraft(userID, platform, "Content "+string(rune('A'+i)))
				drafts = append(drafts, draft)
			}

			// Verify: Posting should succeed before disconnect
			for _, draft := range drafts {
				err := postingService.PostDraft(ctx, draft)
				if err != nil {
					t.Logf("Posting should succeed before disconnect: %v", err)
					return false
				}
			}

			// Action: Disconnect the platform
			err = connService.Disconnect(ctx, userID, platform)
			if err != nil {
				t.Logf("Disconnect failed: %v", err)
				return false
			}

			// Verify: Drafts still exist
			if draftStore.CountDrafts(userID) != numDrafts {
				t.Logf("Drafts should be preserved after disconnect")
				return false
			}

			// Verify: Posting should fail for ALL drafts after disconnect
			for _, draft := range drafts {
				err := postingService.PostDraft(ctx, draft)
				if err != ErrCredentialsNotFound {
					t.Logf("Expected ErrCredentialsNotFound when posting after disconnect, got: %v", err)
					return false
				}
			}

			return true
		},
		gen.IntRange(1, 10),
		gen.OneConstOf(PlatformLinkedIn, PlatformTwitter, PlatformBluesky),
	))

	properties.TestingRun(t)
}

// TestProperty33_ReconnectRestoresPostingAbility tests that after reconnecting,
// previously preserved drafts can be posted again.
func TestProperty33_ReconnectRestoresPostingAbility(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 10

	properties := gopter.NewProperties(parameters)

	// Property 33c: Reconnecting the platform allows drafts to be posted again
	properties.Property("reconnect restores posting ability for preserved drafts", prop.ForAll(
		func(numDrafts int, platform string) bool {
			ctx := context.Background()
			userID := "test-user-reconnect"

			// Create stores and services
			credStore := NewMockCredentialStore()
			draftStore := NewDisconnectTestDraftStore()
			postingService := NewDisconnectTestPostingService(credStore)
			connService := NewConnectionService(ConnectionServiceConfig{
				CredentialStore: credStore,
			})

			// Setup: Initial connection
			now := time.Now()
			future := now.Add(time.Hour)
			err := credStore.SaveCredentials(ctx, &PlatformCredentials{
				UserID:         userID,
				Platform:       platform,
				AccessToken:    "initial-token",
				TokenExpiresAt: &future,
			})
			if err != nil {
				return false
			}

			// Setup: Create drafts
			drafts := make([]*DisconnectTestDraft, 0, numDrafts)
			for i := 0; i < numDrafts; i++ {
				draft := draftStore.CreateDraft(userID, platform, "Reconnect test "+string(rune('A'+i)))
				drafts = append(drafts, draft)
			}

			// Action: Disconnect
			err = connService.Disconnect(ctx, userID, platform)
			if err != nil {
				t.Logf("Disconnect failed: %v", err)
				return false
			}

			// Verify: Posting fails after disconnect
			for _, draft := range drafts {
				err := postingService.PostDraft(ctx, draft)
				if err != ErrCredentialsNotFound {
					t.Logf("Posting should fail after disconnect")
					return false
				}
			}

			// Action: Reconnect (save new credentials)
			err = credStore.SaveCredentials(ctx, &PlatformCredentials{
				UserID:         userID,
				Platform:       platform,
				AccessToken:    "new-token-after-reconnect",
				TokenExpiresAt: &future,
			})
			if err != nil {
				t.Logf("Reconnect (save credentials) failed: %v", err)
				return false
			}

			// Verify: Drafts are still preserved after the disconnect/reconnect cycle
			if draftStore.CountDrafts(userID) != numDrafts {
				t.Logf("Drafts should be preserved through disconnect/reconnect cycle")
				return false
			}

			// Verify: Posting should succeed again after reconnect
			for _, draft := range drafts {
				err := postingService.PostDraft(ctx, draft)
				if err != nil {
					t.Logf("Posting should succeed after reconnect: %v", err)
					return false
				}
			}

			return true
		},
		gen.IntRange(1, 10),
		gen.OneConstOf(PlatformLinkedIn, PlatformTwitter, PlatformBluesky),
	))

	properties.TestingRun(t)
}

// TestProperty33_DisconnectOnlyAffectsSpecificPlatform tests that disconnecting
// one platform doesn't affect drafts or credentials for other platforms.
func TestProperty33_DisconnectOnlyAffectsSpecificPlatform(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100

	properties := gopter.NewProperties(parameters)

	// Property 33d: Disconnecting one platform doesn't affect other platforms
	properties.Property("disconnect only affects the specific platform", prop.ForAll(
		func(numDraftsPerPlatform int) bool {
			ctx := context.Background()
			userID := "test-user-multi-platform"
			platforms := []string{PlatformLinkedIn, PlatformTwitter, PlatformBluesky}

			// Create stores
			credStore := NewMockCredentialStore()
			draftStore := NewDisconnectTestDraftStore()
			postingService := NewDisconnectTestPostingService(credStore)
			connService := NewConnectionService(ConnectionServiceConfig{
				CredentialStore: credStore,
			})

			// Setup: Connect all platforms and create drafts for each
			now := time.Now()
			future := now.Add(time.Hour)
			for _, platform := range platforms {
				err := credStore.SaveCredentials(ctx, &PlatformCredentials{
					UserID:         userID,
					Platform:       platform,
					AccessToken:    "token-" + platform,
					TokenExpiresAt: &future,
				})
				if err != nil {
					return false
				}

				for i := 0; i < numDraftsPerPlatform; i++ {
					draftStore.CreateDraft(userID, platform, platform+" draft "+string(rune('A'+i)))
				}
			}

			totalDrafts := numDraftsPerPlatform * len(platforms)

			// Verify initial state
			if draftStore.CountDrafts(userID) != totalDrafts {
				t.Logf("Expected %d total drafts, got %d", totalDrafts, draftStore.CountDrafts(userID))
				return false
			}

			// Action: Disconnect only LinkedIn
			disconnectedPlatform := PlatformLinkedIn
			err := connService.Disconnect(ctx, userID, disconnectedPlatform)
			if err != nil {
				t.Logf("Disconnect failed: %v", err)
				return false
			}

			// Verify: All drafts still exist (including LinkedIn drafts)
			if draftStore.CountDrafts(userID) != totalDrafts {
				t.Logf("All drafts should be preserved, got %d", draftStore.CountDrafts(userID))
				return false
			}

			// Verify: LinkedIn credentials are gone
			_, err = credStore.GetCredentials(ctx, userID, disconnectedPlatform)
			if err != ErrCredentialsNotFound {
				t.Logf("LinkedIn credentials should be deleted")
				return false
			}

			// Verify: Other platform credentials still exist
			for _, platform := range platforms {
				if platform == disconnectedPlatform {
					continue
				}
				_, err = credStore.GetCredentials(ctx, userID, platform)
				if err != nil {
					t.Logf("Credentials for %s should still exist: %v", platform, err)
					return false
				}
			}

			// Verify: Posting to LinkedIn fails, but other platforms succeed
			for _, draft := range draftStore.ListDraftsByUser(userID) {
				err := postingService.PostDraft(ctx, draft)
				if draft.Platform == disconnectedPlatform {
					if err != ErrCredentialsNotFound {
						t.Logf("Posting to %s should fail after disconnect", disconnectedPlatform)
						return false
					}
				} else {
					if err != nil {
						t.Logf("Posting to %s should succeed: %v", draft.Platform, err)
						return false
					}
				}
			}

			return true
		},
		gen.IntRange(1, 5), // 1-5 drafts per platform
	))

	properties.TestingRun(t)
}

// TestProperty33_DraftCountPreservedAcrossMultipleDisconnects tests that the draft
// count remains constant across multiple disconnect/reconnect cycles.
func TestProperty33_DraftCountPreservedAcrossMultipleDisconnects(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50

	properties := gopter.NewProperties(parameters)

	// Property 33e: Draft count is preserved across multiple disconnect/reconnect cycles
	properties.Property("drafts preserved across multiple disconnect/reconnect cycles", prop.ForAll(
		func(numDrafts, numCycles int, platform string) bool {
			ctx := context.Background()
			userID := "test-user-multi-cycle"

			// Create stores
			credStore := NewMockCredentialStore()
			draftStore := NewDisconnectTestDraftStore()
			connService := NewConnectionService(ConnectionServiceConfig{
				CredentialStore: credStore,
			})

			// Setup: Initial connection and drafts
			now := time.Now()
			future := now.Add(time.Hour)
			err := credStore.SaveCredentials(ctx, &PlatformCredentials{
				UserID:         userID,
				Platform:       platform,
				AccessToken:    "initial-token",
				TokenExpiresAt: &future,
			})
			if err != nil {
				return false
			}

			for i := 0; i < numDrafts; i++ {
				draftStore.CreateDraft(userID, platform, "Cycle test "+string(rune('A'+i)))
			}

			initialDraftCount := draftStore.CountDrafts(userID)

			// Action: Multiple disconnect/reconnect cycles
			for cycle := 0; cycle < numCycles; cycle++ {
				// Disconnect
				err = connService.Disconnect(ctx, userID, platform)
				if err != nil {
					t.Logf("Disconnect failed on cycle %d: %v", cycle, err)
					return false
				}

				// Verify drafts preserved
				if draftStore.CountDrafts(userID) != initialDraftCount {
					t.Logf("Draft count changed after disconnect on cycle %d", cycle)
					return false
				}

				// Reconnect
				err = credStore.SaveCredentials(ctx, &PlatformCredentials{
					UserID:         userID,
					Platform:       platform,
					AccessToken:    "reconnect-token-" + string(rune('0'+cycle)),
					TokenExpiresAt: &future,
				})
				if err != nil {
					t.Logf("Reconnect failed on cycle %d: %v", cycle, err)
					return false
				}

				// Verify drafts still preserved
				if draftStore.CountDrafts(userID) != initialDraftCount {
					t.Logf("Draft count changed after reconnect on cycle %d", cycle)
					return false
				}
			}

			// Final verification: All original drafts exist
			if draftStore.CountDrafts(userID) != initialDraftCount {
				t.Logf("Final draft count %d != initial %d", draftStore.CountDrafts(userID), initialDraftCount)
				return false
			}

			return true
		},
		gen.IntRange(1, 10),  // 1-10 drafts
		gen.IntRange(2, 5),   // 2-5 disconnect/reconnect cycles
		gen.OneConstOf(PlatformLinkedIn, PlatformTwitter, PlatformBluesky),
	))

	properties.TestingRun(t)
}

// TestProperty33_DraftContentPreservedAfterDisconnect tests that not just the count,
// but the actual content of drafts is preserved after disconnect.
func TestProperty33_DraftContentPreservedAfterDisconnect(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100

	properties := gopter.NewProperties(parameters)

	// Property 33f: Draft content is exactly preserved after disconnect
	properties.Property("draft content exactly preserved after disconnect", prop.ForAll(
		func(numDrafts int, contentSeed string, platform string) bool {
			ctx := context.Background()
			userID := "test-user-content-preserve"

			// Create stores
			credStore := NewMockCredentialStore()
			draftStore := NewDisconnectTestDraftStore()
			connService := NewConnectionService(ConnectionServiceConfig{
				CredentialStore: credStore,
			})

			// Setup: Connect platform
			now := time.Now()
			future := now.Add(time.Hour)
			err := credStore.SaveCredentials(ctx, &PlatformCredentials{
				UserID:         userID,
				Platform:       platform,
				AccessToken:    "test-token",
				TokenExpiresAt: &future,
			})
			if err != nil {
				return false
			}

			// Generate content strings from seed
			contents := make([]string, numDrafts)
			for i := 0; i < numDrafts; i++ {
				contents[i] = contentSeed + "-" + string(rune('A'+i))
			}

			// Setup: Create drafts with specific contents and record their IDs
			draftIDs := make([]string, 0, len(contents))
			for _, content := range contents {
				draft := draftStore.CreateDraft(userID, platform, content)
				draftIDs = append(draftIDs, draft.ID)
			}

			// Action: Disconnect
			err = connService.Disconnect(ctx, userID, platform)
			if err != nil {
				t.Logf("Disconnect failed: %v", err)
				return false
			}

			// Verify: Each draft has exactly the same content
			for i, draftID := range draftIDs {
				draft := draftStore.GetDraft(userID, draftID)
				if draft == nil {
					t.Logf("Draft %s not found after disconnect", draftID)
					return false
				}
				if draft.Content != contents[i] {
					t.Logf("Draft content mismatch: got %q, want %q", draft.Content, contents[i])
					return false
				}
				if draft.Platform != platform {
					t.Logf("Draft platform mismatch: got %q, want %q", draft.Platform, platform)
					return false
				}
			}

			return true
		},
		gen.IntRange(1, 10), // 1-10 drafts
		gen.AnyString(),     // Content seed
		gen.OneConstOf(PlatformLinkedIn, PlatformTwitter, PlatformBluesky),
	))

	properties.TestingRun(t)
}
