//go:build browser

package web

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// =============================================================================
// Activity Feed Page Tests (TDD Red Phase)
//
// These tests verify the activity feed on /dashboard which displays user
// activities like draft creation, successful posts, and failed posts.
//
// Expected behavior:
// - Dashboard shows activity feed section
// - Activities display with type (draft_created/post_success/post_failed)
// - Activities ordered newest first
// - Pagination for many activities
// - Empty state when no activities
//
// Run with: go test -tags=browser -v ./internal/web -run TestBrowser_ActivityFeed
// =============================================================================

// Activity represents a user activity for the feed
type Activity struct {
	ID        string
	UserID    string
	Type      string // draft_created, post_success, post_failed
	DraftID   *string
	PostID    *string
	Platform  string
	Message   string
	CreatedAt time.Time
}

// MockActivityStore simulates activity storage
type MockActivityStore struct {
	activities map[string][]*Activity // userID -> activities
}

func NewMockActivityStore() *MockActivityStore {
	return &MockActivityStore{
		activities: make(map[string][]*Activity),
	}
}

func (m *MockActivityStore) ListActivitiesByUser(ctx context.Context, userID string, limit, offset int) ([]*Activity, error) {
	userActivities := m.activities[userID]
	if userActivities == nil {
		return []*Activity{}, nil
	}

	// Apply offset and limit
	start := offset
	if start > len(userActivities) {
		return []*Activity{}, nil
	}
	end := start + limit
	if end > len(userActivities) {
		end = len(userActivities)
	}

	return userActivities[start:end], nil
}

func (m *MockActivityStore) CountActivitiesByUser(ctx context.Context, userID string) (int, error) {
	return len(m.activities[userID]), nil
}

func (m *MockActivityStore) AddActivity(userID string, activity *Activity) {
	activity.ID = uuid.New().String()
	activity.UserID = userID
	// Prepend to keep newest first
	m.activities[userID] = append([]*Activity{activity}, m.activities[userID]...)
}

// TestBrowser_ActivityFeed_RendersActivityList tests that dashboard shows activity list
func TestBrowser_ActivityFeed_RendersActivityList(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	activityStore := NewMockActivityStore()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}

	router := NewRouterWithActivityStore(userStore, repoStore, nil, nil, secretGen, "https://api.test", activityStore)

	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	// Create and login user
	testEmail := "activity-feed-test@example.com"
	testPassword := "securepassword123"

	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Get user and add activities
	user, _ := userStore.GetUserByEmail(context.Background(), testEmail)

	draftID := "draft-123"
	activityStore.AddActivity(user.ID, &Activity{
		Type:      "draft_created",
		DraftID:   &draftID,
		Platform:  "threads",
		Message:   "Draft created from commit abc123",
		CreatedAt: time.Now().Add(-1 * time.Hour),
	})

	postID := "post-456"
	activityStore.AddActivity(user.ID, &Activity{
		Type:      "post_success",
		PostID:    &postID,
		Platform:  "threads",
		Message:   "Successfully posted to Threads",
		CreatedAt: time.Now().Add(-30 * time.Minute),
	})

	// Login
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Should be on dashboard
	currentURL := page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/dashboard") {
		t.Fatalf("Expected to be on dashboard, got: %s", currentURL)
	}

	// =========================================================================
	// Test: Activity feed section is present
	// =========================================================================
	t.Log("Testing: Activity feed section is present on dashboard")

	activityFeed := page.MustElement(".activity-feed")
	if activityFeed == nil {
		t.Fatal("FAILED: Expected .activity-feed section on dashboard")
	}

	// =========================================================================
	// Test: Activities are displayed
	// =========================================================================
	t.Log("Testing: Activities are displayed in the feed")

	bodyText := page.MustElement("body").MustText()

	if !strings.Contains(bodyText, "Draft created") {
		t.Error("FAILED: Expected 'Draft created' activity in feed")
	}
	if !strings.Contains(bodyText, "Successfully posted") {
		t.Error("FAILED: Expected 'Successfully posted' activity in feed")
	}

	t.Log("PASSED: Activity feed renders activity list")
}

// TestBrowser_ActivityFeed_ShowsActivityTypes tests that different activity types are displayed correctly
func TestBrowser_ActivityFeed_ShowsActivityTypes(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	activityStore := NewMockActivityStore()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}

	router := NewRouterWithActivityStore(userStore, repoStore, nil, nil, secretGen, "https://api.test", activityStore)

	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	// Create and login user
	testEmail := "activity-types-test@example.com"
	testPassword := "securepassword123"

	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	user, _ := userStore.GetUserByEmail(context.Background(), testEmail)

	// Add all three activity types
	draftID := "draft-1"
	activityStore.AddActivity(user.ID, &Activity{
		Type:      "draft_created",
		DraftID:   &draftID,
		Platform:  "threads",
		Message:   "New draft created",
		CreatedAt: time.Now().Add(-3 * time.Hour),
	})

	postID := "post-1"
	activityStore.AddActivity(user.ID, &Activity{
		Type:      "post_success",
		PostID:    &postID,
		Platform:  "threads",
		Message:   "Post published successfully",
		CreatedAt: time.Now().Add(-2 * time.Hour),
	})

	activityStore.AddActivity(user.ID, &Activity{
		Type:      "post_failed",
		DraftID:   &draftID,
		Platform:  "linkedin",
		Message:   "Failed to post: API rate limit exceeded",
		CreatedAt: time.Now().Add(-1 * time.Hour),
	})

	// Login
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// =========================================================================
	// Test: draft_created type has correct styling
	// =========================================================================
	t.Log("Testing: Activity types have correct styling/icons")

	// Check for activity type indicators
	draftActivities := page.MustElements(".activity-draft-created")
	if len(draftActivities) == 0 {
		t.Error("FAILED: Expected .activity-draft-created element for draft_created type")
	}

	successActivities := page.MustElements(".activity-post-success")
	if len(successActivities) == 0 {
		t.Error("FAILED: Expected .activity-post-success element for post_success type")
	}

	failedActivities := page.MustElements(".activity-post-failed")
	if len(failedActivities) == 0 {
		t.Error("FAILED: Expected .activity-post-failed element for post_failed type")
	}

	// =========================================================================
	// Test: Failed activities show error message
	// =========================================================================
	t.Log("Testing: Failed activities show error message")

	bodyText := page.MustElement("body").MustText()
	if !strings.Contains(bodyText, "rate limit") {
		t.Error("FAILED: Expected error message for failed post activity")
	}

	t.Log("PASSED: Activity types are displayed correctly")
}

// TestBrowser_ActivityFeed_NewestFirst tests that activities are ordered newest first
func TestBrowser_ActivityFeed_NewestFirst(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	activityStore := NewMockActivityStore()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}

	router := NewRouterWithActivityStore(userStore, repoStore, nil, nil, secretGen, "https://api.test", activityStore)

	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	testEmail := "newest-first-test@example.com"
	testPassword := "securepassword123"

	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	user, _ := userStore.GetUserByEmail(context.Background(), testEmail)

	// Add activities in chronological order (oldest to newest)
	draftID1 := "draft-old"
	activityStore.AddActivity(user.ID, &Activity{
		Type:      "draft_created",
		DraftID:   &draftID1,
		Message:   "OLDEST activity",
		CreatedAt: time.Now().Add(-3 * time.Hour),
	})

	draftID2 := "draft-mid"
	activityStore.AddActivity(user.ID, &Activity{
		Type:      "draft_created",
		DraftID:   &draftID2,
		Message:   "MIDDLE activity",
		CreatedAt: time.Now().Add(-2 * time.Hour),
	})

	draftID3 := "draft-new"
	activityStore.AddActivity(user.ID, &Activity{
		Type:      "draft_created",
		DraftID:   &draftID3,
		Message:   "NEWEST activity",
		CreatedAt: time.Now().Add(-1 * time.Hour),
	})

	// Login
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// =========================================================================
	// Test: Activities are ordered newest first
	// =========================================================================
	t.Log("Testing: Activities are ordered newest first")

	// Get all activity items
	activityItems := page.MustElements(".activity-item")
	if len(activityItems) < 3 {
		t.Fatalf("FAILED: Expected at least 3 activity items, got %d", len(activityItems))
	}

	// First item should be NEWEST
	firstItemText := activityItems[0].MustText()
	if !strings.Contains(firstItemText, "NEWEST") {
		t.Errorf("FAILED: First activity should be NEWEST, got: %s", firstItemText)
	}

	// Last item should be OLDEST
	lastItemText := activityItems[len(activityItems)-1].MustText()
	if !strings.Contains(lastItemText, "OLDEST") {
		t.Errorf("FAILED: Last activity should be OLDEST, got: %s", lastItemText)
	}

	t.Log("PASSED: Activities are ordered newest first")
}

// TestBrowser_ActivityFeed_Pagination tests pagination of activity feed
func TestBrowser_ActivityFeed_Pagination(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	activityStore := NewMockActivityStore()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}

	router := NewRouterWithActivityStore(userStore, repoStore, nil, nil, secretGen, "https://api.test", activityStore)

	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	testEmail := "pagination-test@example.com"
	testPassword := "securepassword123"

	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	user, _ := userStore.GetUserByEmail(context.Background(), testEmail)

	// Add many activities (more than page size, assume page size is 10)
	for i := 0; i < 25; i++ {
		draftID := "draft-" + string(rune('A'+i))
		activityStore.AddActivity(user.ID, &Activity{
			Type:      "draft_created",
			DraftID:   &draftID,
			Message:   "Activity " + string(rune('A'+i)),
			CreatedAt: time.Now().Add(-time.Duration(i) * time.Hour),
		})
	}

	// Login
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// =========================================================================
	// Test: Pagination controls are present
	// =========================================================================
	t.Log("Testing: Pagination controls are present")

	pagination := page.MustElement(".pagination")
	if pagination == nil {
		t.Fatal("FAILED: Expected .pagination element for paginated activities")
	}

	// =========================================================================
	// Test: Next page link works
	// =========================================================================
	t.Log("Testing: Next page link works")

	nextLink := page.MustElement(".pagination a.next")
	if nextLink == nil {
		t.Fatal("FAILED: Expected 'next' pagination link")
	}

	// Click next page
	nextLink.MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// URL should have page parameter
	currentURL := page.MustInfo().URL
	if !strings.Contains(currentURL, "page=2") {
		t.Errorf("FAILED: Expected page=2 in URL, got: %s", currentURL)
	}

	// =========================================================================
	// Test: Previous page link works
	// =========================================================================
	t.Log("Testing: Previous page link works")

	prevLink := page.MustElement(".pagination a.prev")
	if prevLink == nil {
		t.Fatal("FAILED: Expected 'prev' pagination link on page 2")
	}

	prevLink.MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Should be back on page 1
	currentURL = page.MustInfo().URL
	if strings.Contains(currentURL, "page=2") {
		t.Error("FAILED: Should be back on page 1")
	}

	t.Log("PASSED: Pagination works correctly")
}

// TestBrowser_ActivityFeed_EmptyState tests empty state when user has no activities
func TestBrowser_ActivityFeed_EmptyState(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	activityStore := NewMockActivityStore() // Empty store
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}

	router := NewRouterWithActivityStore(userStore, repoStore, nil, nil, secretGen, "https://api.test", activityStore)

	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	testEmail := "empty-activity-test@example.com"
	testPassword := "securepassword123"

	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Login (no activities added)
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// =========================================================================
	// Test: Empty state message is shown
	// =========================================================================
	t.Log("Testing: Empty state message is shown when no activities")

	bodyText := page.MustElement("body").MustText()

	// Should show empty state message
	hasEmptyState := strings.Contains(bodyText, "No activity yet") ||
		strings.Contains(bodyText, "no activities") ||
		strings.Contains(bodyText, "Get started")

	if !hasEmptyState {
		t.Error("FAILED: Expected empty state message when user has no activities")
	}

	// Should NOT show pagination on empty state
	pagination, err := page.Element(".pagination")
	if err == nil && pagination != nil {
		paginationVisible, _ := pagination.Visible()
		if paginationVisible {
			t.Error("FAILED: Pagination should not be visible when no activities")
		}
	}

	t.Log("PASSED: Empty state message shown for users with no activities")
}

// TestBrowser_ActivityFeed_ShowsPlatform tests that platform is displayed for activities
func TestBrowser_ActivityFeed_ShowsPlatform(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	activityStore := NewMockActivityStore()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}

	router := NewRouterWithActivityStore(userStore, repoStore, nil, nil, secretGen, "https://api.test", activityStore)

	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	testEmail := "platform-test@example.com"
	testPassword := "securepassword123"

	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	user, _ := userStore.GetUserByEmail(context.Background(), testEmail)

	// Add activities with different platforms
	postID1 := "post-threads"
	activityStore.AddActivity(user.ID, &Activity{
		Type:      "post_success",
		PostID:    &postID1,
		Platform:  "threads",
		Message:   "Posted to Threads",
		CreatedAt: time.Now().Add(-1 * time.Hour),
	})

	postID2 := "post-linkedin"
	activityStore.AddActivity(user.ID, &Activity{
		Type:      "post_success",
		PostID:    &postID2,
		Platform:  "linkedin",
		Message:   "Posted to LinkedIn",
		CreatedAt: time.Now().Add(-30 * time.Minute),
	})

	// Login
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// =========================================================================
	// Test: Platform is displayed in activity items
	// =========================================================================
	t.Log("Testing: Platform is displayed in activity items")

	bodyText := page.MustElement("body").MustText()

	// Should show platform names
	if !strings.Contains(strings.ToLower(bodyText), "threads") {
		t.Error("FAILED: Expected 'threads' platform in activity feed")
	}
	if !strings.Contains(strings.ToLower(bodyText), "linkedin") {
		t.Error("FAILED: Expected 'linkedin' platform in activity feed")
	}

	// Platform badges should exist
	platformBadges := page.MustElements(".activity-platform")
	if len(platformBadges) < 2 {
		t.Errorf("FAILED: Expected at least 2 platform badges, got %d", len(platformBadges))
	}

	t.Log("PASSED: Platform is displayed in activity items")
}
