package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// Mock Stores for Draft Creation Tests (alice-86 TDD RED phase)
// =============================================================================

// Draft represents a draft social media post created from a webhook push
type Draft struct {
	ID               string
	UserID           string
	RepositoryID     string
	Ref              string     // e.g., "refs/heads/main"
	BeforeSHA        string     // SHA before push
	AfterSHA         string     // SHA after push
	CommitSHAs       []string   // List of commit SHAs in the push
	GeneratedContent string     // AI-generated content
	EditedContent    string     // User-edited content (initially same as generated)
	Status           string     // draft, posted, failed, error
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// DraftStatus constants
const (
	DraftStatusDraft  = "draft"
	DraftStatusPosted = "posted"
	DraftStatusFailed = "failed"
	DraftStatusError  = "error"
)

// Activity represents an activity log entry
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

// ActivityType constants
const (
	ActivityTypeDraftCreated = "draft_created"
	ActivityTypePostSuccess  = "post_success"
	ActivityTypePostFailed   = "post_failed"
)

// DraftWebhookStore defines the interface for draft persistence from webhooks
type DraftWebhookStore interface {
	CreateDraftFromPush(ctx context.Context, userID, repoID, ref, beforeSHA, afterSHA string, commitSHAs []string) (*Draft, error)
	GetDraftByPushSignature(ctx context.Context, repoID, beforeSHA, afterSHA string) (*Draft, error)
}

// ActivityStore defines the interface for activity logging
type ActivityStore interface {
	CreateActivity(ctx context.Context, userID, activityType string, draftID *string, message string) (*Activity, error)
}

// AIGeneratorService defines the interface for async AI content generation
type AIGeneratorService interface {
	TriggerGeneration(ctx context.Context, draftID string) error
}

// IdempotencyStore defines the interface for delivery idempotency checks
type IdempotencyStore interface {
	CheckDeliveryProcessed(ctx context.Context, deliveryID string) (bool, error)
	MarkDeliveryProcessed(ctx context.Context, deliveryID, repoID string) error
}

// =============================================================================
// Mock Implementations
// =============================================================================

// MockDraftWebhookStore is an in-memory draft store for testing
type MockDraftWebhookStore struct {
	mu     sync.Mutex
	drafts map[string]*Draft
	nextID int
}

func NewMockDraftWebhookStore() *MockDraftWebhookStore {
	return &MockDraftWebhookStore{
		drafts: make(map[string]*Draft),
		nextID: 1,
	}
}

func (m *MockDraftWebhookStore) CreateDraftFromPush(ctx context.Context, userID, repoID, ref, beforeSHA, afterSHA string, commitSHAs []string) (*Draft, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	draft := &Draft{
		ID:           generateTestID("draft", m.nextID),
		UserID:       userID,
		RepositoryID: repoID,
		Ref:          ref,
		BeforeSHA:    beforeSHA,
		AfterSHA:     afterSHA,
		CommitSHAs:   commitSHAs,
		Status:       DraftStatusDraft,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	m.nextID++
	m.drafts[draft.ID] = draft
	return draft, nil
}

func (m *MockDraftWebhookStore) GetDraftByPushSignature(ctx context.Context, repoID, beforeSHA, afterSHA string) (*Draft, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, d := range m.drafts {
		if d.RepositoryID == repoID && d.BeforeSHA == beforeSHA && d.AfterSHA == afterSHA {
			return d, nil
		}
	}
	return nil, nil
}

func (m *MockDraftWebhookStore) GetDrafts() []*Draft {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]*Draft, 0, len(m.drafts))
	for _, d := range m.drafts {
		result = append(result, d)
	}
	return result
}

// MockActivityStore is an in-memory activity store for testing
type MockActivityStore struct {
	mu         sync.Mutex
	activities []*Activity
	nextID     int
}

func NewMockActivityStore() *MockActivityStore {
	return &MockActivityStore{
		activities: make([]*Activity, 0),
		nextID:     1,
	}
}

func (m *MockActivityStore) CreateActivity(ctx context.Context, userID, activityType string, draftID *string, message string) (*Activity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	activity := &Activity{
		ID:        generateTestID("activity", m.nextID),
		UserID:    userID,
		Type:      activityType,
		DraftID:   draftID,
		Message:   message,
		CreatedAt: time.Now(),
	}
	m.nextID++
	m.activities = append(m.activities, activity)
	return activity, nil
}

func (m *MockActivityStore) GetActivities() []*Activity {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]*Activity, len(m.activities))
	copy(result, m.activities)
	return result
}

// MockAIGeneratorService tracks AI generation triggers
type MockAIGeneratorService struct {
	mu               sync.Mutex
	triggeredDraftIDs []string
}

func NewMockAIGeneratorService() *MockAIGeneratorService {
	return &MockAIGeneratorService{
		triggeredDraftIDs: make([]string, 0),
	}
}

func (m *MockAIGeneratorService) TriggerGeneration(ctx context.Context, draftID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.triggeredDraftIDs = append(m.triggeredDraftIDs, draftID)
	return nil
}

func (m *MockAIGeneratorService) GetTriggeredDraftIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]string, len(m.triggeredDraftIDs))
	copy(result, m.triggeredDraftIDs)
	return result
}

// MockIdempotencyStore tracks processed delivery IDs
type MockIdempotencyStore struct {
	mu          sync.Mutex
	processedIDs map[string]bool
}

func NewMockIdempotencyStore() *MockIdempotencyStore {
	return &MockIdempotencyStore{
		processedIDs: make(map[string]bool),
	}
}

func (m *MockIdempotencyStore) CheckDeliveryProcessed(ctx context.Context, deliveryID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.processedIDs[deliveryID], nil
}

func (m *MockIdempotencyStore) MarkDeliveryProcessed(ctx context.Context, deliveryID, repoID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.processedIDs[deliveryID] = true
	return nil
}

func (m *MockIdempotencyStore) IsProcessed(deliveryID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.processedIDs[deliveryID]
}

// =============================================================================
// Test Helpers
// =============================================================================

func generateTestID(prefix string, n int) string {
	return prefix + "-" + string(rune('0'+n))
}

// createPushPayloadWithSHAs creates a GitHub push event payload with before/after SHAs
func createPushPayloadWithSHAs(beforeSHA, afterSHA string, commits []map[string]interface{}) []byte {
	payload := map[string]interface{}{
		"ref":    "refs/heads/main",
		"before": beforeSHA,
		"after":  afterSHA,
		"repository": map[string]interface{}{
			"html_url":  "https://github.com/test/repo",
			"full_name": "test/repo",
		},
		"commits": commits,
	}
	data, _ := json.Marshal(payload)
	return data
}

// createDraftWebhookRequest creates a webhook request with X-GitHub-Delivery header
func createDraftWebhookRequest(t *testing.T, repoID string, payload []byte, signature, deliveryID string) *http.Request {
	t.Helper()

	url := "/webhooks/github/" + repoID
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	if signature != "" {
		req.Header.Set("X-Hub-Signature-256", signature)
	}
	if deliveryID != "" {
		req.Header.Set("X-GitHub-Delivery", deliveryID)
	}

	return req
}

// =============================================================================
// TDD RED Phase Tests: Webhook Draft Creation (alice-86)
// =============================================================================

// TestWebhookDraft_CreatesDraftFromPush tests that a push webhook creates a draft
// instead of directly creating a post.
//
// EXPECTED BEHAVIOR (alice-64):
// - Receive push webhook with commits
// - Create a draft record with ref, before_sha, after_sha, commit_shas
// - Draft status should be "draft"
// - Return success response with draft info
func TestWebhookDraft_CreatesDraftFromPush(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	draftStore := NewMockDraftWebhookStore()
	idempotencyStore := NewMockIdempotencyStore()
	_ = idempotencyStore // Will be used when handler is implemented

	t.Skip("TDD RED: Webhook handler does not yet create drafts (alice-64 not implemented)")

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "test-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	// TODO: Create DraftCreatingWebhookHandler when alice-64 is implemented
	// handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempotencyStore)

	commits := []map[string]interface{}{
		{
			"id":        "abc123def456",
			"message":   "feat: add new feature",
			"url":       "https://github.com/test/repo/commit/abc123def456",
			"timestamp": "2024-01-15T10:30:00Z",
			"author":    map[string]interface{}{"name": "Test Author", "email": "test@example.com"},
		},
	}
	beforeSHA := "0000000000000000000000000000000000000000"
	afterSHA := "abc123def456789012345678901234567890abcd"
	payload := createPushPayloadWithSHAs(beforeSHA, afterSHA, commits)
	signature := generateGitHubSignature(payload, repo.WebhookSecret)
	deliveryID := "delivery-uuid-12345"

	req := createDraftWebhookRequest(t, repo.ID, payload, signature, deliveryID)
	req.Header.Set("X-GitHub-Event", "push")

	rr := httptest.NewRecorder()
	// handler.ServeHTTP(rr, req)

	// Verify response
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify draft was created
	drafts := draftStore.GetDrafts()
	if len(drafts) != 1 {
		t.Fatalf("Expected 1 draft created, got %d", len(drafts))
	}

	draft := drafts[0]
	if draft.RepositoryID != repo.ID {
		t.Errorf("Expected repository ID %s, got %s", repo.ID, draft.RepositoryID)
	}
	if draft.UserID != repo.UserID {
		t.Errorf("Expected user ID %s, got %s", repo.UserID, draft.UserID)
	}
	if draft.Ref != "refs/heads/main" {
		t.Errorf("Expected ref 'refs/heads/main', got %s", draft.Ref)
	}
	if draft.BeforeSHA != beforeSHA {
		t.Errorf("Expected before_sha %s, got %s", beforeSHA, draft.BeforeSHA)
	}
	if draft.AfterSHA != afterSHA {
		t.Errorf("Expected after_sha %s, got %s", afterSHA, draft.AfterSHA)
	}
	if len(draft.CommitSHAs) != 1 || draft.CommitSHAs[0] != "abc123def456" {
		t.Errorf("Expected commit_shas [abc123def456], got %v", draft.CommitSHAs)
	}
	if draft.Status != DraftStatusDraft {
		t.Errorf("Expected status 'draft', got %s", draft.Status)
	}
}

// TestWebhookDraft_CreatesActivityRecord tests that an activity record is created
// when a draft is created from a webhook push.
//
// EXPECTED BEHAVIOR (alice-71):
// - When draft is created, create activity record
// - Activity type should be "draft_created"
// - Activity should reference the draft ID
func TestWebhookDraft_CreatesActivityRecord(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	draftStore := NewMockDraftWebhookStore()
	activityStore := NewMockActivityStore()
	idempotencyStore := NewMockIdempotencyStore()
	_ = idempotencyStore // Will be used when handler is implemented

	t.Skip("TDD RED: Webhook handler does not yet create activity records (alice-64 not implemented)")

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "test-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	// TODO: Create handler with activity store when alice-64 is implemented
	// handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempotencyStore).
	//     WithActivityStore(activityStore)

	commits := []map[string]interface{}{
		{
			"id":      "abc123",
			"message": "fix: bug fix",
			"author":  map[string]interface{}{"name": "Dev"},
		},
	}
	payload := createPushPayloadWithSHAs("before123", "after456", commits)
	signature := generateGitHubSignature(payload, repo.WebhookSecret)

	req := createDraftWebhookRequest(t, repo.ID, payload, signature, "delivery-123")
	req.Header.Set("X-GitHub-Event", "push")

	rr := httptest.NewRecorder()
	// handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d", rr.Code)
	}

	// Verify activity was created
	activities := activityStore.GetActivities()
	if len(activities) != 1 {
		t.Fatalf("Expected 1 activity created, got %d", len(activities))
	}

	activity := activities[0]
	if activity.Type != ActivityTypeDraftCreated {
		t.Errorf("Expected activity type '%s', got '%s'", ActivityTypeDraftCreated, activity.Type)
	}
	if activity.UserID != repo.UserID {
		t.Errorf("Expected user ID %s, got %s", repo.UserID, activity.UserID)
	}
	if activity.DraftID == nil {
		t.Error("Expected activity to reference draft ID")
	}

	// Verify activity references the created draft
	drafts := draftStore.GetDrafts()
	if len(drafts) > 0 && activity.DraftID != nil && *activity.DraftID != drafts[0].ID {
		t.Errorf("Expected activity draft_id %s, got %s", drafts[0].ID, *activity.DraftID)
	}
}

// TestWebhookDraft_IdempotencyRejectsDuplicate tests that duplicate webhook deliveries
// are rejected based on X-GitHub-Delivery header (delivery_id).
//
// EXPECTED BEHAVIOR (alice-77):
// - First delivery with delivery_id should be processed
// - Second delivery with same delivery_id should be rejected (200 OK but no new draft)
// - Response should indicate it was a duplicate
func TestWebhookDraft_IdempotencyRejectsDuplicate(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	draftStore := NewMockDraftWebhookStore()
	idempotencyStore := NewMockIdempotencyStore()
	_ = idempotencyStore // Will be used when handler is implemented

	t.Skip("TDD RED: Webhook handler does not yet check delivery_id idempotency (alice-77 not implemented)")

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "test-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	// TODO: Create handler with idempotency store
	// handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempotencyStore)

	commits := []map[string]interface{}{
		{
			"id":      "abc123",
			"message": "feat: feature",
			"author":  map[string]interface{}{"name": "Dev"},
		},
	}
	payload := createPushPayloadWithSHAs("before123", "after456", commits)
	signature := generateGitHubSignature(payload, repo.WebhookSecret)
	deliveryID := "delivery-uuid-same-123"

	// First request
	req1 := createDraftWebhookRequest(t, repo.ID, payload, signature, deliveryID)
	req1.Header.Set("X-GitHub-Event", "push")

	rr1 := httptest.NewRecorder()
	// handler.ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Errorf("First request: expected status 200 OK, got %d", rr1.Code)
	}

	// Verify one draft was created
	draftsAfterFirst := draftStore.GetDrafts()
	if len(draftsAfterFirst) != 1 {
		t.Fatalf("Expected 1 draft after first request, got %d", len(draftsAfterFirst))
	}

	// Second request with SAME delivery_id (duplicate)
	req2 := createDraftWebhookRequest(t, repo.ID, payload, signature, deliveryID)
	req2.Header.Set("X-GitHub-Event", "push")

	rr2 := httptest.NewRecorder()
	// handler.ServeHTTP(rr2, req2)

	// Should return 200 OK (idempotent - not an error, just a no-op)
	if rr2.Code != http.StatusOK {
		t.Errorf("Duplicate request: expected status 200 OK, got %d", rr2.Code)
	}

	// Verify NO new draft was created
	draftsAfterSecond := draftStore.GetDrafts()
	if len(draftsAfterSecond) != 1 {
		t.Errorf("Expected still 1 draft after duplicate request, got %d", len(draftsAfterSecond))
	}

	// Verify response indicates it was a duplicate
	var response map[string]interface{}
	if err := json.Unmarshal(rr2.Body.Bytes(), &response); err == nil {
		if msg, ok := response["message"].(string); !ok || msg != "duplicate delivery" {
			t.Logf("Response should indicate duplicate: %v", response)
		}
	}

	// Verify delivery_id was marked as processed
	if !idempotencyStore.IsProcessed(deliveryID) {
		t.Error("Expected delivery_id to be marked as processed")
	}
}

// TestWebhookDraft_IdempotencyAllowsDifferentDeliveryIDs tests that different
// delivery IDs are processed independently.
func TestWebhookDraft_IdempotencyAllowsDifferentDeliveryIDs(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	draftStore := NewMockDraftWebhookStore()
	idempotencyStore := NewMockIdempotencyStore()
	_ = idempotencyStore // Will be used when handler is implemented

	t.Skip("TDD RED: Webhook handler does not yet check delivery_id idempotency (alice-77 not implemented)")

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "test-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	// TODO: Create handler
	// handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempotencyStore)

	// First push
	commits1 := []map[string]interface{}{
		{"id": "commit1", "message": "first", "author": map[string]interface{}{"name": "Dev"}},
	}
	payload1 := createPushPayloadWithSHAs("before1", "after1", commits1)
	signature1 := generateGitHubSignature(payload1, repo.WebhookSecret)

	req1 := createDraftWebhookRequest(t, repo.ID, payload1, signature1, "delivery-1")
	req1.Header.Set("X-GitHub-Event", "push")

	rr1 := httptest.NewRecorder()
	// handler.ServeHTTP(rr1, req1)

	// Second push (different delivery_id)
	commits2 := []map[string]interface{}{
		{"id": "commit2", "message": "second", "author": map[string]interface{}{"name": "Dev"}},
	}
	payload2 := createPushPayloadWithSHAs("before2", "after2", commits2)
	signature2 := generateGitHubSignature(payload2, repo.WebhookSecret)

	req2 := createDraftWebhookRequest(t, repo.ID, payload2, signature2, "delivery-2")
	req2.Header.Set("X-GitHub-Event", "push")

	rr2 := httptest.NewRecorder()
	// handler.ServeHTTP(rr2, req2)

	// Both should succeed
	if rr1.Code != http.StatusOK {
		t.Errorf("First request: expected 200, got %d", rr1.Code)
	}
	if rr2.Code != http.StatusOK {
		t.Errorf("Second request: expected 200, got %d", rr2.Code)
	}

	// Two drafts should exist
	drafts := draftStore.GetDrafts()
	if len(drafts) != 2 {
		t.Errorf("Expected 2 drafts for different delivery IDs, got %d", len(drafts))
	}
}

// TestWebhookDraft_TriggersAsyncAIGeneration tests that AI content generation
// is triggered asynchronously after draft creation.
//
// EXPECTED BEHAVIOR:
// - Draft is created
// - AI generation is triggered for the draft
// - Request returns immediately (async generation)
func TestWebhookDraft_TriggersAsyncAIGeneration(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	draftStore := NewMockDraftWebhookStore()
	idempotencyStore := NewMockIdempotencyStore()
	aiGenerator := NewMockAIGeneratorService()
	_ = idempotencyStore // Will be used when handler is implemented

	t.Skip("TDD RED: Webhook handler does not yet trigger async AI generation (alice-64 not implemented)")

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "test-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	// TODO: Create handler with AI generator
	// handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempotencyStore).
	//     WithAIGenerator(aiGenerator)

	commits := []map[string]interface{}{
		{
			"id":      "abc123",
			"message": "feat: amazing new feature with lots of details",
			"author":  map[string]interface{}{"name": "Developer"},
		},
	}
	payload := createPushPayloadWithSHAs("before123", "after456", commits)
	signature := generateGitHubSignature(payload, repo.WebhookSecret)

	req := createDraftWebhookRequest(t, repo.ID, payload, signature, "delivery-123")
	req.Header.Set("X-GitHub-Event", "push")

	rr := httptest.NewRecorder()
	// handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d", rr.Code)
	}

	// Verify AI generation was triggered
	triggeredIDs := aiGenerator.GetTriggeredDraftIDs()
	if len(triggeredIDs) != 1 {
		t.Fatalf("Expected 1 AI generation trigger, got %d", len(triggeredIDs))
	}

	// Verify it was triggered for the created draft
	drafts := draftStore.GetDrafts()
	if len(drafts) > 0 && triggeredIDs[0] != drafts[0].ID {
		t.Errorf("Expected AI generation for draft %s, got %s", drafts[0].ID, triggeredIDs[0])
	}
}

// TestWebhookDraft_MultipleCommitsInSinglePush tests that a push with multiple
// commits creates a single draft (not one per commit).
func TestWebhookDraft_MultipleCommitsInSinglePush(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	draftStore := NewMockDraftWebhookStore()
	idempotencyStore := NewMockIdempotencyStore()
	_ = idempotencyStore // Will be used when handler is implemented

	t.Skip("TDD RED: Webhook handler does not yet create drafts (alice-64 not implemented)")

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "test-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	// TODO: Create handler
	// handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempotencyStore)

	// Push with 3 commits
	commits := []map[string]interface{}{
		{"id": "commit-1", "message": "feat: first", "author": map[string]interface{}{"name": "Dev"}},
		{"id": "commit-2", "message": "fix: second", "author": map[string]interface{}{"name": "Dev"}},
		{"id": "commit-3", "message": "docs: third", "author": map[string]interface{}{"name": "Dev"}},
	}
	payload := createPushPayloadWithSHAs("before-sha", "after-sha", commits)
	signature := generateGitHubSignature(payload, repo.WebhookSecret)

	req := createDraftWebhookRequest(t, repo.ID, payload, signature, "delivery-multi")
	req.Header.Set("X-GitHub-Event", "push")

	rr := httptest.NewRecorder()
	// handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d", rr.Code)
	}

	// Should create exactly ONE draft (not 3)
	drafts := draftStore.GetDrafts()
	if len(drafts) != 1 {
		t.Errorf("Expected 1 draft for multi-commit push, got %d", len(drafts))
	}

	// Draft should contain all commit SHAs
	if len(drafts) > 0 {
		draft := drafts[0]
		if len(draft.CommitSHAs) != 3 {
			t.Errorf("Expected 3 commit SHAs in draft, got %d", len(draft.CommitSHAs))
		}
	}
}

// TestWebhookDraft_PingEventDoesNotCreateDraft tests that ping events
// don't create drafts (only push events should).
func TestWebhookDraft_PingEventDoesNotCreateDraft(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	draftStore := NewMockDraftWebhookStore()
	idempotencyStore := NewMockIdempotencyStore()
	_ = idempotencyStore // Will be used when handler is implemented

	t.Skip("TDD RED: Webhook handler does not yet create drafts (alice-64 not implemented)")

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "test-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	// TODO: Create handler
	// handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempotencyStore)

	payload := createPingPayload()
	signature := generateGitHubSignature(payload, repo.WebhookSecret)

	req := createDraftWebhookRequest(t, repo.ID, payload, signature, "delivery-ping")
	req.Header.Set("X-GitHub-Event", "ping")

	rr := httptest.NewRecorder()
	// handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK for ping, got %d", rr.Code)
	}

	// No draft should be created for ping event
	drafts := draftStore.GetDrafts()
	if len(drafts) != 0 {
		t.Errorf("Expected 0 drafts for ping event, got %d", len(drafts))
	}
}

// TestWebhookDraft_MissingDeliveryIDRejects tests that webhooks without
// X-GitHub-Delivery header are rejected.
func TestWebhookDraft_MissingDeliveryIDRejects(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	draftStore := NewMockDraftWebhookStore()
	idempotencyStore := NewMockIdempotencyStore()
	_ = idempotencyStore // Will be used when handler is implemented

	t.Skip("TDD RED: Webhook handler does not yet require delivery_id (alice-77 not implemented)")

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "test-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	// TODO: Create handler
	// handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempotencyStore)

	commits := []map[string]interface{}{
		{"id": "abc123", "message": "test", "author": map[string]interface{}{"name": "Dev"}},
	}
	payload := createPushPayloadWithSHAs("before", "after", commits)
	signature := generateGitHubSignature(payload, repo.WebhookSecret)

	// No X-GitHub-Delivery header
	req := createDraftWebhookRequest(t, repo.ID, payload, signature, "")
	req.Header.Set("X-GitHub-Event", "push")

	rr := httptest.NewRecorder()
	// handler.ServeHTTP(rr, req)

	// Should reject request without delivery_id
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 Bad Request for missing delivery_id, got %d", rr.Code)
	}

	// No draft should be created
	drafts := draftStore.GetDrafts()
	if len(drafts) != 0 {
		t.Errorf("Expected 0 drafts when delivery_id missing, got %d", len(drafts))
	}
}

// TestWebhookDraft_DualIdempotencyCheck tests the dual idempotency mechanism:
// 1. delivery_id check (X-GitHub-Delivery header)
// 2. Push signature check (repo_id + before_sha + after_sha)
func TestWebhookDraft_DualIdempotencyCheck(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	draftStore := NewMockDraftWebhookStore()
	idempotencyStore := NewMockIdempotencyStore()
	_ = idempotencyStore // Will be used when handler is implemented

	t.Skip("TDD RED: Webhook handler does not yet implement dual idempotency (alice-77 not implemented)")

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "test-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	// TODO: Create handler
	// handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempotencyStore)

	commits := []map[string]interface{}{
		{"id": "abc123", "message": "test", "author": map[string]interface{}{"name": "Dev"}},
	}
	beforeSHA := "before123"
	afterSHA := "after456"
	payload := createPushPayloadWithSHAs(beforeSHA, afterSHA, commits)
	signature := generateGitHubSignature(payload, repo.WebhookSecret)

	// First request
	req1 := createDraftWebhookRequest(t, repo.ID, payload, signature, "delivery-1")
	req1.Header.Set("X-GitHub-Event", "push")

	rr1 := httptest.NewRecorder()
	// handler.ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Errorf("First request: expected 200, got %d", rr1.Code)
	}

	// Second request: different delivery_id, but SAME before/after SHA
	// This simulates GitHub retrying a webhook with a new delivery ID
	req2 := createDraftWebhookRequest(t, repo.ID, payload, signature, "delivery-2-retry")
	req2.Header.Set("X-GitHub-Event", "push")

	rr2 := httptest.NewRecorder()
	// handler.ServeHTTP(rr2, req2)

	// Should return 200 OK (idempotent)
	if rr2.Code != http.StatusOK {
		t.Errorf("Retry request: expected 200, got %d", rr2.Code)
	}

	// Should still only have 1 draft (caught by push signature check)
	drafts := draftStore.GetDrafts()
	if len(drafts) != 1 {
		t.Errorf("Expected 1 draft with dual idempotency, got %d", len(drafts))
	}
}
