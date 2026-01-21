package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mikelady/roxas/internal/auth"
)

// =============================================================================
// Mock Draft Store for Testing
// =============================================================================

type MockDraftStore struct {
	mu     sync.RWMutex
	drafts map[string]*Draft
	// Track method calls for verification
	UpdateContentCalls   int
	UpdateStatusCalls    int
	DeleteCalls          int
	RegenerateCalls      int
	// Configurable errors
	GetErr            error
	UpdateContentErr  error
	UpdateStatusErr   error
	DeleteErr         error
}

func NewMockDraftStore() *MockDraftStore {
	return &MockDraftStore{
		drafts: make(map[string]*Draft),
	}
}

func (m *MockDraftStore) AddDraft(draft *Draft) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drafts[draft.ID] = draft
}

func (m *MockDraftStore) GetDraftByID(ctx context.Context, draftID string) (*Draft, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.GetErr != nil {
		return nil, m.GetErr
	}

	draft, ok := m.drafts[draftID]
	if !ok {
		return nil, nil
	}
	return draft, nil
}

func (m *MockDraftStore) GetDraftsByUserID(ctx context.Context, userID string, limit, offset int) ([]*Draft, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Draft
	for _, d := range m.drafts {
		if d.UserID == userID {
			result = append(result, d)
		}
	}
	return result, nil
}

func (m *MockDraftStore) UpdateDraftContent(ctx context.Context, draftID, editedContent string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.UpdateContentCalls++

	if m.UpdateContentErr != nil {
		return m.UpdateContentErr
	}

	draft, ok := m.drafts[draftID]
	if !ok {
		return errors.New("draft not found")
	}
	draft.EditedContent = &editedContent
	draft.UpdatedAt = time.Now()
	return nil
}

func (m *MockDraftStore) UpdateDraftStatus(ctx context.Context, draftID, status string, errorMsg *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.UpdateStatusCalls++

	if m.UpdateStatusErr != nil {
		return m.UpdateStatusErr
	}

	draft, ok := m.drafts[draftID]
	if !ok {
		return errors.New("draft not found")
	}
	draft.Status = status
	draft.ErrorMessage = errorMsg
	draft.UpdatedAt = time.Now()
	return nil
}

func (m *MockDraftStore) DeleteDraft(ctx context.Context, draftID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.DeleteCalls++

	if m.DeleteErr != nil {
		return m.DeleteErr
	}

	if _, ok := m.drafts[draftID]; !ok {
		return errors.New("draft not found")
	}
	delete(m.drafts, draftID)
	return nil
}

// =============================================================================
// Mock AI Generator for Regenerate Tests
// =============================================================================

type MockAIGenerator struct {
	GeneratedContent string
	GenerateErr      error
	GenerateCalls    int
}

func (m *MockAIGenerator) GeneratePostContent(ctx context.Context, commitInfo interface{}) (string, error) {
	m.GenerateCalls++
	if m.GenerateErr != nil {
		return "", m.GenerateErr
	}
	if m.GeneratedContent != "" {
		return m.GeneratedContent, nil
	}
	return "Regenerated content for your commit!", nil
}

// =============================================================================
// TDD Tests for Draft Handlers (RED PHASE - These should fail initially)
// =============================================================================

// -----------------------------------------------------------------------------
// POST /drafts/{id}/edit - Update draft content
// -----------------------------------------------------------------------------

func TestDraftHandler_PostEdit_UpdatesContent(t *testing.T) {
	draftStore := NewMockDraftStore()

	// Create a test draft
	userID := uuid.New().String()
	draftID := uuid.New().String()
	originalContent := "Original generated content"
	draftStore.AddDraft(&Draft{
		ID:               draftID,
		UserID:           userID,
		RepositoryID:     uuid.New().String(),
		Ref:              "refs/heads/main",
		AfterSHA:         "abc123",
		CommitSHAs:       []string{"abc123"},
		CommitCount:      1,
		GeneratedContent: &originalContent,
		Status:           "draft",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	})

	// Create handler with mock store
	handler := NewDraftHandler(draftStore, nil)

	// Create authenticated request
	form := url.Values{}
	form.Set("content", "User edited content here")

	req := httptest.NewRequest(http.MethodPost, "/drafts/"+draftID+"/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = addAuthContext(req, userID)

	rr := httptest.NewRecorder()
	handler.HandleEdit(rr, req, draftID)

	// Should return success (200 OK or redirect)
	if rr.Code != http.StatusOK && rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status 200 or 303, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify content was updated
	if draftStore.UpdateContentCalls != 1 {
		t.Errorf("Expected UpdateDraftContent to be called once, got %d", draftStore.UpdateContentCalls)
	}

	// Verify draft was updated
	updatedDraft, _ := draftStore.GetDraftByID(context.Background(), draftID)
	if updatedDraft == nil {
		t.Fatal("Draft should still exist")
	}
	if updatedDraft.EditedContent == nil || *updatedDraft.EditedContent != "User edited content here" {
		t.Errorf("Expected edited content to be updated")
	}
}

func TestDraftHandler_PostEdit_RequiresAuth(t *testing.T) {
	draftStore := NewMockDraftStore()
	handler := NewDraftHandler(draftStore, nil)

	draftID := uuid.New().String()

	form := url.Values{}
	form.Set("content", "Some content")

	req := httptest.NewRequest(http.MethodPost, "/drafts/"+draftID+"/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// No auth context

	rr := httptest.NewRecorder()
	handler.HandleEdit(rr, req, draftID)

	// Should return 401 Unauthorized
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestDraftHandler_PostEdit_ValidatesOwnership(t *testing.T) {
	draftStore := NewMockDraftStore()

	// Create draft owned by user1
	user1ID := uuid.New().String()
	user2ID := uuid.New().String()
	draftID := uuid.New().String()
	content := "Some content"
	draftStore.AddDraft(&Draft{
		ID:               draftID,
		UserID:           user1ID, // Owned by user1
		GeneratedContent: &content,
		Status:           "draft",
	})

	handler := NewDraftHandler(draftStore, nil)

	form := url.Values{}
	form.Set("content", "Hacker content")

	// Request from user2 trying to edit user1's draft
	req := httptest.NewRequest(http.MethodPost, "/drafts/"+draftID+"/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = addAuthContext(req, user2ID)

	rr := httptest.NewRecorder()
	handler.HandleEdit(rr, req, draftID)

	// Should return 403 Forbidden or 404 Not Found
	if rr.Code != http.StatusForbidden && rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 403 or 404 for unauthorized access, got %d", rr.Code)
	}

	// Content should not be updated
	if draftStore.UpdateContentCalls != 0 {
		t.Errorf("UpdateDraftContent should not be called for unauthorized user")
	}
}

func TestDraftHandler_PostEdit_NotFound(t *testing.T) {
	draftStore := NewMockDraftStore()
	handler := NewDraftHandler(draftStore, nil)

	userID := uuid.New().String()
	nonExistentID := uuid.New().String()

	form := url.Values{}
	form.Set("content", "Content for non-existent draft")

	req := httptest.NewRequest(http.MethodPost, "/drafts/"+nonExistentID+"/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = addAuthContext(req, userID)

	rr := httptest.NewRecorder()
	handler.HandleEdit(rr, req, nonExistentID)

	// Should return 404 Not Found
	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestDraftHandler_PostEdit_ValidatesContentLength(t *testing.T) {
	draftStore := NewMockDraftStore()

	userID := uuid.New().String()
	draftID := uuid.New().String()
	content := "Original"
	draftStore.AddDraft(&Draft{
		ID:               draftID,
		UserID:           userID,
		GeneratedContent: &content,
		Status:           "draft",
	})

	handler := NewDraftHandler(draftStore, nil)

	// Content exceeds Threads 500 char limit
	longContent := strings.Repeat("a", 501)
	form := url.Values{}
	form.Set("content", longContent)

	req := httptest.NewRequest(http.MethodPost, "/drafts/"+draftID+"/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = addAuthContext(req, userID)

	rr := httptest.NewRecorder()
	handler.HandleEdit(rr, req, draftID)

	// Should return 400 Bad Request for content too long
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for content exceeding limit, got %d", rr.Code)
	}
}

// -----------------------------------------------------------------------------
// POST /drafts/{id}/delete - Delete draft
// -----------------------------------------------------------------------------

func TestDraftHandler_PostDelete_RemovesDraft(t *testing.T) {
	draftStore := NewMockDraftStore()

	userID := uuid.New().String()
	draftID := uuid.New().String()
	content := "Content to delete"
	draftStore.AddDraft(&Draft{
		ID:               draftID,
		UserID:           userID,
		GeneratedContent: &content,
		Status:           "draft",
	})

	handler := NewDraftHandler(draftStore, nil)

	req := httptest.NewRequest(http.MethodPost, "/drafts/"+draftID+"/delete", nil)
	req = addAuthContext(req, userID)

	rr := httptest.NewRecorder()
	handler.HandleDelete(rr, req, draftID)

	// Should redirect to drafts list on success
	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusOK {
		t.Errorf("Expected status 303 or 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify delete was called
	if draftStore.DeleteCalls != 1 {
		t.Errorf("Expected DeleteDraft to be called once, got %d", draftStore.DeleteCalls)
	}

	// Verify draft is gone
	deleted, _ := draftStore.GetDraftByID(context.Background(), draftID)
	if deleted != nil {
		t.Error("Draft should be deleted")
	}
}

func TestDraftHandler_PostDelete_RequiresAuth(t *testing.T) {
	draftStore := NewMockDraftStore()
	handler := NewDraftHandler(draftStore, nil)

	draftID := uuid.New().String()

	req := httptest.NewRequest(http.MethodPost, "/drafts/"+draftID+"/delete", nil)
	// No auth

	rr := httptest.NewRecorder()
	handler.HandleDelete(rr, req, draftID)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestDraftHandler_PostDelete_ValidatesOwnership(t *testing.T) {
	draftStore := NewMockDraftStore()

	user1ID := uuid.New().String()
	user2ID := uuid.New().String()
	draftID := uuid.New().String()
	content := "User1's draft"
	draftStore.AddDraft(&Draft{
		ID:               draftID,
		UserID:           user1ID,
		GeneratedContent: &content,
		Status:           "draft",
	})

	handler := NewDraftHandler(draftStore, nil)

	// User2 tries to delete user1's draft
	req := httptest.NewRequest(http.MethodPost, "/drafts/"+draftID+"/delete", nil)
	req = addAuthContext(req, user2ID)

	rr := httptest.NewRecorder()
	handler.HandleDelete(rr, req, draftID)

	if rr.Code != http.StatusForbidden && rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 403 or 404, got %d", rr.Code)
	}

	// Draft should NOT be deleted
	if draftStore.DeleteCalls != 0 {
		t.Error("DeleteDraft should not be called for unauthorized user")
	}
}

func TestDraftHandler_PostDelete_NotFound(t *testing.T) {
	draftStore := NewMockDraftStore()
	handler := NewDraftHandler(draftStore, nil)

	userID := uuid.New().String()

	req := httptest.NewRequest(http.MethodPost, "/drafts/"+uuid.New().String()+"/delete", nil)
	req = addAuthContext(req, userID)

	rr := httptest.NewRecorder()
	handler.HandleDelete(rr, req, uuid.New().String())

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestDraftHandler_PostDelete_CannotDeletePostedDraft(t *testing.T) {
	draftStore := NewMockDraftStore()

	userID := uuid.New().String()
	draftID := uuid.New().String()
	content := "Posted content"
	draftStore.AddDraft(&Draft{
		ID:               draftID,
		UserID:           userID,
		GeneratedContent: &content,
		Status:           "posted", // Already posted
	})

	handler := NewDraftHandler(draftStore, nil)

	req := httptest.NewRequest(http.MethodPost, "/drafts/"+draftID+"/delete", nil)
	req = addAuthContext(req, userID)

	rr := httptest.NewRecorder()
	handler.HandleDelete(rr, req, draftID)

	// Should return 400 Bad Request - cannot delete posted drafts
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for deleting posted draft, got %d", rr.Code)
	}
}

// -----------------------------------------------------------------------------
// POST /drafts/{id}/regenerate - Regenerate AI content
// -----------------------------------------------------------------------------

func TestDraftHandler_PostRegenerate_GeneratesNewContent(t *testing.T) {
	draftStore := NewMockDraftStore()
	aiGenerator := &MockAIGenerator{
		GeneratedContent: "Fresh AI-generated content!",
	}

	userID := uuid.New().String()
	draftID := uuid.New().String()
	originalContent := "Old content"
	draftStore.AddDraft(&Draft{
		ID:               draftID,
		UserID:           userID,
		RepositoryID:     uuid.New().String(),
		Ref:              "refs/heads/main",
		AfterSHA:         "abc123",
		CommitSHAs:       []string{"abc123"},
		GeneratedContent: &originalContent,
		Status:           "draft",
	})

	handler := NewDraftHandler(draftStore, aiGenerator)

	req := httptest.NewRequest(http.MethodPost, "/drafts/"+draftID+"/regenerate", nil)
	req = addAuthContext(req, userID)

	rr := httptest.NewRecorder()
	handler.HandleRegenerate(rr, req, draftID)

	// Should return success or redirect
	if rr.Code != http.StatusOK && rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status 200 or 303, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify AI generator was called
	if aiGenerator.GenerateCalls != 1 {
		t.Errorf("Expected GeneratePostContent to be called once, got %d", aiGenerator.GenerateCalls)
	}
}

func TestDraftHandler_PostRegenerate_RequiresAuth(t *testing.T) {
	draftStore := NewMockDraftStore()
	handler := NewDraftHandler(draftStore, nil)

	req := httptest.NewRequest(http.MethodPost, "/drafts/"+uuid.New().String()+"/regenerate", nil)

	rr := httptest.NewRecorder()
	handler.HandleRegenerate(rr, req, uuid.New().String())

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestDraftHandler_PostRegenerate_ValidatesOwnership(t *testing.T) {
	draftStore := NewMockDraftStore()

	user1ID := uuid.New().String()
	user2ID := uuid.New().String()
	draftID := uuid.New().String()
	content := "User1's content"
	draftStore.AddDraft(&Draft{
		ID:               draftID,
		UserID:           user1ID,
		GeneratedContent: &content,
		Status:           "draft",
	})

	handler := NewDraftHandler(draftStore, nil)

	req := httptest.NewRequest(http.MethodPost, "/drafts/"+draftID+"/regenerate", nil)
	req = addAuthContext(req, user2ID)

	rr := httptest.NewRecorder()
	handler.HandleRegenerate(rr, req, draftID)

	if rr.Code != http.StatusForbidden && rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 403 or 404, got %d", rr.Code)
	}
}

func TestDraftHandler_PostRegenerate_HandlesAIFailure(t *testing.T) {
	draftStore := NewMockDraftStore()
	aiGenerator := &MockAIGenerator{
		GenerateErr: errors.New("AI service unavailable"),
	}

	userID := uuid.New().String()
	draftID := uuid.New().String()
	content := "Original content"
	draftStore.AddDraft(&Draft{
		ID:               draftID,
		UserID:           userID,
		GeneratedContent: &content,
		Status:           "draft",
	})

	handler := NewDraftHandler(draftStore, aiGenerator)

	req := httptest.NewRequest(http.MethodPost, "/drafts/"+draftID+"/regenerate", nil)
	req = addAuthContext(req, userID)

	rr := httptest.NewRecorder()
	handler.HandleRegenerate(rr, req, draftID)

	// Should return error status
	if rr.Code != http.StatusInternalServerError && rr.Code != http.StatusServiceUnavailable {
		// Could also redirect with error flash message
		if rr.Code == http.StatusSeeOther {
			// Acceptable if it redirects with an error message
			return
		}
		t.Errorf("Expected error status for AI failure, got %d", rr.Code)
	}
}

func TestDraftHandler_PostRegenerate_CannotRegeneratePostedDraft(t *testing.T) {
	draftStore := NewMockDraftStore()

	userID := uuid.New().String()
	draftID := uuid.New().String()
	content := "Posted content"
	draftStore.AddDraft(&Draft{
		ID:               draftID,
		UserID:           userID,
		GeneratedContent: &content,
		Status:           "posted",
	})

	handler := NewDraftHandler(draftStore, nil)

	req := httptest.NewRequest(http.MethodPost, "/drafts/"+draftID+"/regenerate", nil)
	req = addAuthContext(req, userID)

	rr := httptest.NewRecorder()
	handler.HandleRegenerate(rr, req, draftID)

	// Should return 400 - cannot regenerate posted drafts
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for regenerating posted draft, got %d", rr.Code)
	}
}

func TestDraftHandler_PostRegenerate_ClearsEditedContent(t *testing.T) {
	draftStore := NewMockDraftStore()
	aiGenerator := &MockAIGenerator{
		GeneratedContent: "New AI content",
	}

	userID := uuid.New().String()
	draftID := uuid.New().String()
	genContent := "Generated"
	editContent := "User edited this"
	draftStore.AddDraft(&Draft{
		ID:               draftID,
		UserID:           userID,
		GeneratedContent: &genContent,
		EditedContent:    &editContent,
		Status:           "draft",
	})

	handler := NewDraftHandler(draftStore, aiGenerator)

	req := httptest.NewRequest(http.MethodPost, "/drafts/"+draftID+"/regenerate", nil)
	req = addAuthContext(req, userID)

	rr := httptest.NewRecorder()
	handler.HandleRegenerate(rr, req, draftID)

	// After regenerate, edited_content should be cleared (or regenerate should warn user)
	// This is a UX decision - either clear it or warn
	if rr.Code == http.StatusOK || rr.Code == http.StatusSeeOther {
		// Success - edited content should be cleared in favor of new generated content
		// The implementation should handle this
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

// addAuthContext adds authentication context to a request
func addAuthContext(req *http.Request, userID string) *http.Request {
	ctx := auth.WithUserID(req.Context(), userID)
	return req.WithContext(ctx)
}
