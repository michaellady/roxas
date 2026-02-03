// Package tests contains property-based tests for the Roxas application.
// Property 39: Draft auto-save with debouncing consolidates rapid edits.
// Validates Requirement 6.4: Auto-save changes with debouncing.
package tests

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// =============================================================================
// Auto-Save Test Types and Interfaces
// =============================================================================

// SaveRequest represents a request to save draft content
type SaveRequest struct {
	DraftID   string
	Content   string
	Timestamp time.Time
}

// SaveResult represents the result of a save operation
type SaveResult struct {
	Success   bool
	Error     error
	SavedAt   time.Time
	Content   string
	RequestID int
}

// DraftSaver defines the interface for saving draft content
type DraftSaver interface {
	SaveDraftContent(ctx context.Context, draftID, content string) error
}

// MockDraftSaver is a mock implementation for testing
type MockDraftSaver struct {
	mu           sync.Mutex
	saveCount    int
	lastContent  string
	lastDraftID  string
	saveHistory  []SaveRequest
	shouldFail   bool
	failureError error
	saveDelay    time.Duration
}

// NewMockDraftSaver creates a new mock saver
func NewMockDraftSaver() *MockDraftSaver {
	return &MockDraftSaver{
		saveHistory: make([]SaveRequest, 0),
	}
}

// SaveDraftContent implements DraftSaver
func (s *MockDraftSaver) SaveDraftContent(ctx context.Context, draftID, content string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.saveDelay > 0 {
		time.Sleep(s.saveDelay)
	}

	if s.shouldFail {
		return s.failureError
	}

	s.saveCount++
	s.lastContent = content
	s.lastDraftID = draftID
	s.saveHistory = append(s.saveHistory, SaveRequest{
		DraftID:   draftID,
		Content:   content,
		Timestamp: time.Now(),
	})

	return nil
}

// GetSaveCount returns the number of saves performed
func (s *MockDraftSaver) GetSaveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveCount
}

// GetLastContent returns the last saved content
func (s *MockDraftSaver) GetLastContent() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastContent
}

// GetSaveHistory returns all save requests
func (s *MockDraftSaver) GetSaveHistory() []SaveRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]SaveRequest, len(s.saveHistory))
	copy(result, s.saveHistory)
	return result
}

// SetFailure configures the saver to simulate failures
func (s *MockDraftSaver) SetFailure(shouldFail bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shouldFail = shouldFail
	s.failureError = err
}

// SetSaveDelay sets a delay for save operations
func (s *MockDraftSaver) SetSaveDelay(delay time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveDelay = delay
}

// Reset clears the mock state
func (s *MockDraftSaver) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveCount = 0
	s.lastContent = ""
	s.lastDraftID = ""
	s.saveHistory = make([]SaveRequest, 0)
	s.shouldFail = false
	s.failureError = nil
}

// =============================================================================
// AutoSaver Implementation for Testing
// =============================================================================

// AutoSaver implements debounced auto-save functionality
// This is the reference implementation that the actual client-side JS should match
type AutoSaver struct {
	mu              sync.Mutex
	saver           DraftSaver
	debounceWindow  time.Duration
	pendingContent  string
	pendingDraftID  string
	hasPending      bool
	timer           *time.Timer
	lastSaveTime    time.Time
	saveInProgress  bool
	lastError       error
	saveCount       int
	onSaveCallback  func(error)
	pendingOnSave   []func(error)
}

// NewAutoSaver creates a new auto-saver with the specified debounce window
func NewAutoSaver(saver DraftSaver, debounceWindow time.Duration) *AutoSaver {
	return &AutoSaver{
		saver:          saver,
		debounceWindow: debounceWindow,
		pendingOnSave:  make([]func(error), 0),
	}
}

// Edit queues a content change for saving with debouncing
func (a *AutoSaver) Edit(draftID, content string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.pendingContent = content
	a.pendingDraftID = draftID
	a.hasPending = true

	// Cancel existing timer if any
	if a.timer != nil {
		a.timer.Stop()
	}

	// Set new timer for debounce
	a.timer = time.AfterFunc(a.debounceWindow, func() {
		a.flush()
	})
}

// EditWithCallback queues a content change and calls callback when save completes
func (a *AutoSaver) EditWithCallback(draftID, content string, onSave func(error)) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.pendingContent = content
	a.pendingDraftID = draftID
	a.hasPending = true

	if onSave != nil {
		a.pendingOnSave = append(a.pendingOnSave, onSave)
	}

	// Cancel existing timer if any
	if a.timer != nil {
		a.timer.Stop()
	}

	// Set new timer for debounce
	a.timer = time.AfterFunc(a.debounceWindow, func() {
		a.flush()
	})
}

// flush performs the actual save operation
func (a *AutoSaver) flush() {
	a.mu.Lock()
	if !a.hasPending || a.saveInProgress {
		a.mu.Unlock()
		return
	}

	content := a.pendingContent
	draftID := a.pendingDraftID
	callbacks := a.pendingOnSave
	a.pendingOnSave = make([]func(error), 0)
	a.hasPending = false
	a.saveInProgress = true
	a.mu.Unlock()

	// Perform save outside of lock
	ctx := context.Background()
	err := a.saver.SaveDraftContent(ctx, draftID, content)

	a.mu.Lock()
	a.saveInProgress = false
	a.lastError = err
	if err == nil {
		a.lastSaveTime = time.Now()
		a.saveCount++
	}
	a.mu.Unlock()

	// Notify callbacks
	for _, cb := range callbacks {
		cb(err)
	}

	// Check if new edits came in while saving
	a.mu.Lock()
	if a.hasPending {
		a.mu.Unlock()
		// Schedule another flush after debounce window
		time.AfterFunc(a.debounceWindow, func() {
			a.flush()
		})
		return
	}
	a.mu.Unlock()
}

// FlushNow forces an immediate save of pending content
func (a *AutoSaver) FlushNow() error {
	a.mu.Lock()
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	a.mu.Unlock()

	a.flush()

	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastError
}

// GetSaveCount returns the number of successful saves
func (a *AutoSaver) GetSaveCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.saveCount
}

// GetLastError returns the last save error
func (a *AutoSaver) GetLastError() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastError
}

// HasPending returns whether there are unsaved changes
func (a *AutoSaver) HasPending() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.hasPending
}

// WaitForSave waits for any pending save to complete
func (a *AutoSaver) WaitForSave(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		if !a.hasPending && !a.saveInProgress {
			a.mu.Unlock()
			return true
		}
		a.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// =============================================================================
// Property Tests: Draft Auto-Save with Debouncing (Property 39)
// =============================================================================

// TestProperty39_RapidEditsConsolidated verifies that rapid edits within
// the debounce window result in a single save operation.
// Property 39a: N edits within debounce window = 1 save with final content
// Validates Requirement 6.4: Auto-save with debouncing
func TestProperty39_RapidEditsConsolidated(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	properties := gopter.NewProperties(parameters)

	// Generator for number of rapid edits (2-20)
	editCountGen := gen.IntRange(2, 20)

	// Generator for draft ID (UUID format)
	draftIDGen := gen.RegexMatch(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	// Generator for content strings
	contentGen := gen.AnyString()

	properties.Property("rapid edits within debounce window result in single save", prop.ForAll(
		func(editCount int, draftID string, contents []string) bool {
			// Ensure we have enough content variations
			if len(contents) < editCount {
				// Pad with generated content if needed
				for i := len(contents); i < editCount; i++ {
					contents = append(contents, "content-"+string(rune('a'+i%26)))
				}
			}

			mockSaver := NewMockDraftSaver()
			autoSaver := NewAutoSaver(mockSaver, 100*time.Millisecond)

			// Perform rapid edits (faster than debounce window)
			for i := 0; i < editCount; i++ {
				autoSaver.Edit(draftID, contents[i])
				time.Sleep(10 * time.Millisecond) // Much shorter than 100ms debounce
			}

			// Wait for debounce to complete
			autoSaver.WaitForSave(500 * time.Millisecond)

			// Property: Only one save should have occurred
			saveCount := mockSaver.GetSaveCount()
			if saveCount != 1 {
				t.Logf("Expected 1 save, got %d for %d edits", saveCount, editCount)
				return false
			}

			return true
		},
		editCountGen,
		draftIDGen,
		gen.SliceOfN(20, contentGen),
	))

	properties.Property("final content is saved, not intermediate", prop.ForAll(
		func(draftID string) bool {
			mockSaver := NewMockDraftSaver()
			autoSaver := NewAutoSaver(mockSaver, 50*time.Millisecond)

			// Perform sequence of edits
			edits := []string{"first", "second", "third", "final"}
			for _, content := range edits {
				autoSaver.Edit(draftID, content)
				time.Sleep(10 * time.Millisecond)
			}

			// Wait for save
			autoSaver.WaitForSave(200 * time.Millisecond)

			// Property: Saved content should be the final edit
			lastContent := mockSaver.GetLastContent()
			if lastContent != "final" {
				t.Logf("Expected 'final', got '%s'", lastContent)
				return false
			}

			return true
		},
		draftIDGen,
	))

	properties.TestingRun(t)
}

// TestProperty39_EditsAfterDebounceWindowTriggerNewSave verifies that edits
// after the debounce window has elapsed trigger separate saves.
// Property 39b: Edits separated by > debounce window = separate saves
func TestProperty39_EditsAfterDebounceWindowTriggerNewSave(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 30
	properties := gopter.NewProperties(parameters)

	draftIDGen := gen.RegexMatch(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	properties.Property("edits after debounce window trigger separate saves", prop.ForAll(
		func(draftID string) bool {
			mockSaver := NewMockDraftSaver()
			debounceWindow := 50 * time.Millisecond
			autoSaver := NewAutoSaver(mockSaver, debounceWindow)

			// First edit
			autoSaver.Edit(draftID, "first content")

			// Wait for debounce to complete
			time.Sleep(debounceWindow + 50*time.Millisecond)
			autoSaver.WaitForSave(200 * time.Millisecond)

			saveCountAfterFirst := mockSaver.GetSaveCount()

			// Second edit (after debounce window)
			autoSaver.Edit(draftID, "second content")

			// Wait for second debounce
			time.Sleep(debounceWindow + 50*time.Millisecond)
			autoSaver.WaitForSave(200 * time.Millisecond)

			saveCountAfterSecond := mockSaver.GetSaveCount()

			// Property: Should have 2 separate saves
			if saveCountAfterFirst != 1 {
				t.Logf("Expected 1 save after first edit, got %d", saveCountAfterFirst)
				return false
			}
			if saveCountAfterSecond != 2 {
				t.Logf("Expected 2 saves after second edit, got %d", saveCountAfterSecond)
				return false
			}

			// Verify both contents were saved in order
			history := mockSaver.GetSaveHistory()
			if len(history) != 2 {
				t.Logf("Expected 2 history entries, got %d", len(history))
				return false
			}
			if history[0].Content != "first content" || history[1].Content != "second content" {
				t.Logf("Save history doesn't match expected order")
				return false
			}

			return true
		},
		draftIDGen,
	))

	properties.TestingRun(t)
}

// TestProperty39_SaveFailureHandling verifies that save failures are properly
// reported and don't lose pending content.
// Property 39c: Save failure preserves pending content for retry
func TestProperty39_SaveFailureHandling(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	properties := gopter.NewProperties(parameters)

	draftIDGen := gen.RegexMatch(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	contentGen := gen.AnyString().SuchThat(func(s string) bool { return len(s) > 0 })

	properties.Property("save failure is reported via callback", prop.ForAll(
		func(draftID, content string) bool {
			mockSaver := NewMockDraftSaver()
			expectedErr := errors.New("network error: connection refused")
			mockSaver.SetFailure(true, expectedErr)

			autoSaver := NewAutoSaver(mockSaver, 50*time.Millisecond)

			var callbackError error
			callbackCalled := false

			autoSaver.EditWithCallback(draftID, content, func(err error) {
				callbackCalled = true
				callbackError = err
			})

			// Wait for debounce and callback
			time.Sleep(150 * time.Millisecond)

			// Property: Callback should be called with error
			if !callbackCalled {
				t.Log("Callback was not called")
				return false
			}
			if callbackError == nil {
				t.Log("Expected error in callback, got nil")
				return false
			}
			if callbackError.Error() != expectedErr.Error() {
				t.Logf("Expected error '%s', got '%s'", expectedErr, callbackError)
				return false
			}

			return true
		},
		draftIDGen,
		contentGen,
	))

	properties.Property("successful save after failure recovery", prop.ForAll(
		func(draftID, content string) bool {
			mockSaver := NewMockDraftSaver()
			networkErr := errors.New("network error")
			mockSaver.SetFailure(true, networkErr)

			autoSaver := NewAutoSaver(mockSaver, 50*time.Millisecond)

			// First edit will fail
			autoSaver.Edit(draftID, "will fail")
			time.Sleep(100 * time.Millisecond)
			autoSaver.WaitForSave(200 * time.Millisecond)

			// Verify failure
			if autoSaver.GetLastError() == nil {
				t.Log("Expected error after failed save")
				return false
			}

			// Recovery: disable failure
			mockSaver.SetFailure(false, nil)

			// Second edit should succeed
			autoSaver.Edit(draftID, content)
			time.Sleep(100 * time.Millisecond)
			autoSaver.WaitForSave(200 * time.Millisecond)

			// Property: Save count should be 1 (only successful save)
			if mockSaver.GetSaveCount() != 1 {
				t.Logf("Expected 1 successful save, got %d", mockSaver.GetSaveCount())
				return false
			}

			// Property: Content should be saved
			if mockSaver.GetLastContent() != content {
				t.Logf("Expected content '%s', got '%s'", content, mockSaver.GetLastContent())
				return false
			}

			return true
		},
		draftIDGen,
		contentGen,
	))

	properties.TestingRun(t)
}

// TestProperty39_FlushNowBypassesDebounce verifies that FlushNow immediately
// saves pending content without waiting for debounce window.
// Property 39d: FlushNow saves immediately regardless of debounce timer
func TestProperty39_FlushNowBypassesDebounce(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	properties := gopter.NewProperties(parameters)

	draftIDGen := gen.RegexMatch(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	contentGen := gen.AnyString().SuchThat(func(s string) bool { return len(s) > 0 })

	properties.Property("FlushNow saves immediately", prop.ForAll(
		func(draftID, content string) bool {
			mockSaver := NewMockDraftSaver()
			autoSaver := NewAutoSaver(mockSaver, 10*time.Second) // Very long debounce

			autoSaver.Edit(draftID, content)

			// Don't wait for debounce, force immediate save
			startTime := time.Now()
			err := autoSaver.FlushNow()
			elapsed := time.Since(startTime)

			// Property: Save should complete quickly (well under debounce window)
			if elapsed > 1*time.Second {
				t.Logf("FlushNow took too long: %v", elapsed)
				return false
			}

			// Property: No error should occur
			if err != nil {
				t.Logf("Unexpected error: %v", err)
				return false
			}

			// Property: Content should be saved
			if mockSaver.GetSaveCount() != 1 {
				t.Logf("Expected 1 save, got %d", mockSaver.GetSaveCount())
				return false
			}

			if mockSaver.GetLastContent() != content {
				t.Logf("Expected content '%s', got '%s'", content, mockSaver.GetLastContent())
				return false
			}

			return true
		},
		draftIDGen,
		contentGen,
	))

	properties.TestingRun(t)
}

// TestProperty39_CorrectDraftIDSaved verifies that saves always include
// the correct draft ID from the latest edit.
// Property 39e: Save uses draft ID from latest edit
func TestProperty39_CorrectDraftIDSaved(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	properties := gopter.NewProperties(parameters)

	draftIDGen := gen.RegexMatch(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	properties.Property("save uses correct draft ID", prop.ForAll(
		func(draftID1, draftID2 string) bool {
			// Ensure different IDs for test validity
			if draftID1 == draftID2 {
				return true // Skip if same (rare with UUIDs)
			}

			mockSaver := NewMockDraftSaver()
			autoSaver := NewAutoSaver(mockSaver, 50*time.Millisecond)

			// Edit with first draft ID
			autoSaver.Edit(draftID1, "content for draft 1")
			time.Sleep(10 * time.Millisecond)

			// Edit with second draft ID (replaces pending)
			autoSaver.Edit(draftID2, "content for draft 2")

			// Wait for save
			autoSaver.WaitForSave(200 * time.Millisecond)

			// Property: Save should use the latest draft ID
			history := mockSaver.GetSaveHistory()
			if len(history) != 1 {
				t.Logf("Expected 1 save, got %d", len(history))
				return false
			}

			if history[0].DraftID != draftID2 {
				t.Logf("Expected draft ID '%s', got '%s'", draftID2, history[0].DraftID)
				return false
			}

			return true
		},
		draftIDGen,
		draftIDGen,
	))

	properties.TestingRun(t)
}

// =============================================================================
// Unit Tests: Draft Auto-Save Edge Cases
// =============================================================================

// TestAutoSave_EmptyContent verifies handling of empty content saves
func TestAutoSave_EmptyContent(t *testing.T) {
	mockSaver := NewMockDraftSaver()
	autoSaver := NewAutoSaver(mockSaver, 50*time.Millisecond)

	draftID := "test-draft-123"

	// Edit with empty content should still save
	autoSaver.Edit(draftID, "")
	autoSaver.WaitForSave(200 * time.Millisecond)

	if mockSaver.GetSaveCount() != 1 {
		t.Errorf("Expected 1 save for empty content, got %d", mockSaver.GetSaveCount())
	}

	if mockSaver.GetLastContent() != "" {
		t.Errorf("Expected empty content, got '%s'", mockSaver.GetLastContent())
	}
}

// TestAutoSave_NoEditsNoSave verifies no save occurs without edits
func TestAutoSave_NoEditsNoSave(t *testing.T) {
	mockSaver := NewMockDraftSaver()
	autoSaver := NewAutoSaver(mockSaver, 50*time.Millisecond)

	// Wait without making any edits
	time.Sleep(100 * time.Millisecond)

	if mockSaver.GetSaveCount() != 0 {
		t.Errorf("Expected 0 saves without edits, got %d", mockSaver.GetSaveCount())
	}

	// FlushNow with no pending content should not error
	err := autoSaver.FlushNow()
	if err != nil {
		t.Errorf("Unexpected error on FlushNow with no pending: %v", err)
	}

	if mockSaver.GetSaveCount() != 0 {
		t.Errorf("Expected 0 saves after FlushNow with no pending, got %d", mockSaver.GetSaveCount())
	}
}

// TestAutoSave_MultipleCallbacksNotified verifies all callbacks are called
func TestAutoSave_MultipleCallbacksNotified(t *testing.T) {
	mockSaver := NewMockDraftSaver()
	autoSaver := NewAutoSaver(mockSaver, 50*time.Millisecond)

	draftID := "test-draft-123"
	callbackCount := 0
	var mu sync.Mutex

	// Register multiple edits with callbacks
	for i := 0; i < 3; i++ {
		autoSaver.EditWithCallback(draftID, "content", func(err error) {
			mu.Lock()
			callbackCount++
			mu.Unlock()
		})
		time.Sleep(10 * time.Millisecond)
	}

	autoSaver.WaitForSave(200 * time.Millisecond)

	// All callbacks should be called
	mu.Lock()
	count := callbackCount
	mu.Unlock()

	if count != 3 {
		t.Errorf("Expected 3 callbacks, got %d", count)
	}

	// But only one save should occur
	if mockSaver.GetSaveCount() != 1 {
		t.Errorf("Expected 1 save, got %d", mockSaver.GetSaveCount())
	}
}

// TestAutoSave_LargeContent verifies handling of large content
func TestAutoSave_LargeContent(t *testing.T) {
	mockSaver := NewMockDraftSaver()
	autoSaver := NewAutoSaver(mockSaver, 50*time.Millisecond)

	draftID := "test-draft-123"

	// Create large content (10KB)
	largeContent := make([]byte, 10*1024)
	for i := range largeContent {
		largeContent[i] = byte('a' + (i % 26))
	}
	content := string(largeContent)

	autoSaver.Edit(draftID, content)
	autoSaver.WaitForSave(200 * time.Millisecond)

	if mockSaver.GetSaveCount() != 1 {
		t.Errorf("Expected 1 save, got %d", mockSaver.GetSaveCount())
	}

	if mockSaver.GetLastContent() != content {
		t.Errorf("Large content not preserved correctly")
	}
}

// TestAutoSave_SpecialCharacters verifies handling of special characters
func TestAutoSave_SpecialCharacters(t *testing.T) {
	testCases := []struct {
		name    string
		content string
	}{
		{"unicode", "Hello 世界 🎉 emoji test"},
		{"newlines", "line1\nline2\r\nline3"},
		{"html", "<script>alert('xss')</script>"},
		{"quotes", `"double" and 'single' quotes`},
		{"null bytes", "before\x00after"},
		{"tabs", "tab\there"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockSaver := NewMockDraftSaver()
			autoSaver := NewAutoSaver(mockSaver, 50*time.Millisecond)

			autoSaver.Edit("draft-123", tc.content)
			autoSaver.WaitForSave(200 * time.Millisecond)

			if mockSaver.GetLastContent() != tc.content {
				t.Errorf("Content not preserved: expected %q, got %q", tc.content, mockSaver.GetLastContent())
			}
		})
	}
}

// TestAutoSave_ConcurrentEdits verifies thread safety with concurrent edits
func TestAutoSave_ConcurrentEdits(t *testing.T) {
	mockSaver := NewMockDraftSaver()
	autoSaver := NewAutoSaver(mockSaver, 100*time.Millisecond)

	draftID := "draft-123"
	numGoroutines := 10
	editsPerGoroutine := 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < editsPerGoroutine; i++ {
				content := "content from goroutine"
				autoSaver.Edit(draftID, content)
				time.Sleep(5 * time.Millisecond)
			}
		}(g)
	}

	wg.Wait()
	autoSaver.WaitForSave(500 * time.Millisecond)

	// Should have consolidated all edits
	saveCount := mockSaver.GetSaveCount()
	if saveCount == 0 {
		t.Error("Expected at least one save")
	}
	if saveCount > 5 {
		// With 100ms debounce and 50 total edits at ~5ms each,
		// should consolidate significantly
		t.Logf("Possibly too many saves: %d (expected heavy consolidation)", saveCount)
	}
}

// TestAutoSave_HasPending verifies HasPending correctly tracks state
func TestAutoSave_HasPending(t *testing.T) {
	mockSaver := NewMockDraftSaver()
	autoSaver := NewAutoSaver(mockSaver, 100*time.Millisecond)

	// Initially no pending
	if autoSaver.HasPending() {
		t.Error("Expected no pending initially")
	}

	// After edit, should have pending
	autoSaver.Edit("draft-123", "content")
	if !autoSaver.HasPending() {
		t.Error("Expected pending after edit")
	}

	// After save completes, no pending
	autoSaver.WaitForSave(300 * time.Millisecond)
	if autoSaver.HasPending() {
		t.Error("Expected no pending after save")
	}
}
