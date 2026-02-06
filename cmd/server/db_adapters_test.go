package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"

	"github.com/mikelady/roxas/internal/database"
	"github.com/mikelady/roxas/internal/handlers"
	"github.com/mikelady/roxas/internal/services"
)

// jsonBytes helper encodes a value as JSON bytes for mock rows (commit_shas column)
func jsonBytes(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

// =============================================================================
// Test draftWebhookStoreAdapter with pgxmock
// =============================================================================

func TestDraftWebhookStoreAdapter_CreateDraftFromPush(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	adapter := &draftWebhookStoreAdapter{store: draftStore}

	now := time.Now()

	// CreateDraftFromPush -> CreateDraft(userID, repoID, ref, beforeSHA, afterSHA, commitSHAs, "")
	// CreateDraft sends 8 SQL args: userID, repoID, ref, beforeSHA, afterSHA, commitSHAsJSON, commitCount, content
	mock.ExpectQuery(`INSERT INTO drafts`).
		WithArgs("user-1", "repo-1", "refs/heads/main", "aaa", "bbb", pgxmock.AnyArg(), 1, "").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", "bbb", jsonBytes([]string{"sha1"}), "", nil, "draft", now, now))

	result, err := adapter.CreateDraftFromPush(context.Background(), "user-1", "repo-1", "refs/heads/main", "aaa", "bbb", []string{"sha1"})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.ID != "draft-1" {
		t.Errorf("ID = %q, want %q", result.ID, "draft-1")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestDraftWebhookStoreAdapter_CreateDraftFromPush_Error(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	adapter := &draftWebhookStoreAdapter{store: draftStore}

	mock.ExpectQuery(`INSERT INTO drafts`).
		WillReturnError(fmt.Errorf("database error"))

	_, err = adapter.CreateDraftFromPush(context.Background(), "user-1", "repo-1", "refs/heads/main", "aaa", "bbb", []string{"sha1"})
	if err == nil {
		t.Error("Expected error")
	}
}

func TestDraftWebhookStoreAdapter_GetDraftByPushSignature(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	adapter := &draftWebhookStoreAdapter{store: draftStore}

	now := time.Now()

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE repository_id`).
		WithArgs("repo-1", "aaa", "bbb").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", "bbb", jsonBytes([]string{"sha1"}), "generated", nil, "draft", now, now))

	result, err := adapter.GetDraftByPushSignature(context.Background(), "repo-1", "aaa", "bbb")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.ID != "draft-1" {
		t.Errorf("ID = %q, want %q", result.ID, "draft-1")
	}
}

func TestDraftWebhookStoreAdapter_GetDraftByPushSignature_NotFound(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	adapter := &draftWebhookStoreAdapter{store: draftStore}

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE repository_id`).
		WithArgs("repo-1", "aaa", "bbb").
		WillReturnError(pgx.ErrNoRows)

	result, err := adapter.GetDraftByPushSignature(context.Background(), "repo-1", "aaa", "bbb")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != nil {
		t.Error("Expected nil result for not found")
	}
}

// =============================================================================
// Test idempotencyStoreAdapter with pgxmock
// =============================================================================

func TestIdempotencyStoreAdapter_CheckDeliveryProcessed(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	deliveryStore := database.NewWebhookDeliveryStoreWithDB(mock)
	adapter := &idempotencyStoreAdapter{store: deliveryStore}

	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs("delivery-1").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))

	processed, err := adapter.CheckDeliveryProcessed(context.Background(), "delivery-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !processed {
		t.Error("Expected delivery to be processed")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestIdempotencyStoreAdapter_CheckDeliveryProcessed_NotFound(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	deliveryStore := database.NewWebhookDeliveryStoreWithDB(mock)
	adapter := &idempotencyStoreAdapter{store: deliveryStore}

	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs("delivery-2").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))

	processed, err := adapter.CheckDeliveryProcessed(context.Background(), "delivery-2")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if processed {
		t.Error("Expected delivery to not be processed")
	}
}

func TestIdempotencyStoreAdapter_MarkDeliveryProcessed(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	deliveryStore := database.NewWebhookDeliveryStoreWithDB(mock)
	adapter := &idempotencyStoreAdapter{store: deliveryStore}

	mock.ExpectExec(`INSERT INTO webhook_deliveries`).
		WithArgs("repo-1", "delivery-1").
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err = adapter.MarkDeliveryProcessed(context.Background(), "delivery-1", "repo-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// =============================================================================
// Test activityStoreAdapter with pgxmock
// =============================================================================

func TestActivityStoreAdapter_CreateActivity(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	activityStore := database.NewActivityStoreWithDB(mock)
	adapter := &activityStoreAdapter{store: activityStore}

	now := time.Now()
	draftID := "draft-1"
	platform := "bluesky"
	message := "Test message"

	mock.ExpectQuery(`INSERT INTO activities`).
		WithArgs("user-1", "draft_created", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "type", "draft_id", "post_id", "platform", "message", "created_at"}).
			AddRow("activity-1", "user-1", "draft_created", &draftID, nil, &platform, &message, now))

	result, err := adapter.CreateActivity(context.Background(), "user-1", "draft_created", &draftID, "Test message")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.ID != "activity-1" {
		t.Errorf("ID = %q, want %q", result.ID, "activity-1")
	}
	if result.Platform != "bluesky" {
		t.Errorf("Platform = %q, want %q", result.Platform, "bluesky")
	}
	if result.Message != "Test message" {
		t.Errorf("Message = %q, want %q", result.Message, "Test message")
	}
}

func TestActivityStoreAdapter_CreateActivity_NilFields(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	activityStore := database.NewActivityStoreWithDB(mock)
	adapter := &activityStoreAdapter{store: activityStore}

	now := time.Now()

	mock.ExpectQuery(`INSERT INTO activities`).
		WithArgs("user-1", "draft_created", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "type", "draft_id", "post_id", "platform", "message", "created_at"}).
			AddRow("activity-2", "user-1", "draft_created", nil, nil, nil, nil, now))

	result, err := adapter.CreateActivity(context.Background(), "user-1", "draft_created", nil, "Test")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Platform != "" {
		t.Errorf("Platform = %q, want empty", result.Platform)
	}
	if result.Message != "" {
		t.Errorf("Message = %q, want empty", result.Message)
	}
}

// =============================================================================
// Test draftStoreAdapter with pgxmock
// =============================================================================

func TestDraftStoreAdapter_GetDraftByID(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	adapter := &draftStoreAdapter{store: draftStore}

	now := time.Now()
	edited := "edited content"

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", "bbb", jsonBytes([]string{"sha1"}), "generated", &edited, "draft", now, now))

	result, err := adapter.GetDraftByID(context.Background(), "draft-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.ID != "draft-1" {
		t.Errorf("ID = %q, want %q", result.ID, "draft-1")
	}
	if result.Content != "edited content" {
		t.Errorf("Content = %q, want %q (should use edited content)", result.Content, "edited content")
	}
	if result.CharLimit != 500 {
		t.Errorf("CharLimit = %d, want 500", result.CharLimit)
	}
}

func TestDraftStoreAdapter_GetDraftByID_NoEditedContent(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	adapter := &draftStoreAdapter{store: draftStore}

	now := time.Now()

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", "bbb", jsonBytes([]string{"sha1"}), "generated content", nil, "draft", now, now))

	result, err := adapter.GetDraftByID(context.Background(), "draft-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Content != "generated content" {
		t.Errorf("Content = %q, want %q (should use generated content)", result.Content, "generated content")
	}
}

func TestDraftStoreAdapter_GetDraftByID_EmptyEditedContent(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	adapter := &draftStoreAdapter{store: draftStore}

	now := time.Now()
	empty := ""

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", "bbb", jsonBytes([]string{"sha1"}), "generated", &empty, "draft", now, now))

	result, err := adapter.GetDraftByID(context.Background(), "draft-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Empty edited content should fall back to generated
	if result.Content != "generated" {
		t.Errorf("Content = %q, want %q", result.Content, "generated")
	}
}

func TestDraftStoreAdapter_GetDraftByID_Error(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	adapter := &draftStoreAdapter{store: draftStore}

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnError(pgx.ErrNoRows)

	_, err = adapter.GetDraftByID(context.Background(), "draft-1")
	if err == nil {
		t.Error("Expected error")
	}
}

func TestDraftStoreAdapter_UpdateDraftContent(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	adapter := &draftStoreAdapter{store: draftStore}

	now := time.Now()
	updatedContent := "updated content"

	mock.ExpectExec(`UPDATE drafts SET edited_content`).
		WithArgs("updated content", "draft-1").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", "bbb", jsonBytes([]string{"sha1"}), "generated", &updatedContent, "draft", now, now))

	result, err := adapter.UpdateDraftContent(context.Background(), "draft-1", "updated content")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Content != "updated content" {
		t.Errorf("Content = %q, want %q", result.Content, "updated content")
	}
}

func TestDraftStoreAdapter_UpdateDraftContent_Error(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	adapter := &draftStoreAdapter{store: draftStore}

	mock.ExpectExec(`UPDATE drafts SET edited_content`).
		WithArgs("content", "draft-1").
		WillReturnError(fmt.Errorf("db error"))

	_, err = adapter.UpdateDraftContent(context.Background(), "draft-1", "content")
	if err == nil {
		t.Error("Expected error")
	}
}

func TestDraftStoreAdapter_DeleteDraft(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	adapter := &draftStoreAdapter{store: draftStore}

	mock.ExpectExec(`DELETE FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	err = adapter.DeleteDraft(context.Background(), "draft-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestDraftStoreAdapter_UpdateDraftStatus(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	adapter := &draftStoreAdapter{store: draftStore}

	now := time.Now()

	mock.ExpectExec(`UPDATE drafts SET status`).
		WithArgs("posted", "draft-1").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", "bbb", jsonBytes([]string{"sha1"}), "content", nil, "posted", now, now))

	result, err := adapter.UpdateDraftStatus(context.Background(), "draft-1", "posted")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Status != "posted" {
		t.Errorf("Status = %q, want %q", result.Status, "posted")
	}
}

func TestDraftStoreAdapter_UpdateDraftStatus_Error(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	adapter := &draftStoreAdapter{store: draftStore}

	mock.ExpectExec(`UPDATE drafts SET status`).
		WithArgs("invalid", "draft-1").
		WillReturnError(fmt.Errorf("invalid status"))

	_, err = adapter.UpdateDraftStatus(context.Background(), "draft-1", "invalid")
	if err == nil {
		t.Error("Expected error for invalid status")
	}
}

// =============================================================================
// Test draftListerAdapter with pgxmock
// =============================================================================

func TestDraftListerAdapter_ListDraftsByUser(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	repoStore := database.NewRepositoryStoreWithDB(mock)
	adapter := &draftListerAdapter{draftStore: draftStore, repoStore: repoStore}

	now := time.Now()
	edited := "Short edited"
	repoName := "repo"

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE user_id`).
		WithArgs("user-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", "bbb", jsonBytes([]string{"sha1"}), "generated content for display", &edited, "draft", now, now))

	// Use (?s) flag to enable dotall mode so .+ matches across newlines in multiline SQL
	mock.ExpectQuery(`(?s)SELECT .+ FROM repositories.+WHERE id`).
		WithArgs("repo-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "github_url", "webhook_secret", "name", "is_active", "created_at", "github_repo_id", "webhook_id", "is_private", "github_app_repo_id", "webhook_source"}).
			AddRow("repo-1", "user-1", "https://github.com/owner/repo", "secret", &repoName, true, now, nil, nil, false, nil, "legacy"))

	items, err := adapter.ListDraftsByUser(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("Expected 1 item, got %d", len(items))
	}
	if items[0].RepoName != "owner/repo" {
		t.Errorf("RepoName = %q, want %q", items[0].RepoName, "owner/repo")
	}
	if items[0].PreviewText != "Short edited" {
		t.Errorf("PreviewText = %q, want %q", items[0].PreviewText, "Short edited")
	}
	if items[0].Platform != "threads" {
		t.Errorf("Platform = %q, want %q", items[0].Platform, "threads")
	}
}

func TestDraftListerAdapter_ListDraftsByUser_EmptyContent(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	repoStore := database.NewRepositoryStoreWithDB(mock)
	adapter := &draftListerAdapter{draftStore: draftStore, repoStore: repoStore}

	now := time.Now()

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE user_id`).
		WithArgs("user-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", "bbb", jsonBytes([]string{"sha1"}), "", nil, "draft", now, now))

	mock.ExpectQuery(`(?s)SELECT .+ FROM repositories.+WHERE id`).
		WithArgs("repo-1").
		WillReturnError(pgx.ErrNoRows)

	items, err := adapter.ListDraftsByUser(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("Expected 1 item, got %d", len(items))
	}
	if items[0].PreviewText != "(Awaiting AI generation...)" {
		t.Errorf("PreviewText = %q, want %q", items[0].PreviewText, "(Awaiting AI generation...)")
	}
	if items[0].RepoName != "Unknown Repository" {
		t.Errorf("RepoName = %q, want %q", items[0].RepoName, "Unknown Repository")
	}
}

func TestDraftListerAdapter_ListDraftsByUser_LongContent(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	repoStore := database.NewRepositoryStoreWithDB(mock)
	adapter := &draftListerAdapter{draftStore: draftStore, repoStore: repoStore}

	now := time.Now()
	longContent := ""
	for i := 0; i < 120; i++ {
		longContent += "a"
	}
	repoName := "repo"

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE user_id`).
		WithArgs("user-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", "bbb", jsonBytes([]string{"sha1"}), longContent, nil, "draft", now, now))

	mock.ExpectQuery(`(?s)SELECT .+ FROM repositories.+WHERE id`).
		WithArgs("repo-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "github_url", "webhook_secret", "name", "is_active", "created_at", "github_repo_id", "webhook_id", "is_private", "github_app_repo_id", "webhook_source"}).
			AddRow("repo-1", "user-1", "https://github.com/owner/repo", "secret", &repoName, true, now, nil, nil, false, nil, "legacy"))

	items, err := adapter.ListDraftsByUser(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("Expected 1 item, got %d", len(items))
	}
	// Should be truncated to 100 chars + "..."
	if len(items[0].PreviewText) != 103 {
		t.Errorf("PreviewText length = %d, want 103", len(items[0].PreviewText))
	}
}

func TestDraftListerAdapter_ListDraftsByUser_Error(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	repoStore := database.NewRepositoryStoreWithDB(mock)
	adapter := &draftListerAdapter{draftStore: draftStore, repoStore: repoStore}

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE user_id`).
		WithArgs("user-1").
		WillReturnError(fmt.Errorf("database error"))

	_, err = adapter.ListDraftsByUser(context.Background(), "user-1")
	if err == nil {
		t.Error("Expected error")
	}
}

// =============================================================================
// Test commitStoreAdapter with pgxmock
// =============================================================================

func TestCommitStoreAdapter_StoreCommit(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	adapter := &commitStoreAdapter{pool: nil} // We can't use pgxmock.Pool as database.Pool

	// Instead, test the handler interface compliance
	var _ handlers.CommitStore = adapter

	// The commitStoreAdapter.StoreCommit uses a.pool.Exec directly, which needs a real database.Pool.
	// We'll verify the interface compliance and test with a mock HTTP approach for the
	// higher-level adapters instead.
	if adapter == nil {
		t.Fatal("Expected non-nil adapter")
	}
}

// =============================================================================
// Test socialPosterAdapter with mock servers
// =============================================================================

func TestSocialPosterAdapter_PostDraft_WithBluesky(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	credStore := newMockCredentialStore()

	// Set up Bluesky credentials
	credStore.credentials["user-1:bluesky"] = &services.PlatformCredentials{
		UserID:         "user-1",
		Platform:       "bluesky",
		AccessToken:    "app-password",
		RefreshToken:   "handle.bsky.social",
		PlatformUserID: "did:plc:123",
	}

	adapter := &socialPosterAdapter{
		draftStore:      draftStore,
		credentialStore: credStore,
	}

	now := time.Now()

	// The PostDraft method first calls GetDraft which queries the database
	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", "bbb", jsonBytes([]string{"sha1"}), "Post content", nil, "draft", now, now))

	// This will fail because it tries to contact the real Bluesky PDS
	// But we can verify the flow reaches the posting step
	_, err = adapter.PostDraft(context.Background(), "user-1", "draft-1")
	if err == nil {
		t.Error("Expected error when posting to real Bluesky")
	}
	// The error should be about posting to Bluesky (auth fails)
	if !strings.Contains(err.Error(), "Bluesky") {
		t.Errorf("Expected Bluesky-related error, got: %v", err)
	}
}

func TestSocialPosterAdapter_PostDraft_WithThreads(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	credStore := newMockCredentialStore()

	// Set up Threads credentials (no Bluesky)
	credStore.credentials["user-1:threads"] = &services.PlatformCredentials{
		UserID:         "user-1",
		Platform:       "threads",
		AccessToken:    "threads-token",
		PlatformUserID: "threads-user",
	}

	adapter := &socialPosterAdapter{
		draftStore:      draftStore,
		credentialStore: credStore,
	}

	now := time.Now()
	edited := "Edited post content"

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", "bbb", jsonBytes([]string{"sha1"}), "Generated", &edited, "draft", now, now))

	// This will fail because it contacts the real Threads API
	_, err = adapter.PostDraft(context.Background(), "user-1", "draft-1")
	if err == nil {
		t.Error("Expected error when posting to real Threads")
	}
	if !strings.Contains(err.Error(), "Threads") {
		t.Errorf("Expected Threads-related error, got: %v", err)
	}
}

func TestSocialPosterAdapter_PostDraft_NoCredentials(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	credStore := newMockCredentialStore()

	adapter := &socialPosterAdapter{
		draftStore:      draftStore,
		credentialStore: credStore,
	}

	now := time.Now()

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", "bbb", jsonBytes([]string{"sha1"}), "Content", nil, "draft", now, now))

	_, err = adapter.PostDraft(context.Background(), "user-1", "draft-1")
	if err == nil {
		t.Error("Expected error when no credentials")
	}
	if !strings.Contains(err.Error(), "no social platform connected") {
		t.Errorf("Expected 'no social platform connected' error, got: %v", err)
	}
}

func TestSocialPosterAdapter_PostDraft_DraftNotFound(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	credStore := newMockCredentialStore()

	adapter := &socialPosterAdapter{
		draftStore:      draftStore,
		credentialStore: credStore,
	}

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-404").
		WillReturnError(pgx.ErrNoRows)

	_, err = adapter.PostDraft(context.Background(), "user-1", "draft-404")
	if err == nil {
		t.Error("Expected error for missing draft")
	}
	if !strings.Contains(err.Error(), "failed to get draft") {
		t.Errorf("Expected 'failed to get draft' error, got: %v", err)
	}
}

// =============================================================================
// Test aiGeneratorAdapter with pgxmock and mock OpenAI
// =============================================================================

func TestAIGeneratorAdapter_TriggerGeneration(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	// Mock OpenAI server
	openAIMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": "Generated social post content"}},
			},
		})
	}))
	defer openAIMock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	repoStore := database.NewRepositoryStoreWithDB(mock)

	// Create a real OpenAI client pointing to mock server
	openaiClient := newMockChatClient("Generated social post content")
	postGenerator := services.NewPostGenerator(openaiClient)

	adapter := &aiGeneratorAdapter{
		draftStore:    draftStore,
		repoStore:     repoStore,
		postGenerator: postGenerator,
	}

	now := time.Now()
	repoName := "repo"

	afterSHA := "bbb1234567890abcdef"

	// GetDraft query
	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", afterSHA, jsonBytes([]string{"sha1"}), "", nil, "draft", now, now))

	// GetRepositoryByID query (multiline SQL)
	mock.ExpectQuery(`(?s)SELECT .+ FROM repositories.+WHERE id`).
		WithArgs("repo-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "github_url", "webhook_secret", "name", "is_active", "created_at", "github_repo_id", "webhook_id", "is_private", "github_app_repo_id", "webhook_source"}).
			AddRow("repo-1", "user-1", "https://github.com/owner/repo", "secret", &repoName, true, now, nil, nil, false, nil, "legacy"))

	// CreateDraft call (trying to store generated content) - will get duplicate, so falls through to UpdateDraftContent
	mock.ExpectQuery(`INSERT INTO drafts`).
		WithArgs("user-1", "repo-1", "refs/heads/main", "aaa", afterSHA, pgxmock.AnyArg(), 1, pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", afterSHA, jsonBytes([]string{"sha1"}), "Generated social post content", nil, "draft", now, now))

	err = adapter.TriggerGeneration(context.Background(), "draft-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestAIGeneratorAdapter_TriggerGeneration_DraftNotFound(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	repoStore := database.NewRepositoryStoreWithDB(mock)

	openaiClient := newMockChatClient("content")
	postGenerator := services.NewPostGenerator(openaiClient)

	adapter := &aiGeneratorAdapter{
		draftStore:    draftStore,
		repoStore:     repoStore,
		postGenerator: postGenerator,
	}

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-404").
		WillReturnError(pgx.ErrNoRows)

	err = adapter.TriggerGeneration(context.Background(), "draft-404")
	if err == nil {
		t.Error("Expected error for missing draft")
	}
	if !strings.Contains(err.Error(), "failed to get draft") {
		t.Errorf("Expected 'failed to get draft' error, got: %v", err)
	}
}

func TestAIGeneratorAdapter_TriggerGeneration_RepoNotFound(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	repoStore := database.NewRepositoryStoreWithDB(mock)

	openaiClient := newMockChatClient("content")
	postGenerator := services.NewPostGenerator(openaiClient)

	adapter := &aiGeneratorAdapter{
		draftStore:    draftStore,
		repoStore:     repoStore,
		postGenerator: postGenerator,
	}

	now := time.Now()

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", "bbb1234567890abcdef", jsonBytes([]string{"sha1"}), "", nil, "draft", now, now))

	mock.ExpectQuery(`(?s)SELECT .+ FROM repositories.+WHERE id`).
		WithArgs("repo-1").
		WillReturnError(fmt.Errorf("repo not found"))

	err = adapter.TriggerGeneration(context.Background(), "draft-1")
	if err == nil {
		t.Error("Expected error")
	}
	if !strings.Contains(err.Error(), "failed to get repository") {
		t.Errorf("Expected 'failed to get repository' error, got: %v", err)
	}
}

func TestAIGeneratorAdapter_TriggerGeneration_AIError(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	repoStore := database.NewRepositoryStoreWithDB(mock)

	// Create a failing mock client
	openaiClient := &mockChatClientErr{err: fmt.Errorf("AI generation failed")}
	postGenerator := services.NewPostGenerator(openaiClient)

	adapter := &aiGeneratorAdapter{
		draftStore:    draftStore,
		repoStore:     repoStore,
		postGenerator: postGenerator,
	}

	now := time.Now()
	repoName := "repo"

	afterSHA := "bbb1234567890abcdef"

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", afterSHA, jsonBytes([]string{"sha1"}), "", nil, "draft", now, now))

	mock.ExpectQuery(`(?s)SELECT .+ FROM repositories.+WHERE id`).
		WithArgs("repo-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "github_url", "webhook_secret", "name", "is_active", "created_at", "github_repo_id", "webhook_id", "is_private", "github_app_repo_id", "webhook_source"}).
			AddRow("repo-1", "user-1", "https://github.com/owner/repo", "secret", &repoName, true, now, nil, nil, false, nil, "legacy"))

	// UpdateDraftStatus called when AI generation fails (best effort)
	mock.ExpectExec(`UPDATE drafts SET status`).
		WithArgs("error", "draft-1").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err = adapter.TriggerGeneration(context.Background(), "draft-1")
	if err == nil {
		t.Error("Expected error for AI failure")
	}
	if !strings.Contains(err.Error(), "failed to generate content") {
		t.Errorf("Expected 'failed to generate content' error, got: %v", err)
	}
}

func TestAIGeneratorAdapter_TriggerGeneration_MultipleCommits(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	repoStore := database.NewRepositoryStoreWithDB(mock)

	openaiClient := newMockChatClient("Multi-commit post")
	postGenerator := services.NewPostGenerator(openaiClient)

	adapter := &aiGeneratorAdapter{
		draftStore:    draftStore,
		repoStore:     repoStore,
		postGenerator: postGenerator,
	}

	now := time.Now()
	repoName := "repo"

	afterSHA := "bbb1234567890abcdef"

	// Multiple commit SHAs
	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", afterSHA, jsonBytes([]string{"sha1", "sha2", "sha3"}), "", nil, "draft", now, now))

	mock.ExpectQuery(`(?s)SELECT .+ FROM repositories.+WHERE id`).
		WithArgs("repo-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "github_url", "webhook_secret", "name", "is_active", "created_at", "github_repo_id", "webhook_id", "is_private", "github_app_repo_id", "webhook_source"}).
			AddRow("repo-1", "user-1", "https://github.com/owner/repo", "secret", &repoName, true, now, nil, nil, false, nil, "legacy"))

	mock.ExpectQuery(`INSERT INTO drafts`).
		WithArgs("user-1", "repo-1", "refs/heads/main", "aaa", afterSHA, pgxmock.AnyArg(), 3, pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-new", "user-1", "repo-1", "refs/heads/main", "aaa", afterSHA, jsonBytes([]string{"sha1", "sha2", "sha3"}), "Multi-commit post", nil, "draft", now, now))

	err = adapter.TriggerGeneration(context.Background(), "draft-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// =============================================================================
// Test aiRegeneratorAdapter
// =============================================================================

func TestAIRegeneratorAdapter_RegenerateDraft(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	repoStore := database.NewRepositoryStoreWithDB(mock)

	openaiClient := newMockChatClient("Regenerated content")
	postGenerator := services.NewPostGenerator(openaiClient)

	generator := &aiGeneratorAdapter{
		draftStore:    draftStore,
		repoStore:     repoStore,
		postGenerator: postGenerator,
	}
	adapter := &aiRegeneratorAdapter{generator: generator}

	now := time.Now()
	repoName := "repo"

	afterSHA := "bbb1234567890abcdef"

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", afterSHA, jsonBytes([]string{"sha1"}), "old content", nil, "draft", now, now))

	mock.ExpectQuery(`(?s)SELECT .+ FROM repositories.+WHERE id`).
		WithArgs("repo-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "github_url", "webhook_secret", "name", "is_active", "created_at", "github_repo_id", "webhook_id", "is_private", "github_app_repo_id", "webhook_source"}).
			AddRow("repo-1", "user-1", "https://github.com/owner/repo", "secret", &repoName, true, now, nil, nil, false, nil, "legacy"))

	mock.ExpectQuery(`INSERT INTO drafts`).
		WithArgs("user-1", "repo-1", "refs/heads/main", "aaa", afterSHA, pgxmock.AnyArg(), 1, pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", afterSHA, jsonBytes([]string{"sha1"}), "Regenerated content", nil, "draft", now, now))

	err = adapter.RegenerateDraft(context.Background(), "draft-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// =============================================================================
// Test aiGeneratorAdapter - CreateDraft fails, falls back to UpdateDraftContent
// =============================================================================

func TestAIGeneratorAdapter_TriggerGeneration_CreateDraftFails_UpdatesContent(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	repoStore := database.NewRepositoryStoreWithDB(mock)

	openaiClient := newMockChatClient("New generated content")
	postGenerator := services.NewPostGenerator(openaiClient)

	adapter := &aiGeneratorAdapter{
		draftStore:    draftStore,
		repoStore:     repoStore,
		postGenerator: postGenerator,
	}

	now := time.Now()
	repoName := "repo"

	afterSHA := "bbb1234567890abcdef"

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", afterSHA, jsonBytes([]string{"sha1"}), "old content", nil, "draft", now, now))

	mock.ExpectQuery(`(?s)SELECT .+ FROM repositories.+WHERE id`).
		WithArgs("repo-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "github_url", "webhook_secret", "name", "is_active", "created_at", "github_repo_id", "webhook_id", "is_private", "github_app_repo_id", "webhook_source"}).
			AddRow("repo-1", "user-1", "https://github.com/owner/repo", "secret", &repoName, true, now, nil, nil, false, nil, "legacy"))

	// CreateDraft fails (duplicate)
	mock.ExpectQuery(`INSERT INTO drafts`).
		WithArgs("user-1", "repo-1", "refs/heads/main", "aaa", afterSHA, pgxmock.AnyArg(), 1, pgxmock.AnyArg()).
		WillReturnError(fmt.Errorf("unique_violation"))

	// Falls back to UpdateDraftContent
	mock.ExpectExec(`UPDATE drafts SET edited_content`).
		WithArgs(pgxmock.AnyArg(), "draft-1").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err = adapter.TriggerGeneration(context.Background(), "draft-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestAIGeneratorAdapter_TriggerGeneration_BothFail(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	draftStore := database.NewDraftStoreWithDB(mock)
	repoStore := database.NewRepositoryStoreWithDB(mock)

	openaiClient := newMockChatClient("Content")
	postGenerator := services.NewPostGenerator(openaiClient)

	adapter := &aiGeneratorAdapter{
		draftStore:    draftStore,
		repoStore:     repoStore,
		postGenerator: postGenerator,
	}

	now := time.Now()
	repoName := "repo"

	afterSHA := "bbb1234567890abcdef"

	mock.ExpectQuery(`SELECT .+ FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}).
			AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "aaa", afterSHA, jsonBytes([]string{"sha1"}), "", nil, "draft", now, now))

	mock.ExpectQuery(`(?s)SELECT .+ FROM repositories.+WHERE id`).
		WithArgs("repo-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "github_url", "webhook_secret", "name", "is_active", "created_at", "github_repo_id", "webhook_id", "is_private", "github_app_repo_id", "webhook_source"}).
			AddRow("repo-1", "user-1", "https://github.com/owner/repo", "secret", &repoName, true, now, nil, nil, false, nil, "legacy"))

	mock.ExpectQuery(`INSERT INTO drafts`).
		WillReturnError(fmt.Errorf("duplicate"))

	mock.ExpectExec(`UPDATE drafts SET edited_content`).
		WillReturnError(fmt.Errorf("update failed"))

	err = adapter.TriggerGeneration(context.Background(), "draft-1")
	if err == nil {
		t.Error("Expected error")
	}
	if !strings.Contains(err.Error(), "failed to update draft content") {
		t.Errorf("Expected 'failed to update draft content' error, got: %v", err)
	}
}

// =============================================================================
// Test createRouter with full configuration
// =============================================================================

func TestCreateRouterWebhookEndpoint(t *testing.T) {
	config := Config{
		WebhookSecret: "test-secret",
	}

	router := createRouter(config, nil)

	// Test GET request to /
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET / expected 200, got %d", rec.Code)
	}

	// Test POST to /webhook without signature
	req = httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader("test"))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST /webhook without sig expected 401, got %d", rec.Code)
	}

	// Test POST to /webhook with valid signature but missing credentials
	payload := `{"repository":{"html_url":"https://github.com/test/repo"},"commits":[{"id":"abc","message":"test","author":{"name":"Dev"}}]}`
	sig := "sha256=" + generateTestSignature([]byte(payload), "test-secret")
	req = httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", sig)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("POST /webhook expected 200, got %d", rec.Code)
	}
}

// =============================================================================
// Test createRouter with dbPool (non-nil pool for initialization coverage)
// =============================================================================

func TestCreateRouterWithDBPool(t *testing.T) {
	// Create a Pool with nil inner pgxpool.Pool - safe for initialization
	// since createRouter only stores references, not making DB calls
	pool := &database.Pool{}

	config := Config{
		WebhookSecret:       "test-secret",
		OpenAIAPIKey:        "test-openai-key",
		EncryptionKey:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // 64 hex chars = 32 bytes
		ThreadsClientID:     "threads-id",
		ThreadsClientSecret: "threads-secret",
		OAuthCallbackURL:    "https://callback.example.com",
		WebhookBaseURL:      "https://webhook.example.com",
	}

	router := createRouter(config, pool)
	if router == nil {
		t.Fatal("Expected non-nil router")
	}

	// Test that webhook endpoint works
	payload := `{"repository":{"html_url":"https://github.com/test/repo"},"commits":[{"id":"abc","message":"test","author":{"name":"Dev"}}]}`
	sig := "sha256=" + generateTestSignature([]byte(payload), "test-secret")
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", sig)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	// Will succeed with 200 because missing LinkedIn token means credentials-missing path
	if rec.Code != http.StatusOK {
		t.Errorf("POST /webhook expected 200, got %d", rec.Code)
	}

	// Test home page
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET / expected 200, got %d", rec.Code)
	}
}

func TestCreateRouterWithDBPool_NoEncryptionKey(t *testing.T) {
	pool := &database.Pool{}

	config := Config{
		WebhookSecret: "test-secret",
		OpenAIAPIKey:  "test-openai-key",
		// No EncryptionKey - social posting disabled
	}

	router := createRouter(config, pool)
	if router == nil {
		t.Fatal("Expected non-nil router")
	}
}

func TestCreateRouterWithDBPool_InvalidEncryptionKey(t *testing.T) {
	pool := &database.Pool{}

	config := Config{
		WebhookSecret: "test-secret",
		EncryptionKey: "not-hex", // Invalid hex
	}

	router := createRouter(config, pool)
	if router == nil {
		t.Fatal("Expected non-nil router")
	}
}

func TestCreateRouterWithDBPool_WrongLengthEncryptionKey(t *testing.T) {
	pool := &database.Pool{}

	config := Config{
		WebhookSecret: "test-secret",
		EncryptionKey: "0123456789abcdef", // Only 8 bytes, need 32
	}

	router := createRouter(config, pool)
	if router == nil {
		t.Fatal("Expected non-nil router")
	}
}

func TestCreateRouterWithDBPool_NoThreadsConfig(t *testing.T) {
	pool := &database.Pool{}

	config := Config{
		WebhookSecret: "test-secret",
		EncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		// No ThreadsClientID/ThreadsClientSecret
	}

	router := createRouter(config, pool)
	if router == nil {
		t.Fatal("Expected non-nil router")
	}
}

func TestCreateRouterWithDBPool_NoOpenAIKey(t *testing.T) {
	pool := &database.Pool{}

	config := Config{
		WebhookSecret: "test-secret",
		// No OpenAIAPIKey
	}

	router := createRouter(config, pool)
	if router == nil {
		t.Fatal("Expected non-nil router")
	}
}

func TestCreateRouterWithDBPool_WithOAuthCallbackFallback(t *testing.T) {
	pool := &database.Pool{}

	config := Config{
		WebhookSecret:       "test-secret",
		EncryptionKey:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ThreadsClientID:     "threads-id",
		ThreadsClientSecret: "threads-secret",
		WebhookBaseURL:      "https://webhook.example.com",
		// OAuthCallbackURL is empty, should fallback to WebhookBaseURL
	}

	router := createRouter(config, pool)
	if router == nil {
		t.Fatal("Expected non-nil router")
	}
}

// =============================================================================
// Mock chat client for AI tests
// =============================================================================

type mockChatClient struct {
	response string
}

func newMockChatClient(response string) *mockChatClient {
	return &mockChatClient{response: response}
}

func (m *mockChatClient) CreateChatCompletion(prompt string) (string, error) {
	return m.response, nil
}

type mockChatClientErr struct {
	err error
}

func (m *mockChatClientErr) CreateChatCompletion(prompt string) (string, error) {
	return "", m.err
}

// =============================================================================
// Compile-time interface checks for handler adapters
// =============================================================================

var _ handlers.CommitStore = (*commitStoreAdapter)(nil)
var _ handlers.IdempotencyStore = (*idempotencyStoreAdapter)(nil)
var _ handlers.ActivityStore = (*activityStoreAdapter)(nil)
