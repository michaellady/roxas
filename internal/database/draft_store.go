package database

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Draft status constants
const (
	DraftStatusDraft   = "draft"
	DraftStatusPosted  = "posted"
	DraftStatusPartial = "partial"
	DraftStatusFailed  = "failed"
	DraftStatusError   = "error"
)

// Valid draft statuses (must match DB check constraint)
var validDraftStatuses = map[string]bool{
	DraftStatusDraft:   true,
	DraftStatusPosted:  true,
	DraftStatusPartial: true,
	DraftStatusFailed:  true,
	DraftStatusError:   true,
}

// Draft-related errors
var (
	ErrDraftNotFound       = errors.New("draft not found")
	ErrInvalidDraftStatus  = errors.New("invalid draft status")
	ErrDuplicateDraft      = errors.New("draft already exists for this push")
	ErrInvalidDraftInput   = errors.New("invalid draft input")
)

// Draft represents a draft social media post generated from a push event
type Draft struct {
	ID               string
	UserID           string
	RepositoryID     string
	Ref              string
	BeforeSHA        string
	AfterSHA         string
	CommitSHAs       []string
	GeneratedContent string
	EditedContent    *string
	Status           string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// DraftStore handles draft persistence using PostgreSQL
type DraftStore struct {
	pool *Pool
}

// NewDraftStore creates a new draft store
func NewDraftStore(pool *Pool) *DraftStore {
	return &DraftStore{pool: pool}
}

// CreateDraft creates a new draft in the database
func (s *DraftStore) CreateDraft(ctx context.Context, userID, repoID, ref, beforeSHA, afterSHA string, commitSHAs []string, content string) (*Draft, error) {
	// Validate required inputs
	if userID == "" {
		return nil, errors.New("user_id is required")
	}
	if repoID == "" {
		return nil, errors.New("repository_id is required")
	}
	if afterSHA == "" {
		return nil, errors.New("after_sha is required")
	}
	if ref == "" {
		return nil, errors.New("ref is required")
	}

	// Convert commitSHAs to JSON
	commitSHAsJSON, err := json.Marshal(commitSHAs)
	if err != nil {
		return nil, err
	}

	commitCount := len(commitSHAs)
	if commitCount == 0 {
		commitCount = 1
	}

	var draft Draft
	var createdAt, updatedAt time.Time
	var commitSHAsJSONResult []byte

	err = s.pool.QueryRow(ctx,
		`INSERT INTO drafts (user_id, repository_id, ref, before_sha, after_sha, commit_shas, commit_count, generated_content)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id, user_id, repository_id, ref, before_sha, after_sha, commit_shas, generated_content, edited_content, status, created_at, updated_at`,
		userID, repoID, ref, beforeSHA, afterSHA, commitSHAsJSON, commitCount, content,
	).Scan(&draft.ID, &draft.UserID, &draft.RepositoryID, &draft.Ref, &draft.BeforeSHA, &draft.AfterSHA,
		&commitSHAsJSONResult, &draft.GeneratedContent, &draft.EditedContent, &draft.Status, &createdAt, &updatedAt)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23505": // unique_violation
				return nil, ErrDuplicateDraft
			case "23503": // foreign_key_violation
				return nil, errors.New("foreign key violation: invalid user_id or repository_id")
			}
		}
		return nil, err
	}

	// Unmarshal the JSON array back to []string
	if err := json.Unmarshal(commitSHAsJSONResult, &draft.CommitSHAs); err != nil {
		return nil, err
	}

	draft.CreatedAt = createdAt
	draft.UpdatedAt = updatedAt

	return &draft, nil
}

// GetDraft retrieves a draft by ID
func (s *DraftStore) GetDraft(ctx context.Context, draftID string) (*Draft, error) {
	var draft Draft
	var createdAt, updatedAt time.Time
	var commitSHAsJSON []byte

	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, repository_id, ref, before_sha, after_sha, commit_shas,
		        generated_content, edited_content, status, created_at, updated_at
		 FROM drafts
		 WHERE id = $1`,
		draftID,
	).Scan(&draft.ID, &draft.UserID, &draft.RepositoryID, &draft.Ref, &draft.BeforeSHA, &draft.AfterSHA,
		&commitSHAsJSON, &draft.GeneratedContent, &draft.EditedContent, &draft.Status, &createdAt, &updatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDraftNotFound
		}
		return nil, err
	}

	if err := json.Unmarshal(commitSHAsJSON, &draft.CommitSHAs); err != nil {
		return nil, err
	}

	draft.CreatedAt = createdAt
	draft.UpdatedAt = updatedAt

	return &draft, nil
}

// ListDraftsByUser retrieves all drafts for a user, ordered by creation time descending
func (s *DraftStore) ListDraftsByUser(ctx context.Context, userID string) ([]*Draft, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, repository_id, ref, before_sha, after_sha, commit_shas,
		        generated_content, edited_content, status, created_at, updated_at
		 FROM drafts
		 WHERE user_id = $1
		 ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var drafts []*Draft
	for rows.Next() {
		var draft Draft
		var createdAt, updatedAt time.Time
		var commitSHAsJSON []byte

		if err := rows.Scan(&draft.ID, &draft.UserID, &draft.RepositoryID, &draft.Ref, &draft.BeforeSHA,
			&draft.AfterSHA, &commitSHAsJSON, &draft.GeneratedContent, &draft.EditedContent,
			&draft.Status, &createdAt, &updatedAt); err != nil {
			return nil, err
		}

		if err := json.Unmarshal(commitSHAsJSON, &draft.CommitSHAs); err != nil {
			return nil, err
		}

		draft.CreatedAt = createdAt
		draft.UpdatedAt = updatedAt
		drafts = append(drafts, &draft)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return drafts, nil
}

// UpdateDraftContent updates the edited content of a draft
func (s *DraftStore) UpdateDraftContent(ctx context.Context, draftID, content string) error {
	result, err := s.pool.Exec(ctx,
		`UPDATE drafts SET edited_content = $1, updated_at = NOW() WHERE id = $2`,
		content, draftID,
	)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return ErrDraftNotFound
	}

	return nil
}

// UpdateDraftStatus updates the status of a draft
func (s *DraftStore) UpdateDraftStatus(ctx context.Context, draftID, status string) error {
	// Validate status before hitting DB
	if !validDraftStatuses[status] {
		return ErrInvalidDraftStatus
	}

	result, err := s.pool.Exec(ctx,
		`UPDATE drafts SET status = $1, updated_at = NOW() WHERE id = $2`,
		status, draftID,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23514" {
			return ErrInvalidDraftStatus
		}
		return err
	}

	if result.RowsAffected() == 0 {
		return ErrDraftNotFound
	}

	return nil
}

// DeleteDraft deletes a draft by ID
func (s *DraftStore) DeleteDraft(ctx context.Context, draftID string) error {
	result, err := s.pool.Exec(ctx,
		`DELETE FROM drafts WHERE id = $1`,
		draftID,
	)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return ErrDraftNotFound
	}

	return nil
}
