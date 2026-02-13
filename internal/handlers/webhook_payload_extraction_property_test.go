package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// =============================================================================
// Property Test: Webhook Payload Extraction
// Property 15: Valid push webhook extracts ref, before_sha, after_sha, commit_shas.
// Validates Requirements 5.4
// =============================================================================

// extractedPayload captures the extracted values from a push webhook
type extractedPayload struct {
	Ref        string
	BeforeSHA  string
	AfterSHA   string
	CommitSHAs []string
}

// mockCapturingDraftCreator captures the extracted payload values for verification
type mockCapturingDraftCreator struct {
	captured *extractedPayload
}

func newMockCapturingDraftCreator() *mockCapturingDraftCreator {
	return &mockCapturingDraftCreator{}
}

func (m *mockCapturingDraftCreator) CreateDraft(ctx context.Context, userID, repoID, ref, beforeSHA, afterSHA string, commitSHAs []string, content string) (string, error) {
	m.captured = &extractedPayload{
		Ref:        ref,
		BeforeSHA:  beforeSHA,
		AfterSHA:   afterSHA,
		CommitSHAs: commitSHAs,
	}
	return "draft-123", nil
}

// createPushPayloadWithFields creates a push webhook payload with specified fields
func createPushPayloadWithFields(ref, before, after string, commits []map[string]interface{}) []byte {
	payload := map[string]interface{}{
		"ref":    ref,
		"before": before,
		"after":  after,
		"repository": map[string]string{
			"html_url":  "https://github.com/test/repo",
			"full_name": "test/repo",
		},
		"commits": commits,
	}
	data, _ := json.Marshal(payload)
	return data
}

// genGitRef generates valid git ref strings
func genGitRef() gopter.Gen {
	return gen.AlphaString().Map(func(s string) string {
		if s == "" {
			s = "main"
		}
		// Alternate between branch and tag refs
		if len(s) > 0 && s[0] >= 'm' {
			return "refs/tags/" + s
		}
		return "refs/heads/" + s
	})
}

// genSHA generates valid 40-character git SHAs
func genSHA() gopter.Gen {
	return gen.RegexMatch(`[0-9a-f]{40}`)
}

// genCommit generates a commit object for the webhook payload
func genCommit(sha string) map[string]interface{} {
	return map[string]interface{}{
		"id":        sha,
		"message":   "Test commit message",
		"url":       "https://github.com/test/repo/commit/" + sha,
		"timestamp": "2026-01-15T10:30:00Z",
		"author": map[string]string{
			"name":  "Test Author",
			"email": "test@example.com",
		},
	}
}

// TestProperty_PushWebhookExtractsRef verifies that ref is correctly extracted from push webhooks
func TestProperty_PushWebhookExtractsRef(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 50

	properties := gopter.NewProperties(parameters)

	properties.Property("Push webhook correctly extracts ref", prop.ForAll(
		func(ref string, beforeSHA string, afterSHA string, repoID string, secret string) bool {
			// Skip invalid inputs
			if ref == "" || beforeSHA == "" || afterSHA == "" || repoID == "" || secret == "" {
				return true
			}

			// Ensure ref has proper format
			if !strings.HasPrefix(ref, "refs/") {
				ref = "refs/heads/" + ref
			}

			// Create commit for the payload
			commits := []map[string]interface{}{
				genCommit(afterSHA[:40]),
			}

			payload := createPushPayloadWithFields(ref, beforeSHA, afterSHA, commits)
			validSig := computeValidSignature(payload, secret)

			// Set up mock stores
			mockRepoStore := &mockRepoStore{
				repo: &Repository{
					ID:            repoID,
					UserID:        "user-123",
					WebhookSecret: secret,
				},
			}
			mockCommitStore := &mockCommitStore{}
			draftCreator := newMockCapturingDraftCreator()

			req := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+repoID, bytes.NewReader(payload))
			req.Header.Set("X-Hub-Signature-256", validSig)
			req.Header.Set("X-GitHub-Event", "push")
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler := NewMultiTenantWebhookHandler(mockRepoStore, mockCommitStore).
				WithDraftCreator(draftCreator)
			handler.ServeHTTP(rr, req)

			// Request should succeed
			if rr.Code != http.StatusOK {
				t.Logf("Request failed with status %d", rr.Code)
				return false
			}

			// Verify ref was correctly extracted
			if draftCreator.captured == nil {
				t.Log("No draft created")
				return false
			}

			if draftCreator.captured.Ref != ref {
				t.Logf("Ref mismatch: expected %q, got %q", ref, draftCreator.captured.Ref)
				return false
			}

			return true
		},
		genGitRef(),
		genSHA(),
		genSHA(),
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) >= 3 }),
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) >= 8 }),
	))

	properties.TestingRun(t)
}

// TestProperty_PushWebhookExtractsBeforeSHA verifies that before_sha is correctly extracted
func TestProperty_PushWebhookExtractsBeforeSHA(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 50

	properties := gopter.NewProperties(parameters)

	properties.Property("Push webhook correctly extracts before_sha", prop.ForAll(
		func(beforeSHA string, afterSHA string, repoID string, secret string) bool {
			// Skip invalid inputs
			if beforeSHA == "" || afterSHA == "" || repoID == "" || secret == "" {
				return true
			}

			ref := "refs/heads/main"
			commits := []map[string]interface{}{
				genCommit(afterSHA[:40]),
			}

			payload := createPushPayloadWithFields(ref, beforeSHA, afterSHA, commits)
			validSig := computeValidSignature(payload, secret)

			mockRepoStore := &mockRepoStore{
				repo: &Repository{
					ID:            repoID,
					UserID:        "user-123",
					WebhookSecret: secret,
				},
			}
			mockCommitStore := &mockCommitStore{}
			draftCreator := newMockCapturingDraftCreator()

			req := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+repoID, bytes.NewReader(payload))
			req.Header.Set("X-Hub-Signature-256", validSig)
			req.Header.Set("X-GitHub-Event", "push")
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler := NewMultiTenantWebhookHandler(mockRepoStore, mockCommitStore).
				WithDraftCreator(draftCreator)
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Logf("Request failed with status %d", rr.Code)
				return false
			}

			if draftCreator.captured == nil {
				t.Log("No draft created")
				return false
			}

			if draftCreator.captured.BeforeSHA != beforeSHA {
				t.Logf("BeforeSHA mismatch: expected %q, got %q", beforeSHA, draftCreator.captured.BeforeSHA)
				return false
			}

			return true
		},
		genSHA(),
		genSHA(),
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) >= 3 }),
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) >= 8 }),
	))

	properties.TestingRun(t)
}

// TestProperty_PushWebhookExtractsAfterSHA verifies that after_sha is correctly extracted
func TestProperty_PushWebhookExtractsAfterSHA(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 50

	properties := gopter.NewProperties(parameters)

	properties.Property("Push webhook correctly extracts after_sha", prop.ForAll(
		func(beforeSHA string, afterSHA string, repoID string, secret string) bool {
			// Skip invalid inputs
			if beforeSHA == "" || afterSHA == "" || repoID == "" || secret == "" {
				return true
			}

			ref := "refs/heads/main"
			commits := []map[string]interface{}{
				genCommit(afterSHA[:40]),
			}

			payload := createPushPayloadWithFields(ref, beforeSHA, afterSHA, commits)
			validSig := computeValidSignature(payload, secret)

			mockRepoStore := &mockRepoStore{
				repo: &Repository{
					ID:            repoID,
					UserID:        "user-123",
					WebhookSecret: secret,
				},
			}
			mockCommitStore := &mockCommitStore{}
			draftCreator := newMockCapturingDraftCreator()

			req := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+repoID, bytes.NewReader(payload))
			req.Header.Set("X-Hub-Signature-256", validSig)
			req.Header.Set("X-GitHub-Event", "push")
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler := NewMultiTenantWebhookHandler(mockRepoStore, mockCommitStore).
				WithDraftCreator(draftCreator)
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Logf("Request failed with status %d", rr.Code)
				return false
			}

			if draftCreator.captured == nil {
				t.Log("No draft created")
				return false
			}

			if draftCreator.captured.AfterSHA != afterSHA {
				t.Logf("AfterSHA mismatch: expected %q, got %q", afterSHA, draftCreator.captured.AfterSHA)
				return false
			}

			return true
		},
		genSHA(),
		genSHA(),
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) >= 3 }),
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) >= 8 }),
	))

	properties.TestingRun(t)
}

// TestProperty_PushWebhookExtractsCommitSHAs verifies that commit_shas are correctly extracted
func TestProperty_PushWebhookExtractsCommitSHAs(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 20

	properties := gopter.NewProperties(parameters)

	properties.Property("Push webhook correctly extracts commit_shas", prop.ForAll(
		func(numCommits int, repoIDSuffix int, secretSuffix int) bool {
			// Use deterministic values derived from int inputs
			repoID := "repo" + strings.Repeat("x", repoIDSuffix%10+3)
			secret := "secret" + strings.Repeat("y", secretSuffix%10+8)

			if numCommits < 1 {
				numCommits = 1
			}
			if numCommits > 5 {
				numCommits = 5
			}

			// Generate unique commit SHAs
			validSHAs := make([]string, numCommits)
			for i := 0; i < numCommits; i++ {
				// Create distinguishable 40-char SHAs
				validSHAs[i] = strings.Repeat(string(rune('a'+i%26)), 39) + string(rune('0'+i%10))
			}

			ref := "refs/heads/main"
			beforeSHA := "0000000000000000000000000000000000000000"
			afterSHA := validSHAs[len(validSHAs)-1] // Last commit is the after SHA

			// Create commits from SHAs
			commits := make([]map[string]interface{}, len(validSHAs))
			for i, sha := range validSHAs {
				commits[i] = genCommit(sha)
			}

			payload := createPushPayloadWithFields(ref, beforeSHA, afterSHA, commits)
			validSig := computeValidSignature(payload, secret)

			mockRepoStore := &mockRepoStore{
				repo: &Repository{
					ID:            repoID,
					UserID:        "user-123",
					WebhookSecret: secret,
				},
			}
			mockCommitStore := &mockCommitStore{}
			draftCreator := newMockCapturingDraftCreator()

			req := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+repoID, bytes.NewReader(payload))
			req.Header.Set("X-Hub-Signature-256", validSig)
			req.Header.Set("X-GitHub-Event", "push")
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler := NewMultiTenantWebhookHandler(mockRepoStore, mockCommitStore).
				WithDraftCreator(draftCreator)
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Logf("Request failed with status %d", rr.Code)
				return false
			}

			if draftCreator.captured == nil {
				t.Log("No draft created")
				return false
			}

			// Verify all commit SHAs were extracted in order
			if len(draftCreator.captured.CommitSHAs) != len(validSHAs) {
				t.Logf("CommitSHAs count mismatch: expected %d, got %d",
					len(validSHAs), len(draftCreator.captured.CommitSHAs))
				return false
			}

			for i, sha := range validSHAs {
				if draftCreator.captured.CommitSHAs[i] != sha {
					t.Logf("CommitSHA[%d] mismatch: expected %q, got %q",
						i, sha, draftCreator.captured.CommitSHAs[i])
					return false
				}
			}

			return true
		},
		gen.IntRange(1, 5), // Generate 1-5 commits
		gen.IntRange(0, 100),
		gen.IntRange(0, 100),
	))

	properties.TestingRun(t)
}

// TestProperty_PushWebhookExtractsAllFieldsTogether verifies all fields are extracted together
func TestProperty_PushWebhookExtractsAllFieldsTogether(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 30

	properties := gopter.NewProperties(parameters)

	properties.Property("Push webhook extracts ref, before_sha, after_sha, and commit_shas together", prop.ForAll(
		func(ref string, beforeSHA string, afterSHA string, numCommits int, repoID string, secret string) bool {
			// Skip invalid inputs
			if ref == "" || beforeSHA == "" || afterSHA == "" || repoID == "" || secret == "" {
				return true
			}
			if numCommits < 1 {
				numCommits = 1
			}
			if numCommits > 10 {
				numCommits = 10
			}

			// Ensure ref has proper format
			if !strings.HasPrefix(ref, "refs/") {
				ref = "refs/heads/" + ref
			}

			// Generate commit SHAs - the after SHA should be one of them
			commitSHAs := make([]string, numCommits)
			for i := 0; i < numCommits-1; i++ {
				// Generate deterministic SHAs for intermediate commits
				commitSHAs[i] = strings.Repeat(string(rune('a'+i%6)), 40)
			}
			commitSHAs[numCommits-1] = afterSHA // Last commit is the after SHA

			// Create commits from SHAs
			commits := make([]map[string]interface{}, numCommits)
			for i, sha := range commitSHAs {
				commits[i] = genCommit(sha)
			}

			payload := createPushPayloadWithFields(ref, beforeSHA, afterSHA, commits)
			validSig := computeValidSignature(payload, secret)

			mockRepoStore := &mockRepoStore{
				repo: &Repository{
					ID:            repoID,
					UserID:        "user-123",
					WebhookSecret: secret,
				},
			}
			mockCommitStore := &mockCommitStore{}
			draftCreator := newMockCapturingDraftCreator()

			req := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+repoID, bytes.NewReader(payload))
			req.Header.Set("X-Hub-Signature-256", validSig)
			req.Header.Set("X-GitHub-Event", "push")
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler := NewMultiTenantWebhookHandler(mockRepoStore, mockCommitStore).
				WithDraftCreator(draftCreator)
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Logf("Request failed with status %d, body: %s", rr.Code, rr.Body.String())
				return false
			}

			if draftCreator.captured == nil {
				t.Log("No draft created")
				return false
			}

			// Verify ALL fields were correctly extracted
			captured := draftCreator.captured

			if captured.Ref != ref {
				t.Logf("Ref mismatch: expected %q, got %q", ref, captured.Ref)
				return false
			}

			if captured.BeforeSHA != beforeSHA {
				t.Logf("BeforeSHA mismatch: expected %q, got %q", beforeSHA, captured.BeforeSHA)
				return false
			}

			if captured.AfterSHA != afterSHA {
				t.Logf("AfterSHA mismatch: expected %q, got %q", afterSHA, captured.AfterSHA)
				return false
			}

			if len(captured.CommitSHAs) != len(commitSHAs) {
				t.Logf("CommitSHAs count mismatch: expected %d, got %d",
					len(commitSHAs), len(captured.CommitSHAs))
				return false
			}

			for i, sha := range commitSHAs {
				if captured.CommitSHAs[i] != sha {
					t.Logf("CommitSHA[%d] mismatch: expected %q, got %q",
						i, sha, captured.CommitSHAs[i])
					return false
				}
			}

			return true
		},
		genGitRef(),
		genSHA(),
		genSHA(),
		gen.IntRange(1, 10), // 1-10 commits
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) >= 3 }),
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) >= 8 }),
	))

	properties.TestingRun(t)
}

// TestProperty_PushWebhookPreservesCommitOrder verifies commit order is preserved
func TestProperty_PushWebhookPreservesCommitOrder(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 20

	properties := gopter.NewProperties(parameters)

	properties.Property("Push webhook preserves commit order in extraction", prop.ForAll(
		func(numCommits int, repoIDSuffix int, secretSuffix int) bool {
			// Use deterministic values derived from int inputs
			repoID := "repo" + strings.Repeat("x", repoIDSuffix%10+3)
			secret := "secret" + strings.Repeat("y", secretSuffix%10+8)

			if numCommits < 2 {
				numCommits = 2
			}
			if numCommits > 10 {
				numCommits = 10
			}

			ref := "refs/heads/main"
			beforeSHA := "0000000000000000000000000000000000000000"

			// Generate unique ordered commit SHAs
			commitSHAs := make([]string, numCommits)
			for i := 0; i < numCommits; i++ {
				// Use index to create distinguishable SHAs
				commitSHAs[i] = strings.Repeat(string(rune('a'+i%26)), 39) + string(rune('0'+i%10))
			}
			afterSHA := commitSHAs[numCommits-1]

			commits := make([]map[string]interface{}, numCommits)
			for i, sha := range commitSHAs {
				commits[i] = genCommit(sha)
			}

			payload := createPushPayloadWithFields(ref, beforeSHA, afterSHA, commits)
			validSig := computeValidSignature(payload, secret)

			mockRepoStore := &mockRepoStore{
				repo: &Repository{
					ID:            repoID,
					UserID:        "user-123",
					WebhookSecret: secret,
				},
			}
			mockCommitStore := &mockCommitStore{}
			draftCreator := newMockCapturingDraftCreator()

			req := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+repoID, bytes.NewReader(payload))
			req.Header.Set("X-Hub-Signature-256", validSig)
			req.Header.Set("X-GitHub-Event", "push")
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler := NewMultiTenantWebhookHandler(mockRepoStore, mockCommitStore).
				WithDraftCreator(draftCreator)
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				return false
			}

			if draftCreator.captured == nil {
				return false
			}

			// Verify order is preserved
			for i, sha := range commitSHAs {
				if i >= len(draftCreator.captured.CommitSHAs) {
					t.Logf("Missing commit at index %d", i)
					return false
				}
				if draftCreator.captured.CommitSHAs[i] != sha {
					t.Logf("Order mismatch at index %d: expected %q, got %q",
						i, sha, draftCreator.captured.CommitSHAs[i])
					return false
				}
			}

			return true
		},
		gen.IntRange(2, 10),
		gen.IntRange(0, 100),
		gen.IntRange(0, 100),
	))

	properties.TestingRun(t)
}

// TestProperty_PushWebhookHandlesEmptyCommitsGracefully verifies empty commit arrays are handled
func TestProperty_PushWebhookHandlesEmptyCommitsGracefully(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	parameters.MaxSize = 20

	properties := gopter.NewProperties(parameters)

	properties.Property("Push webhook handles empty commits array gracefully", prop.ForAll(
		func(repoIDSuffix int, secretSuffix int) bool {
			// Use deterministic values to avoid discards
			ref := "refs/heads/main"
			beforeSHA := "0000000000000000000000000000000000000000"
			afterSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			repoID := "repo" + strings.Repeat("x", repoIDSuffix%10+3)
			secret := "secret" + strings.Repeat("y", secretSuffix%10+8)

			// Empty commits array
			commits := []map[string]interface{}{}

			payload := createPushPayloadWithFields(ref, beforeSHA, afterSHA, commits)
			validSig := computeValidSignature(payload, secret)

			mockRepoStore := &mockRepoStore{
				repo: &Repository{
					ID:            repoID,
					UserID:        "user-123",
					WebhookSecret: secret,
				},
			}
			mockCommitStore := &mockCommitStore{}
			draftCreator := newMockCapturingDraftCreator()

			req := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+repoID, bytes.NewReader(payload))
			req.Header.Set("X-Hub-Signature-256", validSig)
			req.Header.Set("X-GitHub-Event", "push")
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler := NewMultiTenantWebhookHandler(mockRepoStore, mockCommitStore).
				WithDraftCreator(draftCreator)
			handler.ServeHTTP(rr, req)

			// Should still succeed (200 OK)
			if rr.Code != http.StatusOK {
				return false
			}

			// Draft should NOT be created when there are no commits
			// (based on the condition in handlePushEvent: len(payload.Commits) > 0)
			if draftCreator.captured != nil {
				t.Log("Draft should not be created for empty commits array")
				return false
			}

			return true
		},
		gen.IntRange(0, 100),
		gen.IntRange(0, 100),
	))

	properties.TestingRun(t)
}
