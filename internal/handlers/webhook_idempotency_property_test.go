package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// =============================================================================
// Property Test: Webhook Idempotency
// Property 16: Duplicate delivery IDs return success without creating new drafts.
// Validates Requirements 5.5, 5.6
//
// This property test verifies that:
// - For ANY number of duplicate webhook deliveries with the same delivery ID,
//   exactly ONE draft is created (idempotency invariant)
// - ALL duplicate deliveries return HTTP 200 OK (success response invariant)
// - The total draft count equals the number of UNIQUE delivery IDs, not total deliveries
// =============================================================================

// TestProperty_DuplicateDeliveryIDsCreateSingleDraft verifies that duplicate
// webhook deliveries with the same X-GitHub-Delivery header create exactly one draft.
// Property: For any N deliveries with the same delivery_id, exactly 1 draft is created.
func TestProperty_DuplicateDeliveryIDsCreateSingleDraft(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 20

	properties := gopter.NewProperties(parameters)

	properties.Property("N duplicate deliveries create exactly 1 draft", prop.ForAll(
		func(numDuplicates int, deliveryIDSuffix string, secretSuffix string) bool {
			// Construct valid IDs with guaranteed minimum length
			deliveryID := "delivery-" + deliveryIDSuffix
			secret := "webhooksecret-" + secretSuffix

			repoStore := NewMockWebhookRepositoryStore()
			draftStore := NewMockDraftWebhookStore()
			idempotencyStore := NewMockIdempotencyStore()

			repo := &Repository{
				ID:            "repo-property-test",
				UserID:        "user-property-test",
				GitHubURL:     "https://github.com/test/property-repo",
				WebhookSecret: secret,
			}
			repoStore.AddRepository(repo)

			handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempotencyStore)

			// Create payload with unique before/after SHAs for each test
			commits := []map[string]interface{}{
				{
					"id":      "commit-" + deliveryID,
					"message": "test commit",
					"author":  map[string]interface{}{"name": "Test"},
				},
			}
			beforeSHA := "before-" + deliveryID
			afterSHA := "after-" + deliveryID
			payload := createPushPayloadWithSHAs(beforeSHA, afterSHA, commits)
			signature := generateGitHubSignature(payload, secret)

			// Send N duplicate webhook deliveries with the SAME delivery ID
			allSucceeded := true
			for i := 0; i < numDuplicates; i++ {
				req := createDraftWebhookRequest(t, repo.ID, payload, signature, deliveryID)
				req.Header.Set("X-GitHub-Event", "push")

				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)

				// Every request should return 200 OK (idempotent success)
				if rr.Code != http.StatusOK {
					t.Logf("Request %d/%d failed with status %d", i+1, numDuplicates, rr.Code)
					allSucceeded = false
				}
			}

			if !allSucceeded {
				return false
			}

			// Verify exactly ONE draft was created (idempotency invariant)
			drafts := draftStore.GetDrafts()
			if len(drafts) != 1 {
				t.Logf("Expected 1 draft after %d duplicate deliveries, got %d", numDuplicates, len(drafts))
				return false
			}

			// Verify the delivery ID was marked as processed
			if !idempotencyStore.IsProcessed(deliveryID) {
				t.Logf("Delivery ID %s should be marked as processed", deliveryID)
				return false
			}

			return true
		},
		gen.IntRange(2, 20), // numDuplicates (2-20)
		gen.AlphaString(),   // deliveryIDSuffix
		gen.AlphaString(),   // secretSuffix
	))

	properties.TestingRun(t)
}

// TestProperty_DifferentDeliveryIDsCreateSeparateDrafts verifies that different
// delivery IDs create separate drafts (no false idempotency).
// Property: For any N unique delivery_ids, exactly N drafts are created.
func TestProperty_DifferentDeliveryIDsCreateSeparateDrafts(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 15

	properties := gopter.NewProperties(parameters)

	properties.Property("N unique delivery IDs create exactly N drafts", prop.ForAll(
		func(numDeliveries int, secretSuffix string) bool {
			secret := "webhooksecret-" + secretSuffix

			repoStore := NewMockWebhookRepositoryStore()
			draftStore := NewMockDraftWebhookStore()
			idempotencyStore := NewMockIdempotencyStore()

			repo := &Repository{
				ID:            "repo-unique-test",
				UserID:        "user-unique-test",
				GitHubURL:     "https://github.com/test/unique-repo",
				WebhookSecret: secret,
			}
			repoStore.AddRepository(repo)

			handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempotencyStore)

			// Send N webhook deliveries with DIFFERENT delivery IDs
			for i := 0; i < numDeliveries; i++ {
				deliveryID := generateTestDeliveryID(i)
				beforeSHA := generateTestSHA("before", i)
				afterSHA := generateTestSHA("after", i)

				commits := []map[string]interface{}{
					{
						"id":      generateTestSHA("commit", i),
						"message": "test commit",
						"author":  map[string]interface{}{"name": "Test"},
					},
				}
				payload := createPushPayloadWithSHAs(beforeSHA, afterSHA, commits)
				signature := generateGitHubSignature(payload, secret)

				req := createDraftWebhookRequest(t, repo.ID, payload, signature, deliveryID)
				req.Header.Set("X-GitHub-Event", "push")

				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)

				if rr.Code != http.StatusOK {
					t.Logf("Request %d failed with status %d", i, rr.Code)
					return false
				}
			}

			// Verify exactly N drafts were created (one per unique delivery ID)
			drafts := draftStore.GetDrafts()
			if len(drafts) != numDeliveries {
				t.Logf("Expected %d drafts for %d unique delivery IDs, got %d", numDeliveries, numDeliveries, len(drafts))
				return false
			}

			return true
		},
		gen.IntRange(1, 15), // numDeliveries (1-15)
		gen.AlphaString(),   // secretSuffix
	))

	properties.TestingRun(t)
}

// TestProperty_MixedDuplicatesAndUniqueDeliveryIDs verifies that a mix of duplicate
// and unique delivery IDs creates the correct number of drafts.
// Property: For a mix of deliveries, draft count = number of unique delivery IDs.
func TestProperty_MixedDuplicatesAndUniqueDeliveryIDs(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 10

	properties := gopter.NewProperties(parameters)

	properties.Property("Mixed duplicates and unique IDs: draft count = unique ID count", prop.ForAll(
		func(numUniqueIDs int, duplicatesPerID int, secretSuffix string) bool {
			secret := "webhooksecret-" + secretSuffix

			repoStore := NewMockWebhookRepositoryStore()
			draftStore := NewMockDraftWebhookStore()
			idempotencyStore := NewMockIdempotencyStore()

			repo := &Repository{
				ID:            "repo-mixed-test",
				UserID:        "user-mixed-test",
				GitHubURL:     "https://github.com/test/mixed-repo",
				WebhookSecret: secret,
			}
			repoStore.AddRepository(repo)

			handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempotencyStore)

			totalRequests := 0

			// For each unique delivery ID, send it multiple times (duplicates)
			for i := 0; i < numUniqueIDs; i++ {
				deliveryID := generateTestDeliveryID(i)
				beforeSHA := generateTestSHA("before", i)
				afterSHA := generateTestSHA("after", i)

				commits := []map[string]interface{}{
					{
						"id":      generateTestSHA("commit", i),
						"message": "test commit " + deliveryID,
						"author":  map[string]interface{}{"name": "Test"},
					},
				}
				payload := createPushPayloadWithSHAs(beforeSHA, afterSHA, commits)
				signature := generateGitHubSignature(payload, secret)

				// Send this delivery ID multiple times
				for j := 0; j < duplicatesPerID; j++ {
					req := createDraftWebhookRequest(t, repo.ID, payload, signature, deliveryID)
					req.Header.Set("X-GitHub-Event", "push")

					rr := httptest.NewRecorder()
					handler.ServeHTTP(rr, req)

					if rr.Code != http.StatusOK {
						t.Logf("Request failed with status %d", rr.Code)
						return false
					}
					totalRequests++
				}
			}

			// Verify draft count equals number of unique delivery IDs
			// (not total requests, which = numUniqueIDs * duplicatesPerID)
			drafts := draftStore.GetDrafts()
			if len(drafts) != numUniqueIDs {
				t.Logf("Expected %d drafts (unique IDs) after %d total requests, got %d",
					numUniqueIDs, totalRequests, len(drafts))
				return false
			}

			return true
		},
		gen.IntRange(1, 10), // numUniqueIDs (1-10)
		gen.IntRange(2, 5),  // duplicatesPerID (2-5)
		gen.AlphaString(),   // secretSuffix
	))

	properties.TestingRun(t)
}

// TestProperty_DuplicateDeliveryReturnsSuccessResponse verifies that duplicate
// deliveries return 200 OK with a "duplicate delivery" message.
// Property: All duplicate deliveries return status 200 and indicate duplication.
func TestProperty_DuplicateDeliveryReturnsSuccessResponse(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 10

	properties := gopter.NewProperties(parameters)

	properties.Property("Duplicate deliveries return 200 OK with duplicate message", prop.ForAll(
		func(numDuplicates int, deliveryIDSuffix string, secretSuffix string) bool {
			deliveryID := "delivery-" + deliveryIDSuffix
			secret := "webhooksecret-" + secretSuffix

			repoStore := NewMockWebhookRepositoryStore()
			draftStore := NewMockDraftWebhookStore()
			idempotencyStore := NewMockIdempotencyStore()

			repo := &Repository{
				ID:            "repo-response-test",
				UserID:        "user-response-test",
				GitHubURL:     "https://github.com/test/response-repo",
				WebhookSecret: secret,
			}
			repoStore.AddRepository(repo)

			handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempotencyStore)

			commits := []map[string]interface{}{
				{
					"id":      "commit-" + deliveryID,
					"message": "test",
					"author":  map[string]interface{}{"name": "Test"},
				},
			}
			payload := createPushPayloadWithSHAs("before-"+deliveryID, "after-"+deliveryID, commits)
			signature := generateGitHubSignature(payload, secret)

			// Send first request - should create draft
			req1 := createDraftWebhookRequest(t, repo.ID, payload, signature, deliveryID)
			req1.Header.Set("X-GitHub-Event", "push")
			rr1 := httptest.NewRecorder()
			handler.ServeHTTP(rr1, req1)

			if rr1.Code != http.StatusOK {
				t.Logf("First request should return 200, got %d", rr1.Code)
				return false
			}

			// First response should indicate "draft created"
			body1 := rr1.Body.String()
			if !bytes.Contains([]byte(body1), []byte("draft created")) {
				t.Logf("First response should indicate draft created: %s", body1)
				return false
			}

			// Send remaining duplicate requests
			for i := 1; i < numDuplicates; i++ {
				req := createDraftWebhookRequest(t, repo.ID, payload, signature, deliveryID)
				req.Header.Set("X-GitHub-Event", "push")
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)

				// Duplicates should return 200 OK
				if rr.Code != http.StatusOK {
					t.Logf("Duplicate request %d should return 200, got %d", i+1, rr.Code)
					return false
				}

				// Response should indicate "duplicate delivery"
				body := rr.Body.String()
				if !bytes.Contains([]byte(body), []byte("duplicate delivery")) {
					t.Logf("Duplicate response should indicate duplicate: %s", body)
					return false
				}
			}

			return true
		},
		gen.IntRange(2, 10), // numDuplicates (2-10)
		gen.AlphaString(),   // deliveryIDSuffix
		gen.AlphaString(),   // secretSuffix
	))

	properties.TestingRun(t)
}

// TestProperty_DualIdempotencyWithDifferentDeliveryIDsSamePush verifies that
// the dual idempotency mechanism (delivery_id + push signature) works correctly.
// Property: Same push (same before/after SHA) with different delivery IDs creates 1 draft.
func TestProperty_DualIdempotencyWithDifferentDeliveryIDsSamePush(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 10

	properties := gopter.NewProperties(parameters)

	properties.Property("Same push with different delivery IDs creates 1 draft (dual idempotency)", prop.ForAll(
		func(numRetries int, beforeSHASuffix string, afterSHASuffix string, secretSuffix string) bool {
			beforeSHA := "before-sha-" + beforeSHASuffix
			afterSHA := "after-sha-" + afterSHASuffix
			secret := "webhooksecret-" + secretSuffix

			repoStore := NewMockWebhookRepositoryStore()
			draftStore := NewMockDraftWebhookStore()
			idempotencyStore := NewMockIdempotencyStore()

			repo := &Repository{
				ID:            "repo-dual-test",
				UserID:        "user-dual-test",
				GitHubURL:     "https://github.com/test/dual-repo",
				WebhookSecret: secret,
			}
			repoStore.AddRepository(repo)

			handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempotencyStore)

			// Create payload with fixed before/after SHAs
			commits := []map[string]interface{}{
				{
					"id":      "commit-sha-fixed",
					"message": "test commit",
					"author":  map[string]interface{}{"name": "Test"},
				},
			}
			payload := createPushPayloadWithSHAs(beforeSHA, afterSHA, commits)
			signature := generateGitHubSignature(payload, secret)

			// Send multiple requests with DIFFERENT delivery IDs but SAME push signature
			// This simulates GitHub retrying a webhook with a new delivery ID
			for i := 0; i < numRetries; i++ {
				// Each retry has a DIFFERENT delivery ID
				deliveryID := generateTestDeliveryID(i)

				req := createDraftWebhookRequest(t, repo.ID, payload, signature, deliveryID)
				req.Header.Set("X-GitHub-Event", "push")

				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)

				// All requests should succeed (idempotent)
				if rr.Code != http.StatusOK {
					t.Logf("Request %d failed with status %d", i, rr.Code)
					return false
				}
			}

			// Verify exactly ONE draft was created (dual idempotency via push signature)
			drafts := draftStore.GetDrafts()
			if len(drafts) != 1 {
				t.Logf("Expected 1 draft with dual idempotency after %d retries, got %d",
					numRetries, len(drafts))
				return false
			}

			// Verify the draft has the correct before/after SHAs
			if drafts[0].BeforeSHA != beforeSHA || drafts[0].AfterSHA != afterSHA {
				t.Logf("Draft has wrong SHAs: expected %s/%s, got %s/%s",
					beforeSHA, afterSHA, drafts[0].BeforeSHA, drafts[0].AfterSHA)
				return false
			}

			return true
		},
		gen.IntRange(2, 10), // numRetries (2-10)
		gen.AlphaString(),   // beforeSHASuffix
		gen.AlphaString(),   // afterSHASuffix
		gen.AlphaString(),   // secretSuffix
	))

	properties.TestingRun(t)
}

// =============================================================================
// Test Helpers
// =============================================================================

// generateTestDeliveryID generates a unique delivery ID for testing
func generateTestDeliveryID(index int) string {
	return "delivery-" + string(rune('A'+index%26)) + string(rune('0'+index/26))
}

// generateTestSHA generates a unique SHA-like string for testing
func generateTestSHA(prefix string, index int) string {
	return prefix + "-sha-" + string(rune('a'+index%26)) + string(rune('0'+index/26))
}
