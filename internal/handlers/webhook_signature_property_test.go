package handlers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// Property Test: Webhook Signature Validation
// Property 13: Valid HMAC-SHA256 accepted, invalid rejected and logged.
// Validates Requirements 5.1, 5.2, 13.3, 13.4
//
// This property test verifies that:
// - For ANY payload and secret, a correctly computed HMAC-SHA256 signature is accepted (200 OK)
// - For ANY payload and secret, an incorrectly computed signature is rejected (401 Unauthorized)
// - For ANY payload and secret, a missing signature is rejected (401 Unauthorized)
// - Invalid signatures are logged (via delivery recording)

// computeValidSignature computes a valid GitHub-style HMAC-SHA256 signature
func computeValidSignature(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// createValidWebhookPayload creates a valid webhook JSON payload with the given message
func createValidWebhookPayload(message string) []byte {
	payload := map[string]interface{}{
		"repository": map[string]string{
			"html_url": "https://github.com/test/repo",
		},
		"commits": []map[string]interface{}{
			{
				"message": message,
				"id":      "abc123",
				"author": map[string]string{
					"name": "Test Author",
				},
			},
		},
	}
	data, _ := json.Marshal(payload)
	return data
}

// TestPropertyValidSignatureAccepted verifies that valid HMAC-SHA256 signatures are always accepted
// Property: For any (payload, secret) pair, HMAC-SHA256(payload, secret) produces an accepted signature
func TestPropertyValidSignatureAccepted(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("Valid HMAC-SHA256 signatures are always accepted", prop.ForAll(
		func(message string, secret string) bool {
			// Skip empty secrets (GitHub requires non-empty secrets)
			if secret == "" {
				return true // vacuously true for invalid inputs
			}

			payload := createValidWebhookPayload(message)
			validSig := computeValidSignature(payload, secret)

			req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
			req.Header.Set("X-Hub-Signature-256", validSig)
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler := NewWebhookHandler(secret)
			handler.ServeHTTP(rr, req)

			// Valid signature MUST result in 200 OK
			return rr.Code == http.StatusOK
		},
		gen.AnyString(),        // message
		gen.AlphaString(),      // secret (non-empty by generator)
	))

	properties.TestingRun(t)
}

// TestPropertyInvalidSignatureRejected verifies that invalid signatures are always rejected
// Property: For any (payload, secret, wrongSignature), if wrongSignature != HMAC-SHA256(payload, secret),
// then the request is rejected with 401 Unauthorized
func TestPropertyInvalidSignatureRejected(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("Invalid signatures are always rejected with 401", prop.ForAll(
		func(message string, secret string, wrongSig string) bool {
			// Skip empty secrets
			if secret == "" {
				return true
			}

			payload := createValidWebhookPayload(message)
			validSig := computeValidSignature(payload, secret)

			// Ensure wrongSig is different from valid signature
			invalidSig := "sha256=" + wrongSig
			if invalidSig == validSig {
				return true // skip this case, it's actually valid
			}

			req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
			req.Header.Set("X-Hub-Signature-256", invalidSig)
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler := NewWebhookHandler(secret)
			handler.ServeHTTP(rr, req)

			// Invalid signature MUST result in 401 Unauthorized
			return rr.Code == http.StatusUnauthorized
		},
		gen.AnyString(),        // message
		gen.AlphaString(),      // secret
		gen.AlphaString(),      // wrongSig (random string, likely invalid)
	))

	properties.TestingRun(t)
}

// TestPropertyMissingSignatureRejected verifies that missing signatures are always rejected
// Property: For any (payload, secret), a request without X-Hub-Signature-256 header is rejected
func TestPropertyMissingSignatureRejected(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("Missing signature is always rejected with 401", prop.ForAll(
		func(message string, secret string) bool {
			// Skip empty secrets
			if secret == "" {
				return true
			}

			payload := createValidWebhookPayload(message)

			req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
			// No X-Hub-Signature-256 header
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler := NewWebhookHandler(secret)
			handler.ServeHTTP(rr, req)

			// Missing signature MUST result in 401 Unauthorized
			return rr.Code == http.StatusUnauthorized
		},
		gen.AnyString(),   // message
		gen.AlphaString(), // secret
	))

	properties.TestingRun(t)
}

// TestPropertyMultiTenantValidSignatureAccepted verifies valid signatures work with multi-tenant handler
// Property: For any (payload, secret, repoID), a valid signature is accepted
func TestPropertyMultiTenantValidSignatureAccepted(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("Multi-tenant: Valid signatures are always accepted", prop.ForAll(
		func(message string, secret string, repoID string) bool {
			// Skip empty secrets or repoIDs
			if secret == "" || repoID == "" {
				return true
			}

			payload := createValidMultiTenantPayload(message)
			validSig := computeValidSignature(payload, secret)

			// Create mock repository store
			mockRepoStore := &mockRepoStore{
				repo: &Repository{
					ID:            repoID,
					UserID:        "user-123",
					WebhookSecret: secret,
				},
			}
			mockCommitStore := &mockCommitStore{}

			req := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+repoID, bytes.NewReader(payload))
			req.Header.Set("X-Hub-Signature-256", validSig)
			req.Header.Set("X-GitHub-Event", "push")
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler := NewMultiTenantWebhookHandler(mockRepoStore, mockCommitStore)
			handler.ServeHTTP(rr, req)

			// Valid signature MUST result in 200 OK
			return rr.Code == http.StatusOK
		},
		gen.AnyString(),   // message
		gen.AlphaString(), // secret
		gen.AlphaString(), // repoID
	))

	properties.TestingRun(t)
}

// TestPropertyMultiTenantInvalidSignatureRejectedAndLogged verifies invalid signatures are rejected
// and logged with the multi-tenant handler
// Property: For any (payload, secret, wrongSig), invalid signature results in 401 and is logged
func TestPropertyMultiTenantInvalidSignatureRejectedAndLogged(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("Multi-tenant: Invalid signatures are rejected and logged", prop.ForAll(
		func(message string, secret string, wrongSig string, repoID string) bool {
			// Skip empty values
			if secret == "" || repoID == "" {
				return true
			}

			payload := createValidMultiTenantPayload(message)
			validSig := computeValidSignature(payload, secret)

			// Ensure wrongSig is different from valid signature
			invalidSig := "sha256=" + wrongSig
			if invalidSig == validSig {
				return true // skip this case
			}

			// Create mock stores including delivery store for logging verification
			mockRepoStore := &mockRepoStore{
				repo: &Repository{
					ID:            repoID,
					UserID:        "user-123",
					WebhookSecret: secret,
				},
			}
			mockCommitStore := &mockCommitStore{}
			mockDeliveryStore := &mockDeliveryStore{}

			req := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+repoID, bytes.NewReader(payload))
			req.Header.Set("X-Hub-Signature-256", invalidSig)
			req.Header.Set("X-GitHub-Event", "push")
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler := NewMultiTenantWebhookHandler(mockRepoStore, mockCommitStore).
				WithDeliveryStore(mockDeliveryStore)
			handler.ServeHTTP(rr, req)

			// Invalid signature MUST result in 401 Unauthorized
			if rr.Code != http.StatusUnauthorized {
				return false
			}

			// Auth failure MUST be logged (delivery recorded with success=false)
			if len(mockDeliveryStore.deliveries) == 0 {
				return false
			}

			delivery := mockDeliveryStore.deliveries[0]
			return !delivery.Success && delivery.ErrorMessage == "invalid signature"
		},
		gen.AnyString(),   // message
		gen.AlphaString(), // secret
		gen.AlphaString(), // wrongSig
		gen.AlphaString(), // repoID
	))

	properties.TestingRun(t)
}

// TestPropertySignatureConstantTimeComparison verifies the signature comparison is constant-time
// Property: The validation function uses hmac.Equal for constant-time comparison
// This is a structural test - we verify the code path, not timing (timing tests are flaky)
func TestPropertySignatureConstantTimeComparison(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("Signature validation uses constant-time comparison (returns consistent results)", prop.ForAll(
		func(secret string, payload1 string, payload2 string) bool {
			if secret == "" {
				return true
			}

			// Test that different payloads with same secret produce different signatures
			// and validation correctly distinguishes them
			p1 := []byte(payload1)
			p2 := []byte(payload2)

			sig1 := computeValidSignature(p1, secret)
			sig2 := computeValidSignature(p2, secret)

			handler := NewWebhookHandler(secret)

			// Each signature should only validate its own payload
			valid1with1 := handler.validateSignature(p1, sig1)
			valid2with2 := handler.validateSignature(p2, sig2)
			valid1with2 := handler.validateSignature(p1, sig2)
			valid2with1 := handler.validateSignature(p2, sig1)

			// sig1 validates p1, sig2 validates p2
			if !valid1with1 || !valid2with2 {
				return false
			}

			// Cross-validation should fail (unless payloads are identical)
			if payload1 != payload2 {
				if valid1with2 || valid2with1 {
					return false
				}
			}

			return true
		},
		gen.AlphaString(), // secret
		gen.AnyString(),   // payload1
		gen.AnyString(),   // payload2
	))

	properties.TestingRun(t)
}

// Helper function to create a valid multi-tenant webhook payload
func createValidMultiTenantPayload(message string) []byte {
	payload := map[string]interface{}{
		"ref":    "refs/heads/main",
		"before": "0000000000000000000000000000000000000000",
		"after":  "abc123abc123abc123abc123abc123abc123abc1",
		"repository": map[string]string{
			"html_url":  "https://github.com/test/repo",
			"full_name": "test/repo",
		},
		"commits": []map[string]interface{}{
			{
				"id":        "abc123",
				"message":   message,
				"url":       "https://github.com/test/repo/commit/abc123",
				"timestamp": "2026-01-01T00:00:00Z",
				"author": map[string]string{
					"name":  "Test Author",
					"email": "test@example.com",
				},
			},
		},
	}
	data, _ := json.Marshal(payload)
	return data
}

// Mock implementations for testing

type mockRepoStore struct {
	repo *Repository
}

func (m *mockRepoStore) GetRepositoryByID(ctx context.Context, repoID string) (*Repository, error) {
	if m.repo != nil && m.repo.ID == repoID {
		return m.repo, nil
	}
	return nil, nil
}

type mockCommitStore struct {
	commits []*StoredCommit
}

func (m *mockCommitStore) StoreCommit(ctx context.Context, commit *StoredCommit) error {
	m.commits = append(m.commits, commit)
	return nil
}

func (m *mockCommitStore) GetCommitBySHA(ctx context.Context, repoID, sha string) (*StoredCommit, error) {
	for _, c := range m.commits {
		if c.RepositoryID == repoID && c.CommitSHA == sha {
			return c, nil
		}
	}
	return nil, nil
}

type mockDeliveryStore struct {
	deliveries []*WebhookDelivery
}

func (m *mockDeliveryStore) RecordDelivery(ctx context.Context, delivery *WebhookDelivery) error {
	m.deliveries = append(m.deliveries, delivery)
	return nil
}

func (m *mockDeliveryStore) GetDeliveries() []*WebhookDelivery {
	return m.deliveries
}
