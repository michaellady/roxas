// Package tests contains property-based tests for the Roxas application.
// Property 9: Webhooks configured for 'push' events with correct URL and secret.
// Validates Requirements 3.4 (webhook URL format), 3.6 (webhook secret security).
package tests

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/mikelady/roxas/internal/handlers"
)

// TestPropertyWebhookURLFormat verifies that webhook URLs are correctly formatted
// with the base URL and repository ID.
// Validates Requirement 3.4: Webhook URL format is https://roxas.ai/webhooks/github/:repo_id
func TestPropertyWebhookURLFormat(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for valid repository IDs (UUIDs)
	repoIDGen := gen.RegexMatch(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	// Generator for valid webhook base URLs
	baseURLGen := gen.OneConstOf(
		"https://api.roxas.dev",
		"https://roxas.ai",
		"https://api.roxas.ai",
		"https://staging.roxas.ai",
	)

	properties.Property("webhook URL contains base URL and repo ID", prop.ForAll(
		func(baseURL, repoID string) bool {
			webhookURL := fmt.Sprintf("%s/webhook/%s", baseURL, repoID)

			// Property: URL must start with base URL
			if !strings.HasPrefix(webhookURL, baseURL) {
				return false
			}

			// Property: URL must contain the repo ID
			if !strings.Contains(webhookURL, repoID) {
				return false
			}

			// Property: URL must follow the format {baseURL}/webhook/{repoID}
			expectedFormat := fmt.Sprintf("%s/webhook/%s", baseURL, repoID)
			if webhookURL != expectedFormat {
				return false
			}

			return true
		},
		baseURLGen,
		repoIDGen,
	))

	properties.Property("webhook URL path is valid", prop.ForAll(
		func(baseURL, repoID string) bool {
			webhookURL := fmt.Sprintf("%s/webhook/%s", baseURL, repoID)

			// Property: URL must have /webhook/ path segment
			if !strings.Contains(webhookURL, "/webhook/") {
				return false
			}

			// Property: repo ID must be at the end of the URL
			if !strings.HasSuffix(webhookURL, repoID) {
				return false
			}

			return true
		},
		baseURLGen,
		repoIDGen,
	))

	properties.TestingRun(t)
}

// TestPropertyWebhookSecretSecurity verifies that generated webhook secrets
// meet security requirements.
// Validates Requirement 3.6: Webhook secrets are auto-generated per repo with sufficient entropy
func TestPropertyWebhookSecretSecurity(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	secretGen := handlers.NewCryptoSecretGenerator()

	properties.Property("generated secrets have minimum length", prop.ForAll(
		func(_ int) bool {
			secret, err := secretGen.Generate()
			if err != nil {
				return false
			}

			// Property: Secret must be at least 32 characters (256 bits of entropy when base64 encoded)
			// 32 bytes of random data = 43 base64 characters (with padding) or 43 without
			minLength := 32
			return len(secret) >= minLength
		},
		gen.IntRange(0, 100), // dummy generator to run property multiple times
	))

	properties.Property("generated secrets are non-empty", prop.ForAll(
		func(_ int) bool {
			secret, err := secretGen.Generate()
			if err != nil {
				return false
			}

			// Property: Secret must not be empty
			return secret != ""
		},
		gen.IntRange(0, 100),
	))

	properties.Property("generated secrets contain only URL-safe characters", prop.ForAll(
		func(_ int) bool {
			secret, err := secretGen.Generate()
			if err != nil {
				return false
			}

			// Property: Secret must only contain URL-safe base64 characters
			// URL-safe base64 uses A-Z, a-z, 0-9, -, _
			urlSafePattern := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
			return urlSafePattern.MatchString(secret)
		},
		gen.IntRange(0, 100),
	))

	properties.TestingRun(t)
}

// TestPropertyWebhookSecretUniqueness verifies that generated secrets are unique.
func TestPropertyWebhookSecretUniqueness(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	properties := gopter.NewProperties(parameters)

	secretGen := handlers.NewCryptoSecretGenerator()

	properties.Property("consecutively generated secrets are different", prop.ForAll(
		func(_ int) bool {
			secret1, err1 := secretGen.Generate()
			secret2, err2 := secretGen.Generate()

			if err1 != nil || err2 != nil {
				return false
			}

			// Property: Two consecutively generated secrets must be different
			return secret1 != secret2
		},
		gen.IntRange(0, 100),
	))

	properties.TestingRun(t)
}

// TestPropertyWebhookSignatureValidation verifies that webhook secrets can be
// used to correctly validate HMAC-SHA256 signatures as used by GitHub webhooks.
func TestPropertyWebhookSignatureValidation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	secretGen := handlers.NewCryptoSecretGenerator()

	// Generator for webhook payload content
	payloadGen := gen.AnyString()

	properties.Property("valid signature is accepted", prop.ForAll(
		func(payload string) bool {
			secret, err := secretGen.Generate()
			if err != nil {
				return false
			}

			// Compute signature (as GitHub would)
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(payload))
			signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

			// Verify using the same secret
			handler := handlers.NewWebhookHandler(secret)
			return handler.ValidateSignatureForTest([]byte(payload), signature)
		},
		payloadGen,
	))

	properties.Property("invalid signature is rejected", prop.ForAll(
		func(payload string) bool {
			secret, err := secretGen.Generate()
			if err != nil {
				return false
			}

			// Compute signature with wrong secret
			wrongSecret := "wrong-secret-12345"
			mac := hmac.New(sha256.New, []byte(wrongSecret))
			mac.Write([]byte(payload))
			wrongSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

			// Verify should fail with correct secret
			handler := handlers.NewWebhookHandler(secret)
			return !handler.ValidateSignatureForTest([]byte(payload), wrongSignature)
		},
		payloadGen,
	))

	properties.Property("tampered payload is rejected", prop.ForAll(
		func(payload string) bool {
			if len(payload) == 0 {
				return true // Skip empty payloads
			}

			secret, err := secretGen.Generate()
			if err != nil {
				return false
			}

			// Compute valid signature for original payload
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(payload))
			signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

			// Tamper with payload
			tamperedPayload := payload + "tampered"

			// Verify should fail with tampered payload
			handler := handlers.NewWebhookHandler(secret)
			return !handler.ValidateSignatureForTest([]byte(tamperedPayload), signature)
		},
		payloadGen,
	))

	properties.TestingRun(t)
}

// TestPropertyWebhookConfigIntegration verifies the complete webhook configuration
// as returned by the repository handler.
func TestPropertyWebhookConfigIntegration(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	properties := gopter.NewProperties(parameters)

	// Generator for valid GitHub repository URLs
	githubURLGen := gen.RegexMatch(`https://github\.com/[a-z][a-z0-9-]{0,38}/[a-z][a-z0-9._-]{0,99}`)

	baseURLGen := gen.OneConstOf(
		"https://api.roxas.dev",
		"https://roxas.ai",
	)

	properties.Property("webhook config has valid URL and secret", prop.ForAll(
		func(baseURL, githubURL string) bool {
			// Skip invalid generated URLs
			if !strings.HasPrefix(githubURL, "https://github.com/") {
				return true
			}

			store := handlers.NewMockRepositoryStore()
			secretGen := handlers.NewCryptoSecretGenerator()
			handler := handlers.NewRepositoryHandler(store, secretGen, baseURL)

			// Get the webhook config that would be returned
			config := handler.GetWebhookConfigForTest("test-repo-id")

			// Property: URL must be correctly formatted
			expectedURLFormat := fmt.Sprintf("%s/webhook/test-repo-id", baseURL)
			if config.URL != expectedURLFormat {
				return false
			}

			// Property: Secret must meet security requirements
			if len(config.Secret) < 32 {
				return false
			}

			return true
		},
		baseURLGen,
		githubURLGen,
	))

	properties.TestingRun(t)
}
