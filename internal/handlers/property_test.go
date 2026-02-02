package handlers

import (
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// =============================================================================
// Property-Based Tests using gopter
// =============================================================================

// TestPropertyUniqueWebhookSecrets verifies that each webhook has a unique secret.
// Property 8: Each webhook has unique secret (Validates Requirements 3.5)
//
// This test uses property-based testing to verify that the CryptoSecretGenerator
// never produces duplicate secrets across many generations. The test generates
// a random number of secrets (between 2 and 1000) and verifies all are unique.
func TestPropertyUniqueWebhookSecrets(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 1000

	properties := gopter.NewProperties(parameters)

	properties.Property("all generated secrets are unique", prop.ForAll(
		func(count int) bool {
			gen := NewCryptoSecretGenerator()
			secrets := make(map[string]struct{}, count)

			for i := 0; i < count; i++ {
				secret, err := gen.Generate()
				if err != nil {
					return false
				}

				// Check if we've seen this secret before
				if _, exists := secrets[secret]; exists {
					return false // Duplicate found - property violated
				}
				secrets[secret] = struct{}{}
			}

			return true // All secrets were unique
		},
		gen.IntRange(2, 1000), // Generate between 2 and 1000 secrets per test
	))

	properties.TestingRun(t)
}

// TestPropertySecretNonEmpty verifies that generated secrets are never empty.
func TestPropertySecretNonEmpty(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 1000

	properties := gopter.NewProperties(parameters)

	properties.Property("generated secrets are never empty", prop.ForAll(
		func(_ int) bool {
			gen := NewCryptoSecretGenerator()
			secret, err := gen.Generate()
			if err != nil {
				return false
			}
			return len(secret) > 0
		},
		gen.Int(), // Use any int as a seed for variation
	))

	properties.TestingRun(t)
}

// TestPropertySecretMinimumLength verifies that secrets meet minimum length requirements.
// With 32 bytes of random data encoded in base64 (RawURLEncoding), the output
// should be at least 43 characters (ceil(32 * 4 / 3)).
func TestPropertySecretMinimumLength(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 1000

	properties := gopter.NewProperties(parameters)

	properties.Property("generated secrets have minimum length", prop.ForAll(
		func(_ int) bool {
			gen := NewCryptoSecretGenerator()
			secret, err := gen.Generate()
			if err != nil {
				return false
			}
			// 32 bytes in base64 RawURLEncoding = 43 characters
			return len(secret) >= 43
		},
		gen.Int(),
	))

	properties.TestingRun(t)
}

// TestPropertySecretBase64URLSafe verifies that secrets contain only URL-safe characters.
// RawURLEncoding uses A-Z, a-z, 0-9, -, and _ (no padding).
func TestPropertySecretBase64URLSafe(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 1000

	properties := gopter.NewProperties(parameters)

	properties.Property("generated secrets are URL-safe", prop.ForAll(
		func(_ int) bool {
			gen := NewCryptoSecretGenerator()
			secret, err := gen.Generate()
			if err != nil {
				return false
			}

			for _, c := range secret {
				isValid := (c >= 'A' && c <= 'Z') ||
					(c >= 'a' && c <= 'z') ||
					(c >= '0' && c <= '9') ||
					c == '-' || c == '_'
				if !isValid {
					return false
				}
			}
			return true
		},
		gen.Int(),
	))

	properties.TestingRun(t)
}
