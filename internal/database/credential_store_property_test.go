package database

import (
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// Property Test: Credential Encryption (Property 6)
// Validates Requirements 2.3, 13.2
//
// Property: Platform credentials (access_token, refresh_token) are stored encrypted.
// This means:
// 1. Encrypted output differs from plaintext input (for non-empty strings)
// 2. Decryption correctly recovers the original plaintext
// 3. Same plaintext encrypted twice produces different ciphertexts (non-deterministic)

func TestProperty_CredentialEncryption(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	store, err := NewCredentialStore(nil, testEncryptionKey)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Property 6a: For any non-empty token, encrypted form differs from plaintext
	properties.Property("encrypted token differs from plaintext", prop.ForAll(
		func(token string) bool {
			if token == "" {
				return true // Empty strings are handled specially
			}
			encrypted, err := store.encrypt(token)
			if err != nil {
				return false
			}
			return encrypted != token
		},
		gen.AnyString(),
	))

	// Property 6b: Encryption round-trip preserves original value
	properties.Property("decrypt(encrypt(token)) == token", prop.ForAll(
		func(token string) bool {
			encrypted, err := store.encrypt(token)
			if err != nil {
				return false
			}
			decrypted, err := store.decrypt(encrypted)
			if err != nil {
				return false
			}
			return decrypted == token
		},
		gen.AnyString(),
	))

	// Property 6c: Same plaintext encrypted twice produces different ciphertexts
	// (demonstrates non-deterministic encryption due to random nonce)
	properties.Property("encryption is non-deterministic", prop.ForAll(
		func(token string) bool {
			if token == "" {
				return true // Empty strings return empty, so they're equal
			}
			encrypted1, err := store.encrypt(token)
			if err != nil {
				return false
			}
			encrypted2, err := store.encrypt(token)
			if err != nil {
				return false
			}
			// Different ciphertexts but both decrypt to same value
			if encrypted1 == encrypted2 {
				return false
			}
			decrypted1, _ := store.decrypt(encrypted1)
			decrypted2, _ := store.decrypt(encrypted2)
			return decrypted1 == decrypted2 && decrypted1 == token
		},
		gen.AnyString().SuchThat(func(s string) bool { return len(s) > 0 }),
	))

	// Property 6d: Encrypted tokens are base64 encoded (storage format)
	properties.Property("encrypted tokens are valid base64", prop.ForAll(
		func(token string) bool {
			if token == "" {
				return true
			}
			encrypted, err := store.encrypt(token)
			if err != nil {
				return false
			}
			// Check it's valid base64 by attempting to decode via decrypt
			// If the format were invalid, decrypt would fail on base64 decode
			_, err = store.decrypt(encrypted)
			return err == nil
		},
		gen.AnyString(),
	))

	// Property 6e: Encryption key length validation
	properties.Property("only 32-byte keys are accepted", prop.ForAll(
		func(keyLen int) bool {
			if keyLen < 0 || keyLen > 100 {
				return true // Out of reasonable range, skip
			}
			key := make([]byte, keyLen)
			_, err := NewCredentialStore(nil, key)
			if keyLen == 32 {
				return err == nil // 32 bytes should succeed
			}
			return err != nil // Other lengths should fail
		},
		gen.IntRange(0, 64),
	))

	// Property 6f: Special characters and various byte sequences are preserved
	properties.Property("special characters are preserved through encryption", prop.ForAll(
		func(token string) bool {
			encrypted, err := store.encrypt(token)
			if err != nil {
				return false
			}
			decrypted, err := store.decrypt(encrypted)
			if err != nil {
				return false
			}
			// Verify exact byte-level equality
			return decrypted == token && len(decrypted) == len(token)
		},
		gen.AnyString(),
	))

	properties.TestingRun(t)
}

// TestProperty_CredentialEncryption_WrongKey validates that decryption fails
// with the wrong key (security property)
func TestProperty_CredentialEncryption_WrongKey(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100

	properties := gopter.NewProperties(parameters)

	store1, _ := NewCredentialStore(nil, testEncryptionKey)
	otherKey := []byte("abcdefghijklmnopqrstuvwxyz123456")
	store2, _ := NewCredentialStore(nil, otherKey)

	// Property: Decryption with wrong key fails
	properties.Property("decrypt with wrong key fails", prop.ForAll(
		func(token string) bool {
			if token == "" {
				return true // Empty strings handled specially
			}
			encrypted, err := store1.encrypt(token)
			if err != nil {
				return false
			}
			// Decrypting with different key should fail
			_, err = store2.decrypt(encrypted)
			return err != nil
		},
		gen.AnyString().SuchThat(func(s string) bool { return len(s) > 0 }),
	))

	properties.TestingRun(t)
}
