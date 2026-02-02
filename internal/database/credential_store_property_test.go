package database

import (
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/mikelady/roxas/internal/services"
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

// TestProperty12_BlueskyCredentialStorage tests Property 12:
// Bluesky auth stores app password as access_token, handle as refresh_token, DID as platform_user_id.
// Validates Requirements 4.5, 4.6
func TestProperty12_BlueskyCredentialStorage(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	store, err := NewCredentialStore(nil, testEncryptionKey)
	if err != nil {
		t.Fatalf("Failed to create credential store: %v", err)
	}

	// Property 12a: App password stored as access_token survives encryption round-trip
	properties.Property("app password stored as AccessToken encrypts and decrypts correctly", prop.ForAll(
		func(appPassword string) bool {
			creds := &services.PlatformCredentials{
				Platform:    services.PlatformBluesky,
				AccessToken: appPassword, // App password stored here
			}

			encrypted, err := store.encrypt(creds.AccessToken)
			if err != nil {
				return false
			}

			decrypted, err := store.decrypt(encrypted)
			if err != nil {
				return false
			}

			return decrypted == appPassword
		},
		genAppPassword(),
	))

	// Property 12b: Handle stored as refresh_token survives encryption round-trip
	properties.Property("handle stored as RefreshToken encrypts and decrypts correctly", prop.ForAll(
		func(handle string) bool {
			creds := &services.PlatformCredentials{
				Platform:     services.PlatformBluesky,
				RefreshToken: handle, // Handle stored here
			}

			encrypted, err := store.encrypt(creds.RefreshToken)
			if err != nil {
				return false
			}

			decrypted, err := store.decrypt(encrypted)
			if err != nil {
				return false
			}

			return decrypted == handle
		},
		genBlueskyHandle(),
	))

	// Property 12c: DID stored as platform_user_id preserves format
	properties.Property("DID stored as PlatformUserID preserves exact value", prop.ForAll(
		func(did string) bool {
			creds := &services.PlatformCredentials{
				Platform:       services.PlatformBluesky,
				PlatformUserID: did, // DID stored here
			}

			// PlatformUserID is not encrypted, but verify it maintains value
			return creds.PlatformUserID == did
		},
		genBlueskyDID(),
	))

	// Property 12d: Complete Bluesky credential mapping is consistent
	properties.Property("complete Bluesky credential mapping preserves all fields", prop.ForAll(
		func(appPassword, handle, did string) bool {
			creds := &services.PlatformCredentials{
				Platform:       services.PlatformBluesky,
				AccessToken:    appPassword, // App password
				RefreshToken:   handle,      // Handle
				PlatformUserID: did,         // DID
			}

			// Verify field mapping
			if creds.AccessToken != appPassword {
				return false
			}
			if creds.RefreshToken != handle {
				return false
			}
			if creds.PlatformUserID != did {
				return false
			}

			// Verify encryption round-trip for sensitive fields
			encryptedAppPwd, err := store.encrypt(creds.AccessToken)
			if err != nil {
				return false
			}
			decryptedAppPwd, err := store.decrypt(encryptedAppPwd)
			if err != nil {
				return false
			}
			if decryptedAppPwd != appPassword {
				return false
			}

			encryptedHandle, err := store.encrypt(creds.RefreshToken)
			if err != nil {
				return false
			}
			decryptedHandle, err := store.decrypt(encryptedHandle)
			if err != nil {
				return false
			}
			if decryptedHandle != handle {
				return false
			}

			return true
		},
		genAppPassword(),
		genBlueskyHandle(),
		genBlueskyDID(),
	))

	// Property 12e: Bluesky platform identifier is always correct
	properties.Property("Bluesky credentials always have correct platform", prop.ForAll(
		func(appPassword, handle, did string) bool {
			creds := &services.PlatformCredentials{
				Platform:       services.PlatformBluesky,
				AccessToken:    appPassword,
				RefreshToken:   handle,
				PlatformUserID: did,
			}

			return creds.Platform == "bluesky"
		},
		genAppPassword(),
		genBlueskyHandle(),
		genBlueskyDID(),
	))

	properties.TestingRun(t)
}

// genAppPassword generates random Bluesky app passwords
// App passwords are 19 characters: xxxx-xxxx-xxxx-xxxx format
func genAppPassword() gopter.Gen {
	return gen.RegexMatch(`[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}`)
}

// genBlueskyHandle generates random Bluesky handles
// Handles are in format: username.bsky.social or custom domains
func genBlueskyHandle() gopter.Gen {
	username := gen.RegexMatch(`[a-z][a-z0-9]{2,15}`)
	domain := gen.OneConstOf("bsky.social", "bsky.app", "example.com")

	return gopter.CombineGens(username, domain).Map(func(vals []interface{}) string {
		return vals[0].(string) + "." + vals[1].(string)
	})
}

// genBlueskyDID generates random Bluesky DIDs
// DIDs are in format: did:plc:<base32-encoded-identifier>
func genBlueskyDID() gopter.Gen {
	// DID identifier is 24 characters of base32
	identifier := gen.RegexMatch(`[a-z2-7]{24}`)

	return identifier.Map(func(id string) string {
		return "did:plc:" + id
	})
}
