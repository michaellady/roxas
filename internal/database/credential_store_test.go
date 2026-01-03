package database

import (
	"testing"
	"time"

	"github.com/mikelady/roxas/internal/services"
)

// testEncryptionKey is a 32-byte key for testing
var testEncryptionKey = []byte("12345678901234567890123456789012")

func TestNewCredentialStore_InvalidKeyLength(t *testing.T) {
	tests := []struct {
		name    string
		keyLen  int
		wantErr bool
	}{
		{name: "empty key", keyLen: 0, wantErr: true},
		{name: "16 byte key (too short)", keyLen: 16, wantErr: true},
		{name: "32 byte key (valid)", keyLen: 32, wantErr: false},
		{name: "64 byte key (too long)", keyLen: 64, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			_, err := NewCredentialStore(nil, key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCredentialStore() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCredentialStore_EncryptDecrypt(t *testing.T) {
	store, err := NewCredentialStore(nil, testEncryptionKey)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{name: "empty string", plaintext: ""},
		{name: "short token", plaintext: "abc123"},
		{name: "typical OAuth token", plaintext: "ya29.a0AfH6SMBxxxxx-yyyyy-zzzzz_long_oauth_token"},
		{name: "unicode content", plaintext: "token-with-emoji-🔐-and-日本語"},
		{name: "special characters", plaintext: `token+with/special=chars&more%stuff`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := store.encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("encrypt() error = %v", err)
			}

			// Encrypted should be different from plaintext (unless empty)
			if tt.plaintext != "" && encrypted == tt.plaintext {
				t.Error("encrypt() returned plaintext unchanged")
			}

			decrypted, err := store.decrypt(encrypted)
			if err != nil {
				t.Fatalf("decrypt() error = %v", err)
			}

			if decrypted != tt.plaintext {
				t.Errorf("decrypt() = %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestCredentialStore_EncryptDeterministic(t *testing.T) {
	store, err := NewCredentialStore(nil, testEncryptionKey)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	plaintext := "same-token-value"

	// Encrypt twice - should produce different ciphertexts (due to random nonce)
	encrypted1, _ := store.encrypt(plaintext)
	encrypted2, _ := store.encrypt(plaintext)

	if encrypted1 == encrypted2 {
		t.Error("encrypt() should produce different ciphertexts for same plaintext (non-deterministic)")
	}

	// Both should decrypt to the same value
	decrypted1, _ := store.decrypt(encrypted1)
	decrypted2, _ := store.decrypt(encrypted2)

	if decrypted1 != decrypted2 {
		t.Error("Both ciphertexts should decrypt to the same plaintext")
	}
}

func TestCredentialStore_DecryptInvalidCiphertext(t *testing.T) {
	store, err := NewCredentialStore(nil, testEncryptionKey)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	tests := []struct {
		name       string
		ciphertext string
	}{
		{name: "invalid base64", ciphertext: "not-valid-base64!!!"},
		{name: "too short", ciphertext: "YWJj"}, // "abc" in base64, too short for GCM
		{name: "corrupted ciphertext", ciphertext: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.decrypt(tt.ciphertext)
			if err == nil {
				t.Error("decrypt() should fail for invalid ciphertext")
			}
		})
	}
}

func TestCredentialStore_DecryptWrongKey(t *testing.T) {
	store1, _ := NewCredentialStore(nil, testEncryptionKey)
	otherKey := []byte("abcdefghijklmnopqrstuvwxyz123456")
	store2, _ := NewCredentialStore(nil, otherKey)

	plaintext := "secret-token"
	encrypted, _ := store1.encrypt(plaintext)

	// Decrypting with different key should fail
	_, err := store2.decrypt(encrypted)
	if err == nil {
		t.Error("decrypt() should fail when using wrong key")
	}
}

func TestPlatformCredentials_Methods(t *testing.T) {
	now := time.Now()
	hourAgo := now.Add(-time.Hour)
	hourFromNow := now.Add(time.Hour)

	t.Run("IsExpired", func(t *testing.T) {
		expiredCreds := &services.PlatformCredentials{TokenExpiresAt: &hourAgo}
		if !expiredCreds.IsExpired() {
			t.Error("Should be expired")
		}

		validCreds := &services.PlatformCredentials{TokenExpiresAt: &hourFromNow}
		if validCreds.IsExpired() {
			t.Error("Should not be expired")
		}

		neverExpires := &services.PlatformCredentials{TokenExpiresAt: nil}
		if neverExpires.IsExpired() {
			t.Error("Nil expiry should not be expired")
		}
	})

	t.Run("ExpiresWithin", func(t *testing.T) {
		in30Min := now.Add(30 * time.Minute)
		creds := &services.PlatformCredentials{TokenExpiresAt: &in30Min}

		if !creds.ExpiresWithin(time.Hour) {
			t.Error("Should expire within 1 hour")
		}
		if creds.ExpiresWithin(15 * time.Minute) {
			t.Error("Should not expire within 15 minutes")
		}
	})

	t.Run("HasRefreshToken", func(t *testing.T) {
		withRefresh := &services.PlatformCredentials{RefreshToken: "refresh-token"}
		if !withRefresh.HasRefreshToken() {
			t.Error("Should have refresh token")
		}

		withoutRefresh := &services.PlatformCredentials{RefreshToken: ""}
		if withoutRefresh.HasRefreshToken() {
			t.Error("Should not have refresh token")
		}
	})
}

func TestValidatePlatform(t *testing.T) {
	validPlatforms := []string{
		services.PlatformLinkedIn,
		services.PlatformTwitter,
		services.PlatformInstagram,
		services.PlatformYouTube,
		services.PlatformBluesky,
		services.PlatformThreads,
		services.PlatformTikTok,
	}

	for _, platform := range validPlatforms {
		if err := services.ValidatePlatform(platform); err != nil {
			t.Errorf("ValidatePlatform(%q) should be valid, got error: %v", platform, err)
		}
	}

	invalidPlatforms := []string{"", "facebook", "myspace", "LINKEDIN"}
	for _, platform := range invalidPlatforms {
		if err := services.ValidatePlatform(platform); err == nil {
			t.Errorf("ValidatePlatform(%q) should be invalid", platform)
		}
	}
}
