package auth

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestHashPassword tests that HashPassword successfully creates a bcrypt hash
func TestHashPassword(t *testing.T) {
	password := "testpassword123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	if hash == "" {
		t.Error("HashPassword returned empty hash")
	}

	// Verify the hash is valid bcrypt format
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		t.Error("Generated hash is not valid bcrypt")
	}
}

// TestCheckPassword_Valid tests that correct password verifies successfully
func TestCheckPassword_Valid(t *testing.T) {
	password := "correctpassword"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	if !CheckPassword(password, hash) {
		t.Error("CheckPassword returned false for correct password")
	}
}

// TestCheckPassword_Invalid tests that wrong password fails verification
func TestCheckPassword_Invalid(t *testing.T) {
	password := "correctpassword"
	wrongPassword := "wrongpassword"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	if CheckPassword(wrongPassword, hash) {
		t.Error("CheckPassword returned true for wrong password")
	}
}

// TestHashPassword_Consistency tests that the same password can be verified
// even though bcrypt generates different hashes each time (due to random salt)
func TestHashPassword_Consistency(t *testing.T) {
	password := "samepassword"

	// Generate two hashes from the same password
	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("First HashPassword returned error: %v", err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Second HashPassword returned error: %v", err)
	}

	// Hashes should be different due to random salt
	if hash1 == hash2 {
		t.Error("Expected different hashes due to salt, got same hash")
	}

	// But both should verify against the original password
	if !CheckPassword(password, hash1) {
		t.Error("First hash failed verification")
	}

	if !CheckPassword(password, hash2) {
		t.Error("Second hash failed verification")
	}
}

// TestCheckPassword_InvalidHash tests behavior with malformed hash
func TestCheckPassword_InvalidHash(t *testing.T) {
	password := "anypassword"
	invalidHash := "notavalidbcrypthash"

	if CheckPassword(password, invalidHash) {
		t.Error("CheckPassword should return false for invalid hash")
	}
}

// TestCheckPassword_EmptyPassword tests behavior with empty password
func TestCheckPassword_EmptyPassword(t *testing.T) {
	// Hash an empty password
	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword returned error for empty password: %v", err)
	}

	// Empty password should verify against its own hash
	if !CheckPassword("", hash) {
		t.Error("Empty password should verify against its own hash")
	}

	// Non-empty password should not verify against empty password hash
	if CheckPassword("notempty", hash) {
		t.Error("Non-empty password should not verify against empty password hash")
	}
}
