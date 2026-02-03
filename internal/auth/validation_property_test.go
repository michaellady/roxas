package auth

import (
	"reflect"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// Property 2: Password Validation Rejects Short Passwords
// For any password shorter than 8 characters, registration should be rejected
// with a validation error.
// Validates: Requirements 1.3

// TestProperty_PasswordValidationRejectsShortPasswords verifies Property 2:
// Any password shorter than 8 characters must be rejected.
func TestProperty_PasswordValidationRejectsShortPasswords(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 7 // Max length for short passwords

	properties := gopter.NewProperties(parameters)

	// Generate non-empty passwords with length 1-7 bytes (using ASCII characters)
	genShortPassword := gen.IntRange(1, 7).FlatMap(func(v interface{}) gopter.Gen {
		length := v.(int)
		// Use ASCII printable characters (33-126) to ensure 1 byte per character
		return gen.SliceOfN(length, gen.IntRange(33, 126)).Map(func(chars []int) string {
			bytes := make([]byte, len(chars))
			for i, c := range chars {
				bytes[i] = byte(c)
			}
			return string(bytes)
		})
	}, reflect.TypeOf(""))

	properties.Property("short passwords (1-7 chars) are rejected", prop.ForAll(
		func(password string) bool {
			err := ValidatePassword(password)

			// Property: Password validation must return an error for short passwords
			if err == nil {
				t.Logf("Expected error for password of length %d, got nil", len(password))
				return false
			}

			// The error should be ErrWeakPassword
			if err != ErrWeakPassword {
				t.Logf("Expected ErrWeakPassword for password of length %d, got %v", len(password), err)
				return false
			}

			return true
		},
		genShortPassword,
	))

	properties.TestingRun(t)
}

// TestProperty_EmptyPasswordIsRejected verifies that empty passwords are rejected.
// This is a special case of Property 2 where the password length is 0.
func TestProperty_EmptyPasswordIsRejected(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100

	properties := gopter.NewProperties(parameters)

	// Generate empty strings (always empty)
	genEmptyPassword := gen.Const("")

	properties.Property("empty password is rejected", prop.ForAll(
		func(password string) bool {
			err := ValidatePassword(password)

			// Property: Password validation must return an error for empty passwords
			if err == nil {
				t.Logf("Expected error for empty password, got nil")
				return false
			}

			// The error should be ErrMissingPassword for empty strings
			if err != ErrMissingPassword {
				t.Logf("Expected ErrMissingPassword for empty password, got %v", err)
				return false
			}

			return true
		},
		genEmptyPassword,
	))

	properties.TestingRun(t)
}

// TestProperty_ValidPasswordsAreAccepted verifies the inverse property:
// passwords of 8+ characters should be accepted.
func TestProperty_ValidPasswordsAreAccepted(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100 // Allow longer passwords

	properties := gopter.NewProperties(parameters)

	// Generate non-empty passwords with length >= 8 bytes (using ASCII characters)
	genValidPassword := gen.IntRange(8, 100).FlatMap(func(v interface{}) gopter.Gen {
		length := v.(int)
		// Use ASCII printable characters (33-126) to ensure 1 byte per character
		return gen.SliceOfN(length, gen.IntRange(33, 126)).Map(func(chars []int) string {
			bytes := make([]byte, len(chars))
			for i, c := range chars {
				bytes[i] = byte(c)
			}
			return string(bytes)
		})
	}, reflect.TypeOf(""))

	properties.Property("passwords with 8+ characters are accepted", prop.ForAll(
		func(password string) bool {
			err := ValidatePassword(password)

			// Property: Password validation must succeed for valid-length passwords
			if err != nil {
				t.Logf("Expected no error for password of length %d, got %v", len(password), err)
				return false
			}

			return true
		},
		genValidPassword,
	))

	properties.TestingRun(t)
}
