package auth

import (
	"testing"
)

// =============================================================================
// ValidateEmail tests
// =============================================================================

func TestValidateEmail_ValidEmails(t *testing.T) {
	testCases := []struct {
		name  string
		email string
	}{
		{"simple email", "test@example.com"},
		{"with subdomain", "test@mail.example.com"},
		{"with plus sign", "test+tag@example.com"},
		{"with dots in local", "first.last@example.com"},
		{"with numbers", "test123@example.com"},
		{"with underscore", "test_user@example.com"},
		{"with hyphen in domain", "test@example-site.com"},
		{"short TLD", "test@example.co"},
		{"long TLD", "test@example.museum"},
		{"all caps", "TEST@EXAMPLE.COM"},
		{"mixed case", "Test@Example.Com"},
		{"with percent", "test%tag@example.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEmail(tc.email)
			if err != nil {
				t.Errorf("ValidateEmail(%q) = %v, want nil", tc.email, err)
			}
		})
	}
}

func TestValidateEmail_InvalidEmails(t *testing.T) {
	testCases := []struct {
		name  string
		email string
	}{
		{"missing @", "testexample.com"},
		{"missing domain", "test@"},
		{"missing local part", "@example.com"},
		{"missing TLD", "test@example"},
		{"double @", "test@@example.com"},
		{"space in local", "test user@example.com"},
		{"space in domain", "test@exam ple.com"},
		{"just @", "@"},
		{"single char TLD", "test@example.c"},
		{"special chars", "test<>@example.com"},
		{"no domain part", "test@.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEmail(tc.email)
			if err != ErrInvalidEmail {
				t.Errorf("ValidateEmail(%q) = %v, want ErrInvalidEmail", tc.email, err)
			}
		})
	}
}

func TestValidateEmail_EmptyAndWhitespace(t *testing.T) {
	testCases := []struct {
		name        string
		email       string
		expectedErr error
	}{
		{"empty string", "", ErrMissingEmail},
		{"only spaces", "   ", ErrMissingEmail},
		{"only tab", "\t", ErrMissingEmail},
		{"only newline", "\n", ErrMissingEmail},
		{"mixed whitespace", " \t\n ", ErrMissingEmail},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEmail(tc.email)
			if err != tc.expectedErr {
				t.Errorf("ValidateEmail(%q) = %v, want %v", tc.email, err, tc.expectedErr)
			}
		})
	}
}

func TestValidateEmail_TrimsWhitespace(t *testing.T) {
	testCases := []struct {
		name  string
		email string
	}{
		{"leading space", " test@example.com"},
		{"trailing space", "test@example.com "},
		{"both spaces", " test@example.com "},
		{"leading tab", "\ttest@example.com"},
		{"trailing newline", "test@example.com\n"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEmail(tc.email)
			if err != nil {
				t.Errorf("ValidateEmail(%q) = %v, want nil (should trim whitespace)", tc.email, err)
			}
		})
	}
}

// =============================================================================
// ValidatePassword tests
// =============================================================================

func TestValidatePassword_EmptyPassword(t *testing.T) {
	err := ValidatePassword("")
	if err != ErrMissingPassword {
		t.Errorf("ValidatePassword(\"\") = %v, want ErrMissingPassword", err)
	}
}

func TestValidatePassword_ShortPasswords(t *testing.T) {
	testCases := []struct {
		name     string
		password string
	}{
		{"1 char", "a"},
		{"2 chars", "ab"},
		{"3 chars", "abc"},
		{"4 chars", "abcd"},
		{"5 chars", "abcde"},
		{"6 chars", "abcdef"},
		{"7 chars", "abcdefg"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePassword(tc.password)
			if err != ErrWeakPassword {
				t.Errorf("ValidatePassword(%q) = %v, want ErrWeakPassword", tc.password, err)
			}
		})
	}
}

func TestValidatePassword_ValidPasswords(t *testing.T) {
	testCases := []struct {
		name     string
		password string
	}{
		{"exactly 8 chars", "abcdefgh"},
		{"9 chars", "abcdefghi"},
		{"10 chars", "abcdefghij"},
		{"long password", "thisisaverylongpasswordthatshouldbefine"},
		{"with numbers", "password123"},
		{"with special chars", "p@ssw0rd!"},
		{"all numbers", "12345678"},
		{"all special chars", "!@#$%^&*"},
		{"with spaces", "pass word"},
		{"unicode chars", "pässwörd"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePassword(tc.password)
			if err != nil {
				t.Errorf("ValidatePassword(%q) = %v, want nil", tc.password, err)
			}
		})
	}
}

// =============================================================================
// ValidateRegistration tests
// =============================================================================

func TestValidateRegistration_ValidInputs(t *testing.T) {
	testCases := []struct {
		name     string
		email    string
		password string
	}{
		{"basic valid", "test@example.com", "password123"},
		{"complex email", "user.name+tag@example.co.uk", "securepass"},
		{"long password", "test@example.com", "thisisaverysecurepassword"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRegistration(tc.email, tc.password)
			if err != nil {
				t.Errorf("ValidateRegistration(%q, %q) = %v, want nil", tc.email, tc.password, err)
			}
		})
	}
}

func TestValidateRegistration_InvalidEmail(t *testing.T) {
	testCases := []struct {
		name        string
		email       string
		password    string
		expectedErr error
	}{
		{"empty email", "", "password123", ErrMissingEmail},
		{"invalid email format", "notanemail", "password123", ErrInvalidEmail},
		{"whitespace email", "   ", "password123", ErrMissingEmail},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRegistration(tc.email, tc.password)
			if err != tc.expectedErr {
				t.Errorf("ValidateRegistration(%q, %q) = %v, want %v", tc.email, tc.password, err, tc.expectedErr)
			}
		})
	}
}

func TestValidateRegistration_InvalidPassword(t *testing.T) {
	testCases := []struct {
		name        string
		email       string
		password    string
		expectedErr error
	}{
		{"empty password", "test@example.com", "", ErrMissingPassword},
		{"short password", "test@example.com", "short", ErrWeakPassword},
		{"7 char password", "test@example.com", "1234567", ErrWeakPassword},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRegistration(tc.email, tc.password)
			if err != tc.expectedErr {
				t.Errorf("ValidateRegistration(%q, %q) = %v, want %v", tc.email, tc.password, err, tc.expectedErr)
			}
		})
	}
}

func TestValidateRegistration_EmailCheckedFirst(t *testing.T) {
	// When both email and password are invalid, email error should be returned first
	err := ValidateRegistration("", "")
	if err != ErrMissingEmail {
		t.Errorf("ValidateRegistration(\"\", \"\") = %v, want ErrMissingEmail (email validated first)", err)
	}

	err = ValidateRegistration("invalid", "short")
	if err != ErrInvalidEmail {
		t.Errorf("ValidateRegistration(\"invalid\", \"short\") = %v, want ErrInvalidEmail (email validated first)", err)
	}
}

// =============================================================================
// Error variable tests
// =============================================================================

func TestErrorMessages(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		contains string
	}{
		{"ErrInvalidEmail", ErrInvalidEmail, "email"},
		{"ErrWeakPassword", ErrWeakPassword, "8 characters"},
		{"ErrMissingEmail", ErrMissingEmail, "email"},
		{"ErrMissingPassword", ErrMissingPassword, "password"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if msg == "" {
				t.Errorf("%s.Error() returned empty string", tc.name)
			}
		})
	}
}
