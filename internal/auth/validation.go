package auth

import (
	"errors"
	"regexp"
	"strings"
)

// Validation errors
var (
	ErrInvalidEmail    = errors.New("invalid email format")
	ErrWeakPassword    = errors.New("password must be at least 8 characters")
	ErrMissingEmail    = errors.New("email is required")
	ErrMissingPassword = errors.New("password is required")
)

// emailRegex is a simple email validation pattern
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// ValidateEmail checks if an email address is valid
func ValidateEmail(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return ErrMissingEmail
	}
	if !emailRegex.MatchString(email) {
		return ErrInvalidEmail
	}
	return nil
}

// ValidatePassword checks if a password meets requirements
func ValidatePassword(password string) error {
	if password == "" {
		return ErrMissingPassword
	}
	if len(password) < 8 {
		return ErrWeakPassword
	}
	return nil
}

// ValidateRegistration validates both email and password
func ValidateRegistration(email, password string) error {
	if err := ValidateEmail(email); err != nil {
		return err
	}
	if err := ValidatePassword(password); err != nil {
		return err
	}
	return nil
}
