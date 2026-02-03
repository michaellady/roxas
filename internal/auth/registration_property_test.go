package auth

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"golang.org/x/crypto/bcrypt"
)

// Property Test: User Registration Creates Valid Accounts (Property 1)
// Validates Requirements 1.1, 1.4, 13.1
//
// Property: For any valid email and password (≥8 chars), registration creates
// user with bcrypt hash and returns JWT with 24h expiration.
// This means:
// 1. Password hashing always produces valid bcrypt hashes
// 2. Generated hashes can verify the original password
// 3. JWT tokens expire in exactly 24 hours
// 4. JWT tokens contain correct user claims

// =============================================================================
// Property 1 Tests
// =============================================================================

func TestProperty1_UserRegistrationCreatesValidAccounts(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	// Property 1a: Valid password always produces bcrypt hash
	properties.Property("valid password produces bcrypt hash", prop.ForAll(
		func(password string) bool {
			hash, err := HashPassword(password)
			if err != nil {
				return false
			}

			// Bcrypt hashes start with $2a$, $2b$, or $2y$
			return strings.HasPrefix(hash, "$2a$") ||
				strings.HasPrefix(hash, "$2b$") ||
				strings.HasPrefix(hash, "$2y$")
		},
		genValidPassword(),
	))

	// Property 1b: Bcrypt hash can verify original password
	properties.Property("bcrypt hash verifies original password", prop.ForAll(
		func(password string) bool {
			hash, err := HashPassword(password)
			if err != nil {
				return false
			}

			// CheckPassword should return true for original password
			return CheckPassword(password, hash)
		},
		genValidPassword(),
	))

	// Property 1c: Bcrypt hash rejects different passwords
	properties.Property("bcrypt hash rejects different passwords", prop.ForAll(
		func(password, differentPassword string) bool {
			if password == differentPassword {
				return true // Skip if passwords happen to be the same
			}

			hash, err := HashPassword(password)
			if err != nil {
				return false
			}

			// CheckPassword should return false for different password
			return !CheckPassword(differentPassword, hash)
		},
		genValidPassword(),
		genValidPassword(),
	))

	// Property 1d: JWT token has 24h expiration
	properties.Property("JWT token expires in 24 hours", prop.ForAll(
		func(userID, email string) bool {
			if userID == "" || email == "" {
				return true // Skip empty cases
			}

			now := time.Now()
			token, err := GenerateToken(userID, email)
			if err != nil {
				return false
			}

			// Parse the token to check expiration
			claims := &Claims{}
			parsedToken, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
				return JWTSecret, nil
			})
			if err != nil || !parsedToken.Valid {
				return false
			}

			// Expiration should be ~24 hours from now (allow 2 second tolerance for test execution)
			expectedExp := now.Add(24 * time.Hour)
			expTime := claims.ExpiresAt.Time

			diff := expTime.Sub(expectedExp)
			if diff < 0 {
				diff = -diff
			}
			return diff < 2*time.Second
		},
		genUserID(),
		genValidEmail(),
	))

	// Property 1e: JWT token contains correct user ID
	properties.Property("JWT token contains correct user ID", prop.ForAll(
		func(userID, email string) bool {
			if userID == "" || email == "" {
				return true
			}

			token, err := GenerateToken(userID, email)
			if err != nil {
				return false
			}

			claims := &Claims{}
			parsedToken, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
				return JWTSecret, nil
			})
			if err != nil || !parsedToken.Valid {
				return false
			}

			return claims.UserID == userID
		},
		genUserID(),
		genValidEmail(),
	))

	// Property 1f: JWT token contains correct email
	properties.Property("JWT token contains correct email", prop.ForAll(
		func(userID, email string) bool {
			if userID == "" || email == "" {
				return true
			}

			token, err := GenerateToken(userID, email)
			if err != nil {
				return false
			}

			claims := &Claims{}
			parsedToken, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
				return JWTSecret, nil
			})
			if err != nil || !parsedToken.Valid {
				return false
			}

			return claims.Email == email
		},
		genUserID(),
		genValidEmail(),
	))

	// Property 1g: JWT token has correct issuer
	properties.Property("JWT token has correct issuer", prop.ForAll(
		func(userID, email string) bool {
			if userID == "" || email == "" {
				return true
			}

			token, err := GenerateToken(userID, email)
			if err != nil {
				return false
			}

			claims := &Claims{}
			parsedToken, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
				return JWTSecret, nil
			})
			if err != nil || !parsedToken.Valid {
				return false
			}

			return claims.Issuer == "roxas"
		},
		genUserID(),
		genValidEmail(),
	))

	// Property 1h: Valid email passes validation
	properties.Property("valid email passes validation", prop.ForAll(
		func(email string) bool {
			err := ValidateEmail(email)
			return err == nil
		},
		genValidEmail(),
	))

	// Property 1i: Valid password passes validation
	properties.Property("valid password passes validation", prop.ForAll(
		func(password string) bool {
			err := ValidatePassword(password)
			return err == nil
		},
		genValidPassword(),
	))

	// Property 1j: Registration validation passes for valid email and password
	properties.Property("registration validation passes for valid inputs", prop.ForAll(
		func(email, password string) bool {
			err := ValidateRegistration(email, password)
			return err == nil
		},
		genValidEmail(),
		genValidPassword(),
	))

	// Property 1k: Each hash is unique (no collisions for same password)
	properties.Property("same password produces different hashes", prop.ForAll(
		func(password string) bool {
			hash1, err1 := HashPassword(password)
			hash2, err2 := HashPassword(password)
			if err1 != nil || err2 != nil {
				return false
			}

			// Bcrypt should produce different hashes due to random salt
			return hash1 != hash2
		},
		genValidPassword(),
	))

	// Property 1l: Hash uses correct bcrypt cost
	properties.Property("hash uses configured bcrypt cost", prop.ForAll(
		func(password string) bool {
			hash, err := HashPassword(password)
			if err != nil {
				return false
			}

			cost, err := bcrypt.Cost([]byte(hash))
			if err != nil {
				return false
			}

			return cost == BcryptCost
		},
		genValidPassword(),
	))

	properties.TestingRun(t)
}

// TestProperty1_PasswordValidationBoundary tests the 8 character boundary
func TestProperty1_PasswordValidationBoundary(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Property: Passwords with exactly 8 characters pass validation
	properties.Property("8 character password passes validation", prop.ForAll(
		func(password string) bool {
			err := ValidatePassword(password)
			return err == nil
		},
		genExactLengthPassword(8),
	))

	// Property: Passwords with 7 characters fail validation
	properties.Property("7 character password fails validation", prop.ForAll(
		func(password string) bool {
			err := ValidatePassword(password)
			return err == ErrWeakPassword
		},
		genExactLengthPassword(7),
	))

	// Property: Passwords longer than 8 characters pass validation
	properties.Property("passwords longer than 8 chars pass validation", prop.ForAll(
		func(password string) bool {
			err := ValidatePassword(password)
			return err == nil
		},
		genLongPassword(),
	))

	properties.TestingRun(t)
}

// TestProperty1_TokenExpirationConstant verifies the token expiration constant
func TestProperty1_TokenExpirationConstant(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Property: TokenExpiration constant equals 24 hours
	properties.Property("TokenExpiration equals 24 hours", prop.ForAll(
		func(_ int) bool {
			return TokenExpiration == 24*time.Hour
		},
		gen.IntRange(0, 100),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Generators
// =============================================================================

// genValidPassword generates valid passwords (≥8 characters, ASCII-safe for bcrypt)
// Bcrypt has a 72-byte limit, so we use ASCII characters only
func genValidPassword() gopter.Gen {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	return gen.IntRange(8, 64).FlatMap(func(length interface{}) gopter.Gen {
		return gen.SliceOfN(length.(int), gen.IntRange(0, len(chars)-1)).Map(func(indices []int) string {
			result := make([]byte, len(indices))
			for i, idx := range indices {
				result[i] = chars[idx]
			}
			return string(result)
		})
	}, reflect.TypeOf(""))
}

// genExactLengthPassword generates passwords of exact length
func genExactLengthPassword(length int) gopter.Gen {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	return gen.SliceOfN(length, gen.IntRange(0, len(chars)-1)).Map(func(indices []int) string {
		result := make([]byte, len(indices))
		for i, idx := range indices {
			result[i] = chars[idx]
		}
		return string(result)
	})
}

// genLongPassword generates passwords longer than 8 characters
func genLongPassword() gopter.Gen {
	return gen.IntRange(9, 64).FlatMap(func(length interface{}) gopter.Gen {
		return genExactLengthPassword(length.(int))
	}, reflect.TypeOf(""))
}

// genValidEmail generates valid email addresses
func genValidEmail() gopter.Gen {
	username := gen.RegexMatch(`[a-z][a-z0-9]{2,10}`)
	domain := gen.OneConstOf("example.com", "test.org", "mail.net", "company.io")

	return gopter.CombineGens(username, domain).Map(func(vals []interface{}) string {
		return vals[0].(string) + "@" + vals[1].(string)
	})
}

// genUserID generates valid user IDs (UUIDs or similar)
func genUserID() gopter.Gen {
	return gen.RegexMatch(`[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`)
}
