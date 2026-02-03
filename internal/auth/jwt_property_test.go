package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// Property Test: JWT Token Generation (Property 3)
// Validates Requirements 1.4, 1.6
//
// Property: For any successful authentication (registration or login), the system
// should generate a JWT token that expires exactly 24 hours from creation.

func TestProperty3_JWTTokenGeneration(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Property 3a: Token expiration is exactly 24 hours from IssuedAt
	properties.Property("token expires exactly 24 hours from creation", prop.ForAll(
		func(userID, email string) bool {
			token, err := GenerateToken(userID, email)
			if err != nil {
				return false
			}

			// Parse the token to extract claims
			parsed, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (interface{}, error) {
				return JWTSecret, nil
			})
			if err != nil {
				return false
			}

			claims, ok := parsed.Claims.(*Claims)
			if !ok {
				return false
			}

			// Verify ExpiresAt - IssuedAt == 24 hours exactly
			issuedAt := claims.IssuedAt.Time
			expiresAt := claims.ExpiresAt.Time
			duration := expiresAt.Sub(issuedAt)

			return duration == 24*time.Hour
		},
		genUserID(),
		genEmail(),
	))

	// Property 3b: Token is valid immediately after creation (not expired)
	properties.Property("token is valid immediately after creation", prop.ForAll(
		func(userID, email string) bool {
			token, err := GenerateToken(userID, email)
			if err != nil {
				return false
			}

			// ValidateToken should succeed for a freshly created token
			claims, err := ValidateToken(token)
			if err != nil {
				return false
			}

			return claims != nil
		},
		genUserID(),
		genEmail(),
	))

	// Property 3c: Token expiration time is in the future
	properties.Property("token expiration is in the future", prop.ForAll(
		func(userID, email string) bool {
			token, err := GenerateToken(userID, email)
			if err != nil {
				return false
			}

			parsed, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (interface{}, error) {
				return JWTSecret, nil
			})
			if err != nil {
				return false
			}

			claims, ok := parsed.Claims.(*Claims)
			if !ok {
				return false
			}

			// ExpiresAt should be in the future (at least 23 hours from now to allow for test execution time)
			return claims.ExpiresAt.Time.After(time.Now().Add(23 * time.Hour))
		},
		genUserID(),
		genEmail(),
	))

	// Property 3d: UserID and Email are preserved in claims
	properties.Property("token preserves user identity", prop.ForAll(
		func(userID, email string) bool {
			token, err := GenerateToken(userID, email)
			if err != nil {
				return false
			}

			claims, err := ValidateToken(token)
			if err != nil {
				return false
			}

			return claims.UserID == userID && claims.Email == email
		},
		genUserID(),
		genEmail(),
	))

	// Property 3e: Token issuer is always "roxas"
	properties.Property("token issuer is roxas", prop.ForAll(
		func(userID, email string) bool {
			token, err := GenerateToken(userID, email)
			if err != nil {
				return false
			}

			parsed, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (interface{}, error) {
				return JWTSecret, nil
			})
			if err != nil {
				return false
			}

			claims, ok := parsed.Claims.(*Claims)
			if !ok {
				return false
			}

			return claims.Issuer == "roxas"
		},
		genUserID(),
		genEmail(),
	))

	// Property 3f: Generated token is non-empty for any valid input
	properties.Property("generated token is non-empty", prop.ForAll(
		func(userID, email string) bool {
			token, err := GenerateToken(userID, email)
			if err != nil {
				return false
			}

			return len(token) > 0
		},
		genUserID(),
		genEmail(),
	))

	properties.TestingRun(t)
}

// genUserID generates random user IDs (UUIDs or alphanumeric strings)
func genUserID() gopter.Gen {
	return gen.RegexMatch(`[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`)
}

// genEmail generates random email addresses
func genEmail() gopter.Gen {
	username := gen.RegexMatch(`[a-z][a-z0-9]{2,10}`)
	domain := gen.OneConstOf("example.com", "test.org", "mail.net")

	return gopter.CombineGens(username, domain).Map(func(vals []interface{}) string {
		return vals[0].(string) + "@" + vals[1].(string)
	})
}
