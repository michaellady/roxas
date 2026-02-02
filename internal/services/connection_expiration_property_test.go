package services

import (
	"context"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// =============================================================================
// Property Test: Token Expiration Status (Property 32)
// Validates Requirements 11.3, 11.4
//
// Property: Credentials expiring within 7 days marked 'expiring soon',
// past expiration marked 'expired'.
// =============================================================================

func TestProperty32_TokenExpirationStatus(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Property 32a: Tokens past expiration have status 'expired'
	properties.Property("expired tokens have status 'expired'", prop.ForAll(
		func(minutesPastExpiry int) bool {
			// Create a credential that expired some time ago
			expiredTime := time.Now().Add(-time.Duration(minutesPastExpiry) * time.Minute)
			creds := &PlatformCredentials{
				UserID:         "test-user",
				Platform:       PlatformLinkedIn,
				AccessToken:    "test-token",
				TokenExpiresAt: &expiredTime,
			}

			// Verify IsExpired returns true
			if !creds.IsExpired() {
				return false
			}

			// Convert to connection and verify status
			credStore := NewMockCredentialStore()
			svc := NewConnectionService(ConnectionServiceConfig{
				CredentialStore: credStore,
			})
			conn := svc.credentialsToConnection(creds)

			return conn.Status == ConnectionStatusExpired
		},
		gen.IntRange(1, 10080), // 1 minute to 7 days past expiry
	))

	// Property 32b: Tokens expiring within 7 days have ExpiresSoon() == true
	properties.Property("tokens expiring within 7 days are marked 'expiring soon'", prop.ForAll(
		func(minutesUntilExpiry int) bool {
			// Create a credential expiring within 7 days (but not yet expired)
			expiryTime := time.Now().Add(time.Duration(minutesUntilExpiry) * time.Minute)
			conn := &Connection{
				UserID:    "test-user",
				Platform:  PlatformLinkedIn,
				Status:    ConnectionStatusConnected,
				ExpiresAt: &expiryTime,
			}

			// ExpiresSoon should return true for tokens expiring within 7 days
			return conn.ExpiresSoon()
		},
		gen.IntRange(1, 10079), // 1 minute to just under 7 days (7*24*60 - 1 minutes)
	))

	// Property 32c: Tokens expiring beyond 7 days have ExpiresSoon() == false
	properties.Property("tokens expiring beyond 7 days are not marked 'expiring soon'", prop.ForAll(
		func(daysUntilExpiry int) bool {
			// Create a credential expiring beyond 7 days
			expiryTime := time.Now().Add(time.Duration(daysUntilExpiry) * 24 * time.Hour)
			conn := &Connection{
				UserID:    "test-user",
				Platform:  PlatformLinkedIn,
				Status:    ConnectionStatusConnected,
				ExpiresAt: &expiryTime,
			}

			// ExpiresSoon should return false for tokens expiring beyond 7 days
			return !conn.ExpiresSoon()
		},
		gen.IntRange(8, 365), // 8 days to 1 year in the future
	))

	// Property 32d: Tokens with no expiry never marked 'expiring soon' or 'expired'
	properties.Property("tokens with no expiry are never marked expiring or expired", prop.ForAll(
		func(platform string) bool {
			// Create a credential with no expiry
			creds := &PlatformCredentials{
				UserID:         "test-user",
				Platform:       platform,
				AccessToken:    "test-token",
				TokenExpiresAt: nil, // No expiry
			}

			// Verify IsExpired returns false
			if creds.IsExpired() {
				return false
			}

			// Verify ExpiresWithin returns false for any duration
			if creds.ExpiresWithin(7 * 24 * time.Hour) {
				return false
			}

			// Convert to connection and verify status is connected (not expired)
			credStore := NewMockCredentialStore()
			svc := NewConnectionService(ConnectionServiceConfig{
				CredentialStore: credStore,
			})
			conn := svc.credentialsToConnection(creds)

			if conn.Status != ConnectionStatusConnected {
				return false
			}

			// Also check that ExpiresSoon returns false for nil expiry
			if conn.ExpiresSoon() {
				return false
			}

			return true
		},
		gen.OneConstOf(PlatformLinkedIn, PlatformTwitter, PlatformInstagram, PlatformBluesky, PlatformThreads),
	))

	// Property 32e: Boundary test - exactly 7 days is still 'expiring soon'
	properties.Property("tokens expiring in exactly 7 days are marked 'expiring soon'", prop.ForAll(
		func(secondsOffset int) bool {
			// Create a credential expiring at exactly 7 days minus some seconds
			// (to ensure we're still within the 7-day window)
			sevenDays := 7 * 24 * time.Hour
			offset := time.Duration(secondsOffset) * time.Second
			expiryTime := time.Now().Add(sevenDays - offset)

			conn := &Connection{
				UserID:    "test-user",
				Platform:  PlatformLinkedIn,
				Status:    ConnectionStatusConnected,
				ExpiresAt: &expiryTime,
			}

			// ExpiresSoon should return true when within 7 days
			return conn.ExpiresSoon()
		},
		gen.IntRange(1, 3600), // 1 second to 1 hour offset from 7 days
	))

	// Property 32f: Connection service correctly propagates expiration status
	properties.Property("connection service correctly sets expired status from credentials", prop.ForAll(
		func(hoursOffset int) bool {
			credStore := NewMockCredentialStore()
			svc := NewConnectionService(ConnectionServiceConfig{
				CredentialStore: credStore,
			})

			ctx := context.Background()
			userID := "test-user"

			// Create credential expired by given hours
			expiredTime := time.Now().Add(-time.Duration(hoursOffset) * time.Hour)
			creds := &PlatformCredentials{
				UserID:         userID,
				Platform:       PlatformLinkedIn,
				AccessToken:    "expired-token",
				TokenExpiresAt: &expiredTime,
			}
			credStore.SaveCredentials(ctx, creds)

			// Get connection through service
			conn, err := svc.GetConnection(ctx, userID, PlatformLinkedIn)
			if err != nil {
				return false
			}

			// Verify status is expired
			return conn.Status == ConnectionStatusExpired
		},
		gen.IntRange(1, 720), // 1 hour to 30 days past expiry
	))

	// Property 32g: Valid (non-expired) credentials have 'connected' status
	properties.Property("valid credentials have 'connected' status", prop.ForAll(
		func(hoursUntilExpiry int) bool {
			credStore := NewMockCredentialStore()
			svc := NewConnectionService(ConnectionServiceConfig{
				CredentialStore: credStore,
			})

			ctx := context.Background()
			userID := "test-user"

			// Create credential that expires in the future
			expiryTime := time.Now().Add(time.Duration(hoursUntilExpiry) * time.Hour)
			creds := &PlatformCredentials{
				UserID:         userID,
				Platform:       PlatformTwitter,
				AccessToken:    "valid-token",
				TokenExpiresAt: &expiryTime,
			}
			credStore.SaveCredentials(ctx, creds)

			// Get connection through service
			conn, err := svc.GetConnection(ctx, userID, PlatformTwitter)
			if err != nil {
				return false
			}

			// Verify status is connected (not expired)
			return conn.Status == ConnectionStatusConnected
		},
		gen.IntRange(1, 8760), // 1 hour to 1 year in the future
	))

	// Property 32h: ExpiresSoon boundary precision at exactly 7 days + 1 minute
	properties.Property("tokens expiring at 7 days + 1 minute are NOT marked 'expiring soon'", prop.ForAll(
		func(extraMinutes int) bool {
			// Create a credential expiring beyond 7 days
			sevenDays := 7 * 24 * time.Hour
			extra := time.Duration(extraMinutes) * time.Minute
			expiryTime := time.Now().Add(sevenDays + extra)

			conn := &Connection{
				UserID:    "test-user",
				Platform:  PlatformLinkedIn,
				Status:    ConnectionStatusConnected,
				ExpiresAt: &expiryTime,
			}

			// ExpiresSoon should return false when beyond 7 days
			return !conn.ExpiresSoon()
		},
		gen.IntRange(1, 10080), // 1 minute to 7 days beyond the 7-day mark
	))

	properties.TestingRun(t)
}

// TestProperty32_PlatformCredentialsExpiration tests the PlatformCredentials
// expiration methods directly
func TestProperty32_PlatformCredentialsExpiration(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100

	properties := gopter.NewProperties(parameters)

	// Property: IsExpired is consistent with ExpiresWithin(0)
	properties.Property("IsExpired consistent with time.Now comparison", prop.ForAll(
		func(secondsOffset int) bool {
			var expiryTime time.Time
			if secondsOffset > 0 {
				expiryTime = time.Now().Add(time.Duration(secondsOffset) * time.Second)
			} else {
				expiryTime = time.Now().Add(time.Duration(secondsOffset) * time.Second)
			}

			creds := &PlatformCredentials{
				TokenExpiresAt: &expiryTime,
			}

			// IsExpired should return true only when expiry is in the past
			isExpired := creds.IsExpired()
			expectedExpired := time.Now().After(expiryTime)

			return isExpired == expectedExpired
		},
		gen.IntRange(-3600, 3600), // 1 hour past to 1 hour future
	))

	// Property: ExpiresWithin is monotonic - if expires within X, also expires within X+Y
	properties.Property("ExpiresWithin is monotonic", prop.ForAll(
		func(hoursUntilExpiry, testHours1, testHours2 int) bool {
			expiryTime := time.Now().Add(time.Duration(hoursUntilExpiry) * time.Hour)
			creds := &PlatformCredentials{
				TokenExpiresAt: &expiryTime,
			}

			// Ensure testHours1 < testHours2
			if testHours1 > testHours2 {
				testHours1, testHours2 = testHours2, testHours1
			}

			d1 := time.Duration(testHours1) * time.Hour
			d2 := time.Duration(testHours2) * time.Hour

			expiresWithin1 := creds.ExpiresWithin(d1)
			expiresWithin2 := creds.ExpiresWithin(d2)

			// If expires within shorter duration, must also expire within longer duration
			if expiresWithin1 && !expiresWithin2 {
				return false
			}

			return true
		},
		gen.IntRange(1, 720),  // 1-720 hours until expiry
		gen.IntRange(1, 168),  // Test duration 1: 1-168 hours (1 week)
		gen.IntRange(1, 336),  // Test duration 2: 1-336 hours (2 weeks)
	))

	properties.TestingRun(t)
}

// TestProperty32_ConnectionExpiresSoonEdgeCases tests edge cases for ExpiresSoon
func TestProperty32_ConnectionExpiresSoonEdgeCases(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50

	properties := gopter.NewProperties(parameters)

	// Property: ExpiresSoon returns false for already expired tokens
	properties.Property("ExpiresSoon returns false for already expired tokens", prop.ForAll(
		func(minutesPastExpiry int) bool {
			expiredTime := time.Now().Add(-time.Duration(minutesPastExpiry) * time.Minute)
			conn := &Connection{
				UserID:    "test-user",
				Platform:  PlatformLinkedIn,
				Status:    ConnectionStatusExpired,
				ExpiresAt: &expiredTime,
			}

			// ExpiresSoon should return false for already expired tokens
			// (time.Until returns negative, so condition > 0 fails)
			return !conn.ExpiresSoon()
		},
		gen.IntRange(1, 10080), // 1 minute to 7 days past expiry
	))

	// Property: IsHealthy returns false when expired, regardless of Status field
	properties.Property("IsHealthy returns false when token is past expiry", prop.ForAll(
		func(minutesPastExpiry int) bool {
			expiredTime := time.Now().Add(-time.Duration(minutesPastExpiry) * time.Minute)

			// Even if status is incorrectly set to Connected, IsHealthy should return false
			conn := &Connection{
				UserID:    "test-user",
				Platform:  PlatformLinkedIn,
				Status:    ConnectionStatusConnected, // Intentionally wrong
				ExpiresAt: &expiredTime,
			}

			return !conn.IsHealthy()
		},
		gen.IntRange(1, 10080),
	))

	properties.TestingRun(t)
}
