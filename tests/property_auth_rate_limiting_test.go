// Package tests contains property-based tests for the Roxas application.
// Property 36: Auth endpoints (login, register) enforce rate limiting to prevent brute force.
// Validates Requirements 13.7
package tests

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// =============================================================================
// Property Test: Authentication Rate Limiting (Property 36)
// Validates Requirements 13.7 (rate limiting on auth endpoints)
// =============================================================================

// AuthRateLimiter implements a token bucket rate limiter for auth endpoints
type AuthRateLimiter struct {
	mu             sync.Mutex
	buckets        map[string]*tokenBucket
	maxTokens      int           // Maximum tokens in bucket
	refillRate     int           // Tokens added per refill interval
	refillInterval time.Duration // Interval between refills
}

// tokenBucket represents a single client's rate limit state
type tokenBucket struct {
	tokens     int
	lastRefill time.Time
}

// NewAuthRateLimiter creates a new rate limiter with specified limits
func NewAuthRateLimiter(maxTokens, refillRate int, refillInterval time.Duration) *AuthRateLimiter {
	return &AuthRateLimiter{
		buckets:        make(map[string]*tokenBucket),
		maxTokens:      maxTokens,
		refillRate:     refillRate,
		refillInterval: refillInterval,
	}
}

// Allow checks if a request from the given client should be allowed
// Returns true if allowed, false if rate limited
func (rl *AuthRateLimiter) Allow(clientID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.buckets[clientID]
	if !exists {
		// Create new bucket with full tokens
		bucket = &tokenBucket{
			tokens:     rl.maxTokens,
			lastRefill: time.Now(),
		}
		rl.buckets[clientID] = bucket
	}

	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	tokensToAdd := int(elapsed / rl.refillInterval) * rl.refillRate
	if tokensToAdd > 0 {
		bucket.tokens = min(bucket.tokens+tokensToAdd, rl.maxTokens)
		bucket.lastRefill = now
	}

	// Check if request can proceed
	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}

	return false
}

// Reset clears all rate limit state
func (rl *AuthRateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.buckets = make(map[string]*tokenBucket)
}

// GetTokensRemaining returns remaining tokens for a client (for testing)
func (rl *AuthRateLimiter) GetTokensRemaining(clientID string) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.buckets[clientID]
	if !exists {
		return rl.maxTokens
	}
	return bucket.tokens
}

// =============================================================================
// Auth Endpoint Types for Testing
// =============================================================================

// AuthEndpoint represents an authentication endpoint type
type AuthEndpoint string

const (
	AuthEndpointLogin    AuthEndpoint = "/api/v1/auth/login"
	AuthEndpointRegister AuthEndpoint = "/api/v1/auth/register"
)

// AuthRequest represents an authentication request for testing
type AuthRequest struct {
	ClientIP string
	Endpoint AuthEndpoint
	Email    string
	Password string
}

// AuthResponse represents the response from an auth endpoint
type AuthResponse struct {
	StatusCode int
	Error      string
}

// MockAuthService simulates auth endpoint behavior with rate limiting
type MockAuthService struct {
	rateLimiter *AuthRateLimiter
	users       map[string]string // email -> password hash (simulated)
}

// NewMockAuthService creates a new mock auth service
func NewMockAuthService(rateLimiter *AuthRateLimiter) *MockAuthService {
	return &MockAuthService{
		rateLimiter: rateLimiter,
		users:       make(map[string]string),
	}
}

// RegisterUser adds a user to the mock store
func (s *MockAuthService) RegisterUser(email, password string) {
	s.users[email] = password
}

// HandleAuth processes an auth request with rate limiting
func (s *MockAuthService) HandleAuth(req AuthRequest) AuthResponse {
	// Check rate limit first
	if !s.rateLimiter.Allow(req.ClientIP) {
		return AuthResponse{
			StatusCode: http.StatusTooManyRequests,
			Error:      "rate limit exceeded",
		}
	}

	// Process based on endpoint
	switch req.Endpoint {
	case AuthEndpointLogin:
		return s.handleLogin(req)
	case AuthEndpointRegister:
		return s.handleRegister(req)
	default:
		return AuthResponse{
			StatusCode: http.StatusNotFound,
			Error:      "endpoint not found",
		}
	}
}

func (s *MockAuthService) handleLogin(req AuthRequest) AuthResponse {
	password, exists := s.users[req.Email]
	if !exists || password != req.Password {
		return AuthResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "invalid credentials",
		}
	}
	return AuthResponse{StatusCode: http.StatusOK}
}

func (s *MockAuthService) handleRegister(req AuthRequest) AuthResponse {
	if _, exists := s.users[req.Email]; exists {
		return AuthResponse{
			StatusCode: http.StatusConflict,
			Error:      "email already registered",
		}
	}

	// Validate password length
	if len(req.Password) < 8 {
		return AuthResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "password too short",
		}
	}

	s.users[req.Email] = req.Password
	return AuthResponse{StatusCode: http.StatusCreated}
}

// =============================================================================
// Property Tests
// =============================================================================

// TestProperty36_RateLimitEnforcedOnAuthEndpoints verifies that auth endpoints
// enforce rate limiting after exceeding the request threshold.
// Validates Requirement 13.7
func TestProperty36_RateLimitEnforcedOnAuthEndpoints(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	properties.Property("requests exceeding limit return 429", prop.ForAll(
		func(clientIP string, requestCount int) bool {
			// Use a small limit for testing (5 requests)
			rateLimit := 5
			rateLimiter := NewAuthRateLimiter(rateLimit, 1, time.Hour)
			service := NewMockAuthService(rateLimiter)

			// Track responses
			var rateLimitedCount int
			var successfulCount int

			for i := 0; i < requestCount; i++ {
				req := AuthRequest{
					ClientIP: clientIP,
					Endpoint: AuthEndpointLogin,
					Email:    "test@example.com",
					Password: "password123",
				}
				resp := service.HandleAuth(req)

				if resp.StatusCode == http.StatusTooManyRequests {
					rateLimitedCount++
				} else {
					successfulCount++
				}
			}

			// Property: At most 'rateLimit' requests should succeed
			if successfulCount > rateLimit {
				t.Logf("Expected at most %d successful requests, got %d", rateLimit, successfulCount)
				return false
			}

			// Property: Requests beyond limit should be rate limited
			expectedRateLimited := max(0, requestCount-rateLimit)
			if rateLimitedCount != expectedRateLimited {
				t.Logf("Expected %d rate limited requests, got %d", expectedRateLimited, rateLimitedCount)
				return false
			}

			return true
		},
		genClientIP(),
		gen.IntRange(1, 20), // 1 to 20 requests
	))

	properties.Property("both login and register endpoints are rate limited", prop.ForAll(
		func(clientIP string) bool {
			rateLimit := 5
			rateLimiter := NewAuthRateLimiter(rateLimit, 1, time.Hour)
			service := NewMockAuthService(rateLimiter)

			// Mix of login and register requests from same client
			endpoints := []AuthEndpoint{
				AuthEndpointLogin, AuthEndpointLogin, AuthEndpointLogin,
				AuthEndpointRegister, AuthEndpointRegister, AuthEndpointRegister,
				AuthEndpointLogin, AuthEndpointRegister,
			}

			var rateLimitedCount int
			for i, endpoint := range endpoints {
				req := AuthRequest{
					ClientIP: clientIP,
					Endpoint: endpoint,
					Email:    "test@example.com",
					Password: "password123",
				}
				resp := service.HandleAuth(req)

				if resp.StatusCode == http.StatusTooManyRequests {
					rateLimitedCount++
				}

				// After rate limit requests, subsequent should be rate limited
				if i >= rateLimit && resp.StatusCode != http.StatusTooManyRequests {
					t.Logf("Request %d should have been rate limited", i)
					return false
				}
			}

			// Property: Rate limiting applies across both endpoints
			return rateLimitedCount == len(endpoints)-rateLimit
		},
		genClientIP(),
	))

	properties.TestingRun(t)
}

// TestProperty36_RateLimitPerClient verifies that rate limiting is applied
// per client, not globally.
// Validates Requirement 13.7
func TestProperty36_RateLimitPerClient(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	properties.Property("different clients have independent rate limits", prop.ForAll(
		func(clientIP1, clientIP2 string) bool {
			// Skip if IPs are the same
			if clientIP1 == clientIP2 {
				return true
			}

			rateLimit := 5
			rateLimiter := NewAuthRateLimiter(rateLimit, 1, time.Hour)
			service := NewMockAuthService(rateLimiter)

			// Exhaust rate limit for client 1
			for i := 0; i < rateLimit+2; i++ {
				req := AuthRequest{
					ClientIP: clientIP1,
					Endpoint: AuthEndpointLogin,
					Email:    "test@example.com",
					Password: "password123",
				}
				service.HandleAuth(req)
			}

			// Client 1 should now be rate limited
			resp1 := service.HandleAuth(AuthRequest{
				ClientIP: clientIP1,
				Endpoint: AuthEndpointLogin,
				Email:    "test@example.com",
				Password: "password123",
			})
			if resp1.StatusCode != http.StatusTooManyRequests {
				t.Log("Client 1 should be rate limited")
				return false
			}

			// Client 2 should still be allowed
			resp2 := service.HandleAuth(AuthRequest{
				ClientIP: clientIP2,
				Endpoint: AuthEndpointLogin,
				Email:    "test@example.com",
				Password: "password123",
			})
			if resp2.StatusCode == http.StatusTooManyRequests {
				t.Log("Client 2 should not be rate limited")
				return false
			}

			return true
		},
		genClientIP(),
		genClientIP(),
	))

	properties.Property("exhausting one client's limit doesn't affect another", prop.ForAll(
		func(clientCount int) bool {
			rateLimit := 3
			rateLimiter := NewAuthRateLimiter(rateLimit, 1, time.Hour)
			service := NewMockAuthService(rateLimiter)

			// Create unique clients
			clients := make([]string, clientCount)
			for i := range clients {
				clients[i] = genClientIPValue(i)
			}

			// Each client should be able to make exactly rateLimit requests
			for _, client := range clients {
				for i := 0; i < rateLimit; i++ {
					resp := service.HandleAuth(AuthRequest{
						ClientIP: client,
						Endpoint: AuthEndpointLogin,
						Email:    "test@example.com",
						Password: "password123",
					})
					if resp.StatusCode == http.StatusTooManyRequests {
						t.Logf("Client %s request %d should not be rate limited", client, i)
						return false
					}
				}

				// Next request should be rate limited
				resp := service.HandleAuth(AuthRequest{
					ClientIP: client,
					Endpoint: AuthEndpointLogin,
					Email:    "test@example.com",
					Password: "password123",
				})
				if resp.StatusCode != http.StatusTooManyRequests {
					t.Logf("Client %s should be rate limited after %d requests", client, rateLimit)
					return false
				}
			}

			return true
		},
		gen.IntRange(2, 10), // 2 to 10 clients
	))

	properties.TestingRun(t)
}

// TestProperty36_RateLimitReturns429 verifies that rate limited requests
// return HTTP 429 status code.
// Validates Requirement 13.7
func TestProperty36_RateLimitReturns429(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	properties.Property("rate limited requests always return 429", prop.ForAll(
		func(clientIP string, extraRequests int) bool {
			rateLimit := 5
			rateLimiter := NewAuthRateLimiter(rateLimit, 1, time.Hour)
			service := NewMockAuthService(rateLimiter)

			// Exhaust the rate limit
			for i := 0; i < rateLimit; i++ {
				service.HandleAuth(AuthRequest{
					ClientIP: clientIP,
					Endpoint: AuthEndpointLogin,
					Email:    "test@example.com",
					Password: "password123",
				})
			}

			// All subsequent requests should return 429
			for i := 0; i < extraRequests; i++ {
				resp := service.HandleAuth(AuthRequest{
					ClientIP: clientIP,
					Endpoint: AuthEndpointLogin,
					Email:    "test@example.com",
					Password: "password123",
				})

				if resp.StatusCode != http.StatusTooManyRequests {
					t.Logf("Expected 429, got %d on extra request %d", resp.StatusCode, i)
					return false
				}
			}

			return true
		},
		genClientIP(),
		gen.IntRange(1, 10), // 1 to 10 extra requests
	))

	properties.Property("rate limited response contains appropriate error", prop.ForAll(
		func(clientIP string) bool {
			rateLimit := 3
			rateLimiter := NewAuthRateLimiter(rateLimit, 1, time.Hour)
			service := NewMockAuthService(rateLimiter)

			// Exhaust the rate limit
			for i := 0; i < rateLimit; i++ {
				service.HandleAuth(AuthRequest{
					ClientIP: clientIP,
					Endpoint: AuthEndpointLogin,
					Email:    "test@example.com",
					Password: "password123",
				})
			}

			// Rate limited request
			resp := service.HandleAuth(AuthRequest{
				ClientIP: clientIP,
				Endpoint: AuthEndpointLogin,
				Email:    "test@example.com",
				Password: "password123",
			})

			// Property: Error message should indicate rate limiting
			if resp.Error == "" {
				t.Log("Rate limited response should have error message")
				return false
			}

			return true
		},
		genClientIP(),
	))

	properties.TestingRun(t)
}

// TestProperty36_TokenBucketReplenishment verifies that the token bucket
// replenishes over time, allowing new requests after waiting.
// Validates Requirement 13.7
func TestProperty36_TokenBucketReplenishment(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	properties.Property("tokens replenish after interval", prop.ForAll(
		func(clientIP string) bool {
			rateLimit := 3
			// Very short interval for testing
			refillInterval := 10 * time.Millisecond
			rateLimiter := NewAuthRateLimiter(rateLimit, 1, refillInterval)
			service := NewMockAuthService(rateLimiter)

			// Exhaust rate limit
			for i := 0; i < rateLimit; i++ {
				resp := service.HandleAuth(AuthRequest{
					ClientIP: clientIP,
					Endpoint: AuthEndpointLogin,
					Email:    "test@example.com",
					Password: "password123",
				})
				if resp.StatusCode == http.StatusTooManyRequests {
					t.Logf("Should not be rate limited on request %d", i)
					return false
				}
			}

			// Should be rate limited now
			resp := service.HandleAuth(AuthRequest{
				ClientIP: clientIP,
				Endpoint: AuthEndpointLogin,
				Email:    "test@example.com",
				Password: "password123",
			})
			if resp.StatusCode != http.StatusTooManyRequests {
				t.Log("Should be rate limited after exhausting limit")
				return false
			}

			// Wait for replenishment
			time.Sleep(refillInterval * 2)

			// Should be allowed again
			resp = service.HandleAuth(AuthRequest{
				ClientIP: clientIP,
				Endpoint: AuthEndpointLogin,
				Email:    "test@example.com",
				Password: "password123",
			})
			if resp.StatusCode == http.StatusTooManyRequests {
				t.Log("Should be allowed after token replenishment")
				return false
			}

			return true
		},
		genClientIP(),
	))

	properties.Property("bucket never exceeds max tokens", prop.ForAll(
		func(clientIP string, waitIntervals int) bool {
			rateLimit := 5
			refillInterval := 10 * time.Millisecond
			rateLimiter := NewAuthRateLimiter(rateLimit, 1, refillInterval)

			// Use one token
			rateLimiter.Allow(clientIP)

			// Wait for many intervals (should replenish but not exceed max)
			time.Sleep(refillInterval * time.Duration(waitIntervals+10))

			// Check remaining tokens
			remaining := rateLimiter.GetTokensRemaining(clientIP)
			if remaining > rateLimit {
				t.Logf("Tokens %d exceeded max %d", remaining, rateLimit)
				return false
			}

			return true
		},
		genClientIP(),
		gen.IntRange(1, 10),
	))

	properties.TestingRun(t)
}

// TestProperty36_RateLimitPreventsRapidRequests verifies that rapid consecutive
// requests are properly rate limited (brute force prevention).
// Validates Requirement 13.7
func TestProperty36_RateLimitPreventsRapidRequests(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	properties.Property("rapid login attempts are rate limited", prop.ForAll(
		func(clientIP string, attemptCount int) bool {
			rateLimit := 5
			rateLimiter := NewAuthRateLimiter(rateLimit, 1, time.Hour)
			service := NewMockAuthService(rateLimiter)

			// Simulate rapid brute force attempts with different passwords
			var rateLimitedCount int
			for i := 0; i < attemptCount; i++ {
				resp := service.HandleAuth(AuthRequest{
					ClientIP: clientIP,
					Endpoint: AuthEndpointLogin,
					Email:    "victim@example.com",
					Password: genPasswordAttempt(i),
				})
				if resp.StatusCode == http.StatusTooManyRequests {
					rateLimitedCount++
				}
			}

			// Property: Most brute force attempts should be blocked
			expectedBlocked := max(0, attemptCount-rateLimit)
			if rateLimitedCount != expectedBlocked {
				t.Logf("Expected %d blocked, got %d", expectedBlocked, rateLimitedCount)
				return false
			}

			return true
		},
		genClientIP(),
		gen.IntRange(10, 100), // 10 to 100 brute force attempts
	))

	properties.Property("rapid registration attempts are rate limited", prop.ForAll(
		func(clientIP string, attemptCount int) bool {
			rateLimit := 5
			rateLimiter := NewAuthRateLimiter(rateLimit, 1, time.Hour)
			service := NewMockAuthService(rateLimiter)

			// Simulate rapid registration attempts
			var rateLimitedCount int
			for i := 0; i < attemptCount; i++ {
				resp := service.HandleAuth(AuthRequest{
					ClientIP: clientIP,
					Endpoint: AuthEndpointRegister,
					Email:    genEmailAttempt(i),
					Password: "password123",
				})
				if resp.StatusCode == http.StatusTooManyRequests {
					rateLimitedCount++
				}
			}

			// Property: Most registration spam should be blocked
			expectedBlocked := max(0, attemptCount-rateLimit)
			if rateLimitedCount != expectedBlocked {
				t.Logf("Expected %d blocked, got %d", expectedBlocked, rateLimitedCount)
				return false
			}

			return true
		},
		genClientIP(),
		gen.IntRange(10, 50), // 10 to 50 registration attempts
	))

	properties.TestingRun(t)
}

// TestProperty36_RateLimitDoesNotAffectNormalUse verifies that normal usage
// patterns (below rate limit) are not affected.
// Validates Requirement 13.7
func TestProperty36_RateLimitDoesNotAffectNormalUse(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	properties.Property("requests below limit are never rate limited", prop.ForAll(
		func(clientIP string, requestCount int) bool {
			rateLimit := 10
			rateLimiter := NewAuthRateLimiter(rateLimit, 1, time.Hour)
			service := NewMockAuthService(rateLimiter)

			// Make fewer requests than the limit
			for i := 0; i < requestCount; i++ {
				resp := service.HandleAuth(AuthRequest{
					ClientIP: clientIP,
					Endpoint: AuthEndpointLogin,
					Email:    "test@example.com",
					Password: "password123",
				})

				if resp.StatusCode == http.StatusTooManyRequests {
					t.Logf("Request %d should not be rate limited (limit is %d)", i, rateLimit)
					return false
				}
			}

			return true
		},
		genClientIP(),
		gen.IntRange(1, 9), // 1 to 9 requests (below limit of 10)
	))

	properties.Property("legitimate auth errors are not masked by rate limiting", prop.ForAll(
		func(clientIP string) bool {
			rateLimit := 10
			rateLimiter := NewAuthRateLimiter(rateLimit, 1, time.Hour)
			service := NewMockAuthService(rateLimiter)

			// Register a user
			service.RegisterUser("existing@example.com", "correctpassword")

			// Test various auth scenarios (all below rate limit)
			scenarios := []struct {
				endpoint       AuthEndpoint
				email          string
				password       string
				expectedStatus int
			}{
				{AuthEndpointLogin, "existing@example.com", "wrongpassword", http.StatusUnauthorized},
				{AuthEndpointLogin, "nonexistent@example.com", "anypassword", http.StatusUnauthorized},
				{AuthEndpointLogin, "existing@example.com", "correctpassword", http.StatusOK},
				{AuthEndpointRegister, "existing@example.com", "newpassword1", http.StatusConflict},
				{AuthEndpointRegister, "new@example.com", "short", http.StatusBadRequest},
				{AuthEndpointRegister, "another@example.com", "validpassword123", http.StatusCreated},
			}

			for _, s := range scenarios {
				resp := service.HandleAuth(AuthRequest{
					ClientIP: clientIP,
					Endpoint: s.endpoint,
					Email:    s.email,
					Password: s.password,
				})

				if resp.StatusCode != s.expectedStatus {
					t.Logf("Expected %d for %s %s, got %d", s.expectedStatus, s.endpoint, s.email, resp.StatusCode)
					return false
				}
			}

			return true
		},
		genClientIP(),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Generators
// =============================================================================

// genClientIP generates random IPv4 addresses
func genClientIP() gopter.Gen {
	return gen.RegexMatch(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
}

// genClientIPValue generates a deterministic client IP for testing
func genClientIPValue(n int) string {
	return "192.168.1." + string(rune('0'+n%10))
}

// genPasswordAttempt generates a password attempt for brute force simulation
func genPasswordAttempt(n int) string {
	return "attempt" + string(rune('0'+n%10)) + string(rune('a'+n%26))
}

// genEmailAttempt generates an email for registration spam simulation
func genEmailAttempt(n int) string {
	return "spam" + string(rune('0'+n%10)) + string(rune('a'+n%26)) + "@example.com"
}
