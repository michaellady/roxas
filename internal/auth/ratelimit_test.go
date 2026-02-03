package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRateLimiter(t *testing.T) {
	rl := NewRateLimiter(5, 1, time.Minute)

	assert.NotNil(t, rl)
	assert.Equal(t, 5, rl.maxTokens)
	assert.Equal(t, 1, rl.refillRate)
	assert.Equal(t, time.Minute, rl.refillInterval)
	assert.NotNil(t, rl.buckets)
}

func TestDefaultAuthRateLimiter(t *testing.T) {
	rl := DefaultAuthRateLimiter()

	assert.NotNil(t, rl)
	assert.Equal(t, 5, rl.maxTokens)
	assert.Equal(t, 1, rl.refillRate)
	assert.Equal(t, time.Minute, rl.refillInterval)
}

func TestRateLimiter_Allow(t *testing.T) {
	t.Run("allows requests up to limit", func(t *testing.T) {
		rl := NewRateLimiter(3, 1, time.Hour)
		clientID := "192.168.1.1"

		// First 3 requests should be allowed
		assert.True(t, rl.Allow(clientID), "request 1 should be allowed")
		assert.True(t, rl.Allow(clientID), "request 2 should be allowed")
		assert.True(t, rl.Allow(clientID), "request 3 should be allowed")

		// 4th request should be blocked
		assert.False(t, rl.Allow(clientID), "request 4 should be blocked")
	})

	t.Run("rate limits are per client", func(t *testing.T) {
		rl := NewRateLimiter(2, 1, time.Hour)
		client1 := "192.168.1.1"
		client2 := "192.168.1.2"

		// Exhaust client1's limit
		assert.True(t, rl.Allow(client1))
		assert.True(t, rl.Allow(client1))
		assert.False(t, rl.Allow(client1), "client1 should be rate limited")

		// Client2 should still have full quota
		assert.True(t, rl.Allow(client2), "client2 should not be affected by client1")
		assert.True(t, rl.Allow(client2), "client2 should still have tokens")
	})

	t.Run("tokens replenish after interval", func(t *testing.T) {
		// Use very short interval for testing
		rl := NewRateLimiter(2, 1, 10*time.Millisecond)
		clientID := "192.168.1.1"

		// Use all tokens
		assert.True(t, rl.Allow(clientID))
		assert.True(t, rl.Allow(clientID))
		assert.False(t, rl.Allow(clientID), "should be rate limited")

		// Wait for replenishment
		time.Sleep(25 * time.Millisecond)

		// Should have 1-2 tokens replenished
		assert.True(t, rl.Allow(clientID), "should be allowed after replenishment")
	})

	t.Run("bucket never exceeds max tokens", func(t *testing.T) {
		rl := NewRateLimiter(3, 1, 5*time.Millisecond)
		clientID := "192.168.1.1"

		// Use one token
		rl.Allow(clientID)

		// Wait for lots of replenishment
		time.Sleep(50 * time.Millisecond)

		// Should have at most maxTokens
		remaining := rl.GetTokensRemaining(clientID)
		assert.LessOrEqual(t, remaining, 3, "tokens should not exceed max")
	})
}

func TestRateLimiter_Reset(t *testing.T) {
	rl := NewRateLimiter(2, 1, time.Hour)
	clientID := "192.168.1.1"

	// Exhaust limit
	rl.Allow(clientID)
	rl.Allow(clientID)
	assert.False(t, rl.Allow(clientID), "should be rate limited before reset")

	// Reset
	rl.Reset()

	// Should have full quota again
	assert.True(t, rl.Allow(clientID), "should be allowed after reset")
}

func TestRateLimiter_GetTokensRemaining(t *testing.T) {
	rl := NewRateLimiter(5, 1, time.Hour)
	clientID := "192.168.1.1"

	// New client should have max tokens
	assert.Equal(t, 5, rl.GetTokensRemaining(clientID))

	// Use some tokens
	rl.Allow(clientID)
	rl.Allow(clientID)

	assert.Equal(t, 3, rl.GetTokensRemaining(clientID))
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		expectedIP string
	}{
		{
			name:       "uses X-Forwarded-For when present",
			remoteAddr: "10.0.0.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "192.168.1.100"},
			expectedIP: "192.168.1.100",
		},
		{
			name:       "uses first IP from X-Forwarded-For chain",
			remoteAddr: "10.0.0.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "192.168.1.100, 10.0.0.50, 10.0.0.1"},
			expectedIP: "192.168.1.100",
		},
		{
			name:       "uses X-Real-IP when X-Forwarded-For absent",
			remoteAddr: "10.0.0.1:12345",
			headers:    map[string]string{"X-Real-IP": "192.168.1.200"},
			expectedIP: "192.168.1.200",
		},
		{
			name:       "X-Forwarded-For takes precedence over X-Real-IP",
			remoteAddr: "10.0.0.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.100",
				"X-Real-IP":       "192.168.1.200",
			},
			expectedIP: "192.168.1.100",
		},
		{
			name:       "falls back to RemoteAddr without port",
			remoteAddr: "192.168.1.50:12345",
			headers:    map[string]string{},
			expectedIP: "192.168.1.50",
		},
		{
			name:       "handles RemoteAddr without port",
			remoteAddr: "192.168.1.50",
			headers:    map[string]string{},
			expectedIP: "192.168.1.50",
		},
		{
			name:       "handles IPv6 with brackets and port",
			remoteAddr: "[::1]:12345",
			headers:    map[string]string{},
			expectedIP: "::1",
		},
		{
			name:       "trims whitespace from X-Forwarded-For",
			remoteAddr: "10.0.0.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "  192.168.1.100  "},
			expectedIP: "192.168.1.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			ip := GetClientIP(req)
			assert.Equal(t, tt.expectedIP, ip)
		})
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	t.Run("allows requests under limit", func(t *testing.T) {
		rl := NewRateLimiter(3, 1, time.Hour)
		handlerCalled := false
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		middleware := RateLimitMiddleware(rl)
		wrappedHandler := middleware(handler)

		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)

		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("blocks requests over limit with 429", func(t *testing.T) {
		rl := NewRateLimiter(1, 1, time.Hour)
		handlerCallCount := 0
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCallCount++
			w.WriteHeader(http.StatusOK)
		})

		middleware := RateLimitMiddleware(rl)
		wrappedHandler := middleware(handler)

		// First request - allowed
		req1 := httptest.NewRequest(http.MethodPost, "/login", nil)
		req1.RemoteAddr = "192.168.1.1:12345"
		rec1 := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rec1, req1)
		assert.Equal(t, http.StatusOK, rec1.Code)

		// Second request - blocked
		req2 := httptest.NewRequest(http.MethodPost, "/login", nil)
		req2.RemoteAddr = "192.168.1.1:12345"
		rec2 := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rec2, req2)
		assert.Equal(t, http.StatusTooManyRequests, rec2.Code)
		assert.Contains(t, rec2.Body.String(), "rate limit exceeded")
		assert.Equal(t, "60", rec2.Header().Get("Retry-After"))

		// Handler should only have been called once
		assert.Equal(t, 1, handlerCallCount)
	})
}

func TestCheckRateLimit(t *testing.T) {
	t.Run("returns true when no rate limiter configured", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		rec := httptest.NewRecorder()

		result := CheckRateLimit(nil, rec, req)

		assert.True(t, result)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("returns true when under limit", func(t *testing.T) {
		rl := NewRateLimiter(5, 1, time.Hour)
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()

		result := CheckRateLimit(rl, rec, req)

		assert.True(t, result)
	})

	t.Run("returns false and writes 429 when over limit", func(t *testing.T) {
		rl := NewRateLimiter(1, 1, time.Hour)

		// Use the one token
		req1 := httptest.NewRequest(http.MethodPost, "/login", nil)
		req1.RemoteAddr = "192.168.1.1:12345"
		rec1 := httptest.NewRecorder()
		CheckRateLimit(rl, rec1, req1)

		// Second request should be blocked
		req2 := httptest.NewRequest(http.MethodPost, "/login", nil)
		req2.RemoteAddr = "192.168.1.1:12345"
		rec2 := httptest.NewRecorder()

		result := CheckRateLimit(rl, rec2, req2)

		assert.False(t, result)
		assert.Equal(t, http.StatusTooManyRequests, rec2.Code)
		assert.Equal(t, "60", rec2.Header().Get("Retry-After"))
	})
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := NewRateLimiter(100, 1, time.Hour)
	clientID := "192.168.1.1"

	// Run many concurrent requests
	done := make(chan bool)
	allowedCount := 0
	blockedCount := 0
	mu := make(chan bool, 1)
	mu <- true // Initialize mutex

	for i := 0; i < 200; i++ {
		go func() {
			allowed := rl.Allow(clientID)
			<-mu
			if allowed {
				allowedCount++
			} else {
				blockedCount++
			}
			mu <- true
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 200; i++ {
		<-done
	}

	// Exactly 100 should be allowed (the limit)
	require.Equal(t, 100, allowedCount, "exactly maxTokens requests should be allowed")
	require.Equal(t, 100, blockedCount, "excess requests should be blocked")
}
