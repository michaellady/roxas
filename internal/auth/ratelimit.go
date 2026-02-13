package auth

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter for auth endpoints.
// It tracks requests per client IP to prevent brute force attacks.
type RateLimiter struct {
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

// NewRateLimiter creates a new rate limiter with specified limits.
// maxTokens: Maximum requests allowed before rate limiting kicks in
// refillRate: Number of tokens to add per interval
// refillInterval: How often to add tokens
func NewRateLimiter(maxTokens, refillRate int, refillInterval time.Duration) *RateLimiter {
	return &RateLimiter{
		buckets:        make(map[string]*tokenBucket),
		maxTokens:      maxTokens,
		refillRate:     refillRate,
		refillInterval: refillInterval,
	}
}

// DefaultAuthRateLimiter creates a rate limiter with sensible defaults for auth endpoints.
// Allows 5 requests, then 1 request per minute.
func DefaultAuthRateLimiter() *RateLimiter {
	return NewRateLimiter(5, 1, time.Minute)
}

// Allow checks if a request from the given client should be allowed.
// Returns true if allowed, false if rate limited.
func (rl *RateLimiter) Allow(clientID string) bool {
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
	tokensToAdd := int(elapsed/rl.refillInterval) * rl.refillRate
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
func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.buckets = make(map[string]*tokenBucket)
}

// GetTokensRemaining returns remaining tokens for a client (for testing)
func (rl *RateLimiter) GetTokensRemaining(clientID string) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.buckets[clientID]
	if !exists {
		return rl.maxTokens
	}
	return bucket.tokens
}

// GetClientIP extracts the client IP from the request.
// It checks X-Forwarded-For header first (for proxied requests like AWS Lambda),
// then falls back to RemoteAddr.
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (common for proxies/load balancers)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one (original client)
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			clientIP := strings.TrimSpace(ips[0])
			if clientIP != "" {
				return clientIP
			}
		}
	}

	// Check X-Real-IP header (another common proxy header)
	xrip := r.Header.Get("X-Real-IP")
	if xrip != "" {
		return strings.TrimSpace(xrip)
	}

	// Fall back to RemoteAddr
	// RemoteAddr typically has format "IP:port" or just "IP"
	addr := r.RemoteAddr
	if colonIdx := strings.LastIndex(addr, ":"); colonIdx != -1 {
		// Check if this looks like an IPv6 address
		if strings.Count(addr, ":") > 1 {
			// IPv6 - if it has brackets, extract the IP
			if strings.HasPrefix(addr, "[") {
				if bracketIdx := strings.Index(addr, "]"); bracketIdx != -1 {
					return addr[1:bracketIdx]
				}
			}
			// IPv6 without brackets, return as-is
			return addr
		}
		// IPv4 with port, strip the port
		return addr[:colonIdx]
	}

	return addr
}

// RateLimitMiddleware creates a middleware that rate limits requests by client IP.
// When rate limited, it returns HTTP 429 Too Many Requests.
func RateLimitMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := GetClientIP(r)

			if !rl.Allow(clientIP) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"rate limit exceeded"}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CheckRateLimit checks if the request should be rate limited.
// Returns true if the request is allowed, false if rate limited.
// When rate limited, it writes the 429 response and the caller should return immediately.
func CheckRateLimit(rl *RateLimiter, w http.ResponseWriter, r *http.Request) bool {
	if rl == nil {
		return true // No rate limiter configured, allow all
	}

	clientIP := GetClientIP(r)

	if !rl.Allow(clientIP) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Too many requests. Please try again later.", http.StatusTooManyRequests)
		return false
	}

	return true
}
