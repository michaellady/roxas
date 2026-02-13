package clients

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mikelady/roxas/internal/services"
)

// =============================================================================
// Test Fixtures
// =============================================================================

func newTestBlueskyServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

// =============================================================================
// createSession Tests
// =============================================================================

func TestBlueskyClient_CreateSession_Success(t *testing.T) {
	server := newTestBlueskyServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.URL.Path != "/xrpc/com.atproto.server.createSession" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json")
		}

		// Parse request body
		var req struct {
			Identifier string `json:"identifier"`
			Password   string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
		}
		if req.Identifier != "test.bsky.social" {
			t.Errorf("expected identifier test.bsky.social, got %s", req.Identifier)
		}
		if req.Password != "app-password-123" {
			t.Errorf("expected password app-password-123, got %s", req.Password)
		}

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"accessJwt":  "access-jwt-token",
			"refreshJwt": "refresh-jwt-token",
			"did":        "did:plc:abc123",
			"handle":     "test.bsky.social",
		})
	})
	defer server.Close()

	client := NewBlueskyClient("test.bsky.social", "app-password-123", server.URL)

	// createSession is called internally, so we test via Post which calls it
	// For now, we'll add a method to test auth directly
	err := client.Authenticate(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if client.GetDID() != "did:plc:abc123" {
		t.Errorf("expected DID did:plc:abc123, got %s", client.GetDID())
	}

	if !client.IsAuthenticated() {
		t.Error("expected client to be authenticated")
	}
}

func TestBlueskyClient_CreateSession_InvalidCredentials(t *testing.T) {
	server := newTestBlueskyServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "AuthenticationRequired",
			"message": "Invalid identifier or password",
		})
	})
	defer server.Close()

	client := NewBlueskyClient("bad.bsky.social", "wrong-password", server.URL)

	err := client.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid credentials")
	}

	if !client.IsAuthError(err) {
		t.Errorf("expected auth error, got %v", err)
	}
}

func TestBlueskyClient_CreateSession_ServerError(t *testing.T) {
	server := newTestBlueskyServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	})
	defer server.Close()

	client := NewBlueskyClient("test.bsky.social", "app-password-123", server.URL)

	err := client.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error for server error")
	}
}

// =============================================================================
// Post Tests
// =============================================================================

func TestBlueskyClient_Post_Success(t *testing.T) {
	callCount := 0
	server := newTestBlueskyServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/xrpc/com.atproto.server.createSession":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"accessJwt":  "access-jwt-token",
				"refreshJwt": "refresh-jwt-token",
				"did":        "did:plc:abc123",
				"handle":     "test.bsky.social",
			})

		case "/xrpc/com.atproto.repo.createRecord":
			// Verify authorization header
			auth := r.Header.Get("Authorization")
			if auth != "Bearer access-jwt-token" {
				t.Errorf("expected Bearer token, got %s", auth)
			}

			// Parse request
			var req struct {
				Repo       string                 `json:"repo"`
				Collection string                 `json:"collection"`
				Record     map[string]interface{} `json:"record"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("failed to decode request: %v", err)
			}

			if req.Repo != "did:plc:abc123" {
				t.Errorf("expected repo did:plc:abc123, got %s", req.Repo)
			}
			if req.Collection != "app.bsky.feed.post" {
				t.Errorf("expected collection app.bsky.feed.post, got %s", req.Collection)
			}
			if req.Record["text"] != "Hello from Roxas!" {
				t.Errorf("expected text 'Hello from Roxas!', got %v", req.Record["text"])
			}
			if req.Record["$type"] != "app.bsky.feed.post" {
				t.Errorf("expected $type app.bsky.feed.post, got %v", req.Record["$type"])
			}

			// Return success
			json.NewEncoder(w).Encode(map[string]interface{}{
				"uri": "at://did:plc:abc123/app.bsky.feed.post/3abc123",
				"cid": "bafyreiabc123",
			})

		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer server.Close()

	client := NewBlueskyClient("test.bsky.social", "app-password-123", server.URL)

	result, err := client.Post(context.Background(), services.PostContent{
		Text: "Hello from Roxas!",
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.PostID != "at://did:plc:abc123/app.bsky.feed.post/3abc123" {
		t.Errorf("unexpected post ID: %s", result.PostID)
	}

	// Should contain bsky.app URL
	if result.PostURL == "" {
		t.Error("expected post URL")
	}
}

func TestBlueskyClient_Post_RateLimited(t *testing.T) {
	server := newTestBlueskyServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/xrpc/com.atproto.server.createSession":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"accessJwt":  "access-jwt-token",
				"refreshJwt": "refresh-jwt-token",
				"did":        "did:plc:abc123",
				"handle":     "test.bsky.social",
			})

		case "/xrpc/com.atproto.repo.createRecord":
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "RateLimitExceeded",
				"message": "Rate limit exceeded",
			})
		}
	})
	defer server.Close()

	client := NewBlueskyClient("test.bsky.social", "app-password-123", server.URL)

	_, err := client.Post(context.Background(), services.PostContent{
		Text: "Hello!",
	})

	if err == nil {
		t.Fatal("expected rate limit error")
	}

	if !client.IsRateLimitError(err) {
		t.Errorf("expected rate limit error, got %v", err)
	}
}

func TestBlueskyClient_Post_AuthExpired(t *testing.T) {
	authAttempts := 0
	server := newTestBlueskyServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/xrpc/com.atproto.server.createSession":
			authAttempts++
			json.NewEncoder(w).Encode(map[string]interface{}{
				"accessJwt":  "access-jwt-token",
				"refreshJwt": "refresh-jwt-token",
				"did":        "did:plc:abc123",
				"handle":     "test.bsky.social",
			})

		case "/xrpc/com.atproto.repo.createRecord":
			// Return 401 to simulate expired token
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "ExpiredToken",
				"message": "Token has expired",
			})
		}
	})
	defer server.Close()

	client := NewBlueskyClient("test.bsky.social", "app-password-123", server.URL)

	_, err := client.Post(context.Background(), services.PostContent{
		Text: "Hello!",
	})

	if err == nil {
		t.Fatal("expected auth error")
	}
}

// =============================================================================
// ValidateContent Tests
// =============================================================================

func TestBlueskyClient_ValidateContent_Valid(t *testing.T) {
	client := NewBlueskyClient("test.bsky.social", "password", "")

	tests := []struct {
		name    string
		content services.PostContent
	}{
		{
			name:    "simple text",
			content: services.PostContent{Text: "Hello world!"},
		},
		{
			name:    "max length",
			content: services.PostContent{Text: string(make([]byte, 300))}, // 300 chars
		},
		{
			name:    "with emoji",
			content: services.PostContent{Text: "Hello 👋 world!"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.ValidateContent(tt.content)
			if err != nil {
				t.Errorf("expected valid content, got error: %v", err)
			}
		})
	}
}

func TestBlueskyClient_ValidateContent_TooLong(t *testing.T) {
	client := NewBlueskyClient("test.bsky.social", "password", "")

	content := services.PostContent{
		Text: string(make([]byte, 301)), // 301 chars - over limit
	}

	err := client.ValidateContent(content)
	if err == nil {
		t.Error("expected error for content over 300 chars")
	}
}

func TestBlueskyClient_ValidateContent_Empty(t *testing.T) {
	client := NewBlueskyClient("test.bsky.social", "password", "")

	content := services.PostContent{
		Text: "",
	}

	err := client.ValidateContent(content)
	if err == nil {
		t.Error("expected error for empty content")
	}
}

// =============================================================================
// Platform Tests
// =============================================================================

func TestBlueskyClient_Platform(t *testing.T) {
	client := NewBlueskyClient("test.bsky.social", "password", "")

	if client.Platform() != "bluesky" {
		t.Errorf("expected platform 'bluesky', got '%s'", client.Platform())
	}
}

// =============================================================================
// GetRateLimits Tests
// =============================================================================

func TestBlueskyClient_GetRateLimits(t *testing.T) {
	client := NewBlueskyClient("test.bsky.social", "password", "")

	limits := client.GetRateLimits()

	// Bluesky doesn't expose rate limits, so we return estimates
	if limits.Limit <= 0 {
		t.Error("expected positive limit")
	}
	if limits.Remaining < 0 {
		t.Error("expected non-negative remaining")
	}
	if limits.ResetAt.Before(time.Now()) {
		t.Error("expected future reset time")
	}
}

// =============================================================================
// URL Conversion Tests
// =============================================================================

func TestBlueskyClient_ATURIToWebURL(t *testing.T) {
	client := NewBlueskyClient("test.bsky.social", "password", "")

	tests := []struct {
		atURI    string
		expected string
	}{
		{
			atURI:    "at://did:plc:abc123/app.bsky.feed.post/3juzlwllznd24",
			expected: "https://bsky.app/profile/test.bsky.social/post/3juzlwllznd24",
		},
	}

	for _, tt := range tests {
		t.Run(tt.atURI, func(t *testing.T) {
			result := client.ATURIToWebURL(tt.atURI)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// =============================================================================
// Post with ThreadID Tests
// =============================================================================

func TestBlueskyClient_Post_WithReply(t *testing.T) {
	var receivedReply map[string]interface{}
	server := newTestBlueskyServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/xrpc/com.atproto.server.createSession":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"accessJwt":  "access-jwt-token",
				"refreshJwt": "refresh-jwt-token",
				"did":        "did:plc:abc123",
				"handle":     "test.bsky.social",
			})

		case "/xrpc/com.atproto.repo.createRecord":
			var req struct {
				Repo       string                 `json:"repo"`
				Collection string                 `json:"collection"`
				Record     map[string]interface{} `json:"record"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			if reply, ok := req.Record["reply"]; ok {
				receivedReply = reply.(map[string]interface{})
			}

			json.NewEncoder(w).Encode(map[string]interface{}{
				"uri": "at://did:plc:abc123/app.bsky.feed.post/reply123",
				"cid": "bafyreireply",
			})
		}
	})
	defer server.Close()

	client := NewBlueskyClient("test.bsky.social", "app-password-123", server.URL)

	threadID := "at://did:plc:parent/app.bsky.feed.post/parent123"
	result, err := client.Post(context.Background(), services.PostContent{
		Text:     "Reply post",
		ThreadID: &threadID,
	})

	if err != nil {
		t.Fatalf("Post() error = %v", err)
	}
	if result == nil {
		t.Fatal("Post() returned nil result")
	}
	if receivedReply == nil {
		t.Error("Expected reply object in record")
	}
}

func TestBlueskyClient_Post_ServerError(t *testing.T) {
	server := newTestBlueskyServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/xrpc/com.atproto.server.createSession":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"accessJwt":  "access-jwt-token",
				"refreshJwt": "refresh-jwt-token",
				"did":        "did:plc:abc123",
				"handle":     "test.bsky.social",
			})

		case "/xrpc/com.atproto.repo.createRecord":
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "InternalServerError",
				"message": "Something went wrong",
			})
		}
	})
	defer server.Close()

	client := NewBlueskyClient("test.bsky.social", "app-password-123", server.URL)

	_, err := client.Post(context.Background(), services.PostContent{
		Text: "Hello!",
	})

	if err == nil {
		t.Fatal("expected error for server error")
	}
}

func TestBlueskyClient_Post_InvalidResponseJSON(t *testing.T) {
	server := newTestBlueskyServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/xrpc/com.atproto.server.createSession":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"accessJwt":  "access-jwt-token",
				"refreshJwt": "refresh-jwt-token",
				"did":        "did:plc:abc123",
				"handle":     "test.bsky.social",
			})

		case "/xrpc/com.atproto.repo.createRecord":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("not valid json"))
		}
	})
	defer server.Close()

	client := NewBlueskyClient("test.bsky.social", "app-password-123", server.URL)

	_, err := client.Post(context.Background(), services.PostContent{
		Text: "Hello!",
	})

	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}

func TestBlueskyClient_CreateSession_BadRequestError(t *testing.T) {
	server := newTestBlueskyServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "InvalidRequest",
			"message": "Bad request",
		})
	})
	defer server.Close()

	client := NewBlueskyClient("test.bsky.social", "password", server.URL)
	err := client.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error for bad request")
	}
	if !client.IsAuthError(err) {
		t.Errorf("expected auth error, got %v", err)
	}
}

func TestBlueskyClient_CreateSession_InvalidResponseJSON(t *testing.T) {
	server := newTestBlueskyServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not valid json"))
	})
	defer server.Close()

	client := NewBlueskyClient("test.bsky.social", "password", server.URL)
	err := client.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestBlueskyClient_ATURIToWebURL_InvalidShortURI(t *testing.T) {
	client := NewBlueskyClient("test.bsky.social", "password", "")

	// Test with a URI that has fewer than 5 parts
	result := client.ATURIToWebURL("at://short")
	if result != "at://short" {
		t.Errorf("expected fallback to original URI, got %q", result)
	}

	result = client.ATURIToWebURL("")
	if result != "" {
		t.Errorf("expected empty string for empty input, got %q", result)
	}
}

// =============================================================================
// Context Cancellation Tests
// =============================================================================

func TestBlueskyClient_Post_ContextCancelled(t *testing.T) {
	server := newTestBlueskyServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	client := NewBlueskyClient("test.bsky.social", "password", server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := client.Post(ctx, services.PostContent{Text: "Hello!"})
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}
