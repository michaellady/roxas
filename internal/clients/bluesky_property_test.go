package clients

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/mikelady/roxas/internal/services"
)

// =============================================================================
// Property 25: Bluesky Post Creation
// =============================================================================

// genValidPostContent generates valid post content (1-300 characters)
func genValidPostContent() gopter.Gen {
	return gen.RegexMatch(`[a-zA-Z0-9 .,!?]{1,50}`)
}

// genBlueskyHandle generates random Bluesky handles
func genBlueskyHandle() gopter.Gen {
	username := gen.RegexMatch(`[a-z][a-z0-9]{2,15}`)
	domain := gen.OneConstOf("bsky.social", "bsky.app", "example.com")

	return gopter.CombineGens(username, domain).Map(func(vals []interface{}) string {
		return vals[0].(string) + "." + vals[1].(string)
	})
}

// genAppPassword generates random Bluesky app passwords
func genAppPassword() gopter.Gen {
	return gen.RegexMatch(`[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}`)
}

// genBlueskyDID generates random Bluesky DIDs
func genBlueskyDID() gopter.Gen {
	identifier := gen.RegexMatch(`[a-z2-7]{24}`)
	return identifier.Map(func(id string) string {
		return "did:plc:" + id
	})
}

// genRecordKey generates random record keys (rkey)
func genRecordKey() gopter.Gen {
	return gen.RegexMatch(`[a-z0-9]{10,15}`)
}

// blueskyMockServer tracks calls to the Bluesky API for verification
type blueskyMockServer struct {
	mu                  sync.Mutex
	createSessionCalled bool
	createRecordCalled  bool
	lastRecordRequest   map[string]interface{}
	handle              string
	appPassword         string
	did                 string
	rkey                string
}

func (m *blueskyMockServer) handler(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")

	switch r.URL.Path {
	case "/xrpc/com.atproto.server.createSession":
		m.createSessionCalled = true

		var req struct {
			Identifier string `json:"identifier"`
			Password   string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			if req.Identifier != m.handle || req.Password != m.appPassword {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":   "AuthenticationRequired",
					"message": "Invalid identifier or password",
				})
				return
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"accessJwt":  "test-access-jwt-token",
			"refreshJwt": "test-refresh-jwt-token",
			"did":        m.did,
			"handle":     m.handle,
		})

	case "/xrpc/com.atproto.repo.createRecord":
		m.createRecordCalled = true

		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-access-jwt-token" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "InvalidToken",
				"message": "Invalid or missing authorization",
			})
			return
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			m.lastRecordRequest = req
		}

		atURI := "at://" + m.did + "/app.bsky.feed.post/" + m.rkey
		json.NewEncoder(w).Encode(map[string]interface{}{
			"uri": atURI,
			"cid": "bafyrei" + m.rkey,
		})

	default:
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "NotFound",
			"message": "Unknown endpoint",
		})
	}
}

func TestProperty25_BlueskyPostCreation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 300

	properties := gopter.NewProperties(parameters)

	properties.Property("posting valid content creates a session", prop.ForAll(
		func(content, handle, appPassword, did, rkey string) bool {
			mock := &blueskyMockServer{
				handle:      handle,
				appPassword: appPassword,
				did:         did,
				rkey:        rkey,
			}
			server := httptest.NewServer(http.HandlerFunc(mock.handler))
			defer server.Close()

			client := NewBlueskyClient(handle, appPassword, server.URL)
			_, err := client.Post(context.Background(), services.PostContent{Text: content})

			if err != nil {
				t.Logf("Post failed: %v", err)
				return false
			}

			mock.mu.Lock()
			defer mock.mu.Unlock()
			return mock.createSessionCalled
		},
		genValidPostContent(),
		genBlueskyHandle(),
		genAppPassword(),
		genBlueskyDID(),
		genRecordKey(),
	))

	properties.Property("posting valid content calls createRecord", prop.ForAll(
		func(content, handle, appPassword, did, rkey string) bool {
			mock := &blueskyMockServer{
				handle:      handle,
				appPassword: appPassword,
				did:         did,
				rkey:        rkey,
			}
			server := httptest.NewServer(http.HandlerFunc(mock.handler))
			defer server.Close()

			client := NewBlueskyClient(handle, appPassword, server.URL)
			_, err := client.Post(context.Background(), services.PostContent{Text: content})

			if err != nil {
				t.Logf("Post failed: %v", err)
				return false
			}

			mock.mu.Lock()
			defer mock.mu.Unlock()
			return mock.createRecordCalled
		},
		genValidPostContent(),
		genBlueskyHandle(),
		genAppPassword(),
		genBlueskyDID(),
		genRecordKey(),
	))

	properties.Property("post returns valid AT Protocol URI", prop.ForAll(
		func(content, handle, appPassword, did, rkey string) bool {
			mock := &blueskyMockServer{
				handle:      handle,
				appPassword: appPassword,
				did:         did,
				rkey:        rkey,
			}
			server := httptest.NewServer(http.HandlerFunc(mock.handler))
			defer server.Close()

			client := NewBlueskyClient(handle, appPassword, server.URL)
			result, err := client.Post(context.Background(), services.PostContent{Text: content})

			if err != nil {
				t.Logf("Post failed: %v", err)
				return false
			}

			atURIPattern := regexp.MustCompile(`^at://did:plc:[a-z2-7]+/app\.bsky\.feed\.post/[a-z0-9]+$`)
			if !atURIPattern.MatchString(result.PostID) {
				t.Logf("Invalid AT URI format: %s", result.PostID)
				return false
			}

			expectedURI := "at://" + did + "/app.bsky.feed.post/" + rkey
			return result.PostID == expectedURI
		},
		genValidPostContent(),
		genBlueskyHandle(),
		genAppPassword(),
		genBlueskyDID(),
		genRecordKey(),
	))

	properties.Property("AT URI is converted to valid web URL", prop.ForAll(
		func(content, handle, appPassword, did, rkey string) bool {
			mock := &blueskyMockServer{
				handle:      handle,
				appPassword: appPassword,
				did:         did,
				rkey:        rkey,
			}
			server := httptest.NewServer(http.HandlerFunc(mock.handler))
			defer server.Close()

			client := NewBlueskyClient(handle, appPassword, server.URL)
			result, err := client.Post(context.Background(), services.PostContent{Text: content})

			if err != nil {
				t.Logf("Post failed: %v", err)
				return false
			}

			expectedURL := "https://bsky.app/profile/" + handle + "/post/" + rkey
			if result.PostURL != expectedURL {
				t.Logf("Expected URL %s, got %s", expectedURL, result.PostURL)
				return false
			}

			return strings.HasPrefix(result.PostURL, "https://bsky.app/profile/") &&
				strings.Contains(result.PostURL, "/post/")
		},
		genValidPostContent(),
		genBlueskyHandle(),
		genAppPassword(),
		genBlueskyDID(),
		genRecordKey(),
	))

	properties.TestingRun(t)
}

func TestProperty25_SessionReuse(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("existing session is reused for subsequent posts", prop.ForAll(
		func(content1, content2, handle, appPassword, did, rkey string) bool {
			sessionCallCount := 0
			var mu sync.Mutex

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()

				w.Header().Set("Content-Type", "application/json")

				switch r.URL.Path {
				case "/xrpc/com.atproto.server.createSession":
					sessionCallCount++
					json.NewEncoder(w).Encode(map[string]interface{}{
						"accessJwt":  "test-access-jwt-token",
						"refreshJwt": "test-refresh-jwt-token",
						"did":        did,
						"handle":     handle,
					})

				case "/xrpc/com.atproto.repo.createRecord":
					atURI := "at://" + did + "/app.bsky.feed.post/" + rkey
					json.NewEncoder(w).Encode(map[string]interface{}{
						"uri": atURI,
						"cid": "bafyrei" + rkey,
					})
				}
			}))
			defer server.Close()

			client := NewBlueskyClient(handle, appPassword, server.URL)

			_, err := client.Post(context.Background(), services.PostContent{Text: content1})
			if err != nil {
				t.Logf("First post failed: %v", err)
				return false
			}

			_, err = client.Post(context.Background(), services.PostContent{Text: content2})
			if err != nil {
				t.Logf("Second post failed: %v", err)
				return false
			}

			mu.Lock()
			defer mu.Unlock()
			return sessionCallCount == 1
		},
		genValidPostContent(),
		genValidPostContent(),
		genBlueskyHandle(),
		genAppPassword(),
		genBlueskyDID(),
		genRecordKey(),
	))

	properties.TestingRun(t)
}

func TestProperty25_ContentLimitValidation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("300-char content succeeds", prop.ForAll(
		func(handle, appPassword, did, rkey string) bool {
			mock := &blueskyMockServer{
				handle:      handle,
				appPassword: appPassword,
				did:         did,
				rkey:        rkey,
			}
			server := httptest.NewServer(http.HandlerFunc(mock.handler))
			defer server.Close()

			content := strings.Repeat("a", 300)

			client := NewBlueskyClient(handle, appPassword, server.URL)
			result, err := client.Post(context.Background(), services.PostContent{Text: content})

			if err != nil {
				t.Logf("Post with 300 chars failed: %v", err)
				return false
			}

			return result != nil && result.PostID != ""
		},
		genBlueskyHandle(),
		genAppPassword(),
		genBlueskyDID(),
		genRecordKey(),
	))

	properties.Property("content over 300 chars fails", prop.ForAll(
		func(extraChars int, handle, appPassword string) bool {
			if extraChars < 1 || extraChars > 100 {
				return true
			}

			client := NewBlueskyClient(handle, appPassword, "")
			content := strings.Repeat("a", 300+extraChars)

			err := client.ValidateContent(services.PostContent{Text: content})

			return err != nil
		},
		gen.IntRange(1, 100),
		genBlueskyHandle(),
		genAppPassword(),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Property 26: AT URI to Web URL Conversion
// =============================================================================

// genBlueskyRkey generates random Bluesky record keys (TID format)
func genBlueskyRkey() gopter.Gen {
	return gen.RegexMatch(`[a-z2-7]{13}`)
}

// genBlueskyDIDForURI generates random Bluesky DIDs for AT URIs
func genBlueskyDIDForURI() gopter.Gen {
	identifier := gen.RegexMatch(`[a-z2-7]{24}`)
	return identifier.Map(func(id string) string {
		return "did:plc:" + id
	})
}

// genBlueskyHandleForURI generates random Bluesky handles
func genBlueskyHandleForURI() gopter.Gen {
	username := gen.RegexMatch(`[a-z][a-z0-9]{2,15}`)
	domain := gen.OneConstOf("bsky.social", "bsky.app", "example.com")

	return gopter.CombineGens(username, domain).Map(func(vals []interface{}) string {
		return vals[0].(string) + "." + vals[1].(string)
	})
}

func TestProperty26_ATURIToWebURLExtractsRkey(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)

	properties := gopter.NewProperties(parameters)

	properties.Property("rkey from AT URI appears in web URL", prop.ForAll(
		func(handle string, did string, rkey string) bool {
			client := NewBlueskyClient(handle, "password", "")
			atURI := "at://" + did + "/app.bsky.feed.post/" + rkey

			webURL := client.ATURIToWebURL(atURI)

			return strings.Contains(webURL, "/post/"+rkey)
		},
		genBlueskyHandleForURI(),
		genBlueskyDIDForURI(),
		genBlueskyRkey(),
	))

	properties.TestingRun(t)
}

func TestProperty26_ATURIToWebURLUsesHandle(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)

	properties := gopter.NewProperties(parameters)

	properties.Property("client handle appears in web URL", prop.ForAll(
		func(handle string, did string, rkey string) bool {
			client := NewBlueskyClient(handle, "password", "")
			atURI := "at://" + did + "/app.bsky.feed.post/" + rkey

			webURL := client.ATURIToWebURL(atURI)

			return strings.Contains(webURL, "/profile/"+handle+"/post/")
		},
		genBlueskyHandleForURI(),
		genBlueskyDIDForURI(),
		genBlueskyRkey(),
	))

	properties.TestingRun(t)
}

func TestProperty26_ATURIToWebURLFormat(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)

	properties := gopter.NewProperties(parameters)

	properties.Property("web URL has correct format https://bsky.app/profile/{handle}/post/{rkey}", prop.ForAll(
		func(handle string, did string, rkey string) bool {
			client := NewBlueskyClient(handle, "password", "")
			atURI := "at://" + did + "/app.bsky.feed.post/" + rkey

			webURL := client.ATURIToWebURL(atURI)
			expectedURL := "https://bsky.app/profile/" + handle + "/post/" + rkey

			return webURL == expectedURL
		},
		genBlueskyHandleForURI(),
		genBlueskyDIDForURI(),
		genBlueskyRkey(),
	))

	properties.TestingRun(t)
}

func TestProperty26_ATURIToWebURLFallback(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)

	properties := gopter.NewProperties(parameters)

	properties.Property("invalid AT URIs return original value", prop.ForAll(
		func(handle string, invalidURI string) bool {
			client := NewBlueskyClient(handle, "password", "")

			result := client.ATURIToWebURL(invalidURI)

			return result == invalidURI
		},
		genBlueskyHandleForURI(),
		genInvalidATURI(),
	))

	properties.TestingRun(t)
}

func genInvalidATURI() gopter.Gen {
	return gen.OneGenOf(
		gen.Const("at://did:plc:abc123"),
		gen.Const("at://did:plc:abc123/app.bsky.feed.post"),
		gen.AlphaString().Map(func(s string) string {
			return "invalid://" + s
		}),
		gen.Const(""),
		gen.Const("at://"),
	)
}

func TestProperty26_ATURIToWebURLBidirectionalConsistency(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)

	properties := gopter.NewProperties(parameters)

	properties.Property("same rkey always produces consistent post path", prop.ForAll(
		func(handle1, handle2, did1, did2, rkey string) bool {
			client1 := NewBlueskyClient(handle1, "password", "")
			client2 := NewBlueskyClient(handle2, "password", "")

			atURI1 := "at://" + did1 + "/app.bsky.feed.post/" + rkey
			atURI2 := "at://" + did2 + "/app.bsky.feed.post/" + rkey

			webURL1 := client1.ATURIToWebURL(atURI1)
			webURL2 := client2.ATURIToWebURL(atURI2)

			suffix := "/post/" + rkey
			return strings.HasSuffix(webURL1, suffix) && strings.HasSuffix(webURL2, suffix)
		},
		genBlueskyHandleForURI(),
		genBlueskyHandleForURI(),
		genBlueskyDIDForURI(),
		genBlueskyDIDForURI(),
		genBlueskyRkey(),
	))

	properties.TestingRun(t)
}

func TestProperty26_ATURIToWebURLStartsWithHTTPS(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)

	properties := gopter.NewProperties(parameters)

	properties.Property("valid AT URIs always produce HTTPS URLs", prop.ForAll(
		func(handle, did, rkey string) bool {
			client := NewBlueskyClient(handle, "password", "")
			atURI := "at://" + did + "/app.bsky.feed.post/" + rkey

			webURL := client.ATURIToWebURL(atURI)

			return strings.HasPrefix(webURL, "https://bsky.app/")
		},
		genBlueskyHandleForURI(),
		genBlueskyDIDForURI(),
		genBlueskyRkey(),
	))

	properties.TestingRun(t)
}
