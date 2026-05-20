package clients

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// parseGraphQLQuery reads the request body and extracts the query and variables.
func parseGraphQLQuery(r *http.Request) (string, map[string]interface{}) {
	body, _ := io.ReadAll(r.Body)
	var req map[string]interface{}
	json.Unmarshal(body, &req)
	query, _ := req["query"].(string)
	vars, _ := req["variables"].(map[string]interface{})
	return query, vars
}

// newGraphQLTestServer creates a test server that handles organizations and channels queries.
func newGraphQLTestServer(t *testing.T, channels []map[string]interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("Expected Bearer test-token, got %s", auth)
		}

		query, _ := parseGraphQLQuery(r)

		if strings.Contains(query, "account") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"account": map[string]interface{}{
						"organizations": []map[string]interface{}{
							{"id": "org-1"},
						},
					},
				},
			})
		} else if strings.Contains(query, "channels") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"channels": channels,
				},
			})
		}
	}))
}

// TestBufferListProfiles tests listing Buffer channels via GraphQL
func TestBufferListProfiles(t *testing.T) {
	channels := []map[string]interface{}{
		{"id": "ch-1", "service": "twitter", "formattedUsername": "Twitter @testuser"},
		{"id": "ch-2", "service": "linkedin", "formattedUsername": "LinkedIn TestCo"},
		{"id": "ch-3", "service": "facebook", "formattedUsername": "Facebook TestPage"},
	}
	server := newGraphQLTestServer(t, channels)
	defer server.Close()

	client := NewBufferClient("test-token", server.URL)
	profiles, err := client.ListProfiles(context.Background())

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(profiles) != 3 {
		t.Fatalf("Expected 3 profiles, got %d", len(profiles))
	}

	if profiles[0].ID != "ch-1" || profiles[0].Service != "twitter" {
		t.Errorf("Expected ch-1/twitter, got %s/%s", profiles[0].ID, profiles[0].Service)
	}
	if profiles[0].Formatted != "Twitter @testuser" {
		t.Errorf("Expected 'Twitter @testuser', got %s", profiles[0].Formatted)
	}
}

// TestBufferGetOrganizations tests fetching organizations via GraphQL
func TestBufferGetOrganizations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("Expected Bearer test-token, got %s", auth)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"account": map[string]interface{}{
					"organizations": []map[string]interface{}{
						{"id": "org-123"},
						{"id": "org-456"},
					},
				},
			},
		})
	}))
	defer server.Close()

	client := NewBufferClient("test-token", server.URL)
	orgID, err := client.getOrganizationID(context.Background())

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if orgID != "org-123" {
		t.Errorf("Expected org-123, got %s", orgID)
	}
}

// TestBufferGetOrganizations_Empty tests error when no organizations exist
func TestBufferGetOrganizations_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"account": map[string]interface{}{
					"organizations": []map[string]interface{}{},
				},
			},
		})
	}))
	defer server.Close()

	client := NewBufferClient("test-token", server.URL)
	_, err := client.getOrganizationID(context.Background())

	if err == nil {
		t.Error("Expected error for empty organizations")
	}
	if !strings.Contains(err.Error(), "no organizations") {
		t.Errorf("Expected 'no organizations' error, got: %v", err)
	}
}

// TestBufferCreatePost tests creating a post via GraphQL mutation
func TestBufferCreatePost(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("Expected Bearer test-token, got %s", auth)
		}

		query, vars := parseGraphQLQuery(r)
		if !strings.Contains(query, "createPost") {
			t.Errorf("Expected createPost mutation, got: %s", query)
		}

		// Verify input variables
		input, ok := vars["input"].(map[string]interface{})
		if !ok {
			t.Fatal("Expected input variable")
		}
		if input["text"] != "Hello from Roxas!" {
			t.Errorf("Expected 'Hello from Roxas!', got %v", input["text"])
		}

		callCount++
		postID := "post-" + input["channelId"].(string)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"createPost": map[string]interface{}{
					"post": map[string]interface{}{
						"id":   postID,
						"text": "Hello from Roxas!",
					},
				},
			},
		})
	}))
	defer server.Close()

	client := NewBufferClient("test-token", server.URL)
	result, err := client.CreatePost(context.Background(), []string{"ch-1", "ch-2"}, "Hello from Roxas!", true)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !result.Success {
		t.Error("Expected success=true")
	}

	if len(result.Updates) != 2 {
		t.Fatalf("Expected 2 updates, got %d", len(result.Updates))
	}

	if callCount != 2 {
		t.Errorf("Expected 2 mutation calls (one per channel), got %d", callCount)
	}

	if result.Updates[0].ID != "post-ch-1" {
		t.Errorf("Expected post-ch-1, got %s", result.Updates[0].ID)
	}
}

// TestBufferCreatePost_MutationError tests handling of GraphQL MutationError
func TestBufferCreatePost_MutationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"createPost": map[string]interface{}{
					"message": "Insufficient permissions to post to this channel",
				},
			},
		})
	}))
	defer server.Close()

	client := NewBufferClient("test-token", server.URL)
	result, err := client.CreatePost(context.Background(), []string{"ch-1"}, "test", true)

	if err != nil {
		t.Fatalf("Expected no error (MutationError is in result), got %v", err)
	}
	if result.Success {
		t.Error("Expected success=false for MutationError")
	}
	if !strings.Contains(result.Message, "Insufficient permissions") {
		t.Errorf("Expected error message, got: %s", result.Message)
	}
}

// TestBufferCreatePost_Failure tests handling of HTTP-level failure
func TestBufferCreatePost_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "Forbidden"}`))
	}))
	defer server.Close()

	client := NewBufferClient("bad-token", server.URL)
	_, err := client.CreatePost(context.Background(), []string{"ch-1"}, "test", true)

	if err == nil {
		t.Error("Expected error for forbidden response, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("Expected 403 error, got: %v", err)
	}
}

// TestBufferCreatePost_GraphQLError tests handling of GraphQL-level errors
func TestBufferCreatePost_GraphQLError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"errors": []map[string]interface{}{
				{"message": "Invalid query syntax"},
			},
		})
	}))
	defer server.Close()

	client := NewBufferClient("test-token", server.URL)
	_, err := client.CreatePost(context.Background(), []string{"ch-1"}, "test", true)

	if err == nil {
		t.Error("Expected error for GraphQL error response, got nil")
	}
	if !strings.Contains(err.Error(), "Invalid query syntax") {
		t.Errorf("Expected GraphQL error message, got: %v", err)
	}
}

// TestBufferPost_SocialClientInterface tests the SocialClient interface implementation
func TestBufferPost_SocialClientInterface(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, _ := parseGraphQLQuery(r)

		if strings.Contains(query, "account") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"account": map[string]interface{}{
						"organizations": []map[string]interface{}{
							{"id": "org-1"},
						},
					},
				},
			})
		} else if strings.Contains(query, "channels") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"channels": []map[string]interface{}{
						{"id": "ch-1", "service": "twitter", "formattedUsername": "Twitter @user"},
					},
				},
			})
		} else if strings.Contains(query, "createPost") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"createPost": map[string]interface{}{
						"post": map[string]interface{}{
							"id":   "post-1",
							"text": "Test post",
						},
					},
				},
			})
		} else {
			t.Errorf("Unexpected query: %s", query)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client := NewBufferClient("test-token", server.URL)
	result, err := client.Post(context.Background(), BufferPostContent{Text: "Test post"})

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.PostID == "" {
		t.Error("Expected non-empty PostID")
	}
	if result.PostID != "post-1" {
		t.Errorf("Expected post-1, got %s", result.PostID)
	}
}

// TestBufferValidateContent tests content validation (280 char limit)
func TestBufferValidateContent(t *testing.T) {
	client := NewBufferClient("token", "")

	// Valid content (under 280 chars)
	err := client.ValidateContent(BufferPostContent{Text: "Short post"})
	if err != nil {
		t.Errorf("Expected no error for short content, got %v", err)
	}

	// Empty content
	err = client.ValidateContent(BufferPostContent{Text: ""})
	if err == nil {
		t.Error("Expected error for empty content")
	}

	// Over 280 chars
	longText := strings.Repeat("a", 281)
	err = client.ValidateContent(BufferPostContent{Text: longText})
	if err == nil {
		t.Error("Expected error for content over 280 chars")
	}

	// Exactly 280 chars
	exactText := strings.Repeat("a", 280)
	err = client.ValidateContent(BufferPostContent{Text: exactText})
	if err != nil {
		t.Errorf("Expected no error for 280 chars, got %v", err)
	}
}

// TestBufferPlatform tests Platform() returns correct identifier
func TestBufferPlatform(t *testing.T) {
	client := NewBufferClient("token", "")
	if p := client.Platform(); p != "buffer" {
		t.Errorf("Expected 'buffer', got %s", p)
	}
}

// TestBufferNetworkError tests network failure handling
func TestBufferNetworkError(t *testing.T) {
	client := NewBufferClient("token", "http://invalid-domain-12345.com")
	_, err := client.ListProfiles(context.Background())

	if err == nil {
		t.Error("Expected network error, got nil")
	}
}

// TestBufferListProfiles_InvalidJSON tests handling of invalid JSON response
func TestBufferListProfiles_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	}))
	defer server.Close()

	client := NewBufferClient("token", server.URL)
	_, err := client.ListProfiles(context.Background())

	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

// TestBufferPost_NoProfiles tests Post when no channels are available
func TestBufferPost_NoProfiles(t *testing.T) {
	server := newGraphQLTestServer(t, []map[string]interface{}{})
	defer server.Close()

	client := NewBufferClient("test-token", server.URL)
	_, err := client.Post(context.Background(), BufferPostContent{Text: "test"})

	if err == nil {
		t.Error("Expected error when no profiles available")
	}
	if !strings.Contains(err.Error(), "no profiles") {
		t.Errorf("Expected 'no profiles' error, got: %v", err)
	}
}
