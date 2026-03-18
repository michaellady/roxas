package clients

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBufferListProfiles tests listing Buffer profiles/channels
func TestBufferListProfiles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/1/profiles.json" {
			t.Errorf("Expected /1/profiles.json, got %s", r.URL.Path)
		}

		// Verify access_token query parameter
		token := r.URL.Query().Get("access_token")
		if token != "test-token" {
			t.Errorf("Expected access_token=test-token, got %s", token)
		}

		profiles := []BufferProfile{
			{ID: "prof-1", Service: "twitter", Formatted: "Twitter @testuser"},
			{ID: "prof-2", Service: "linkedin", Formatted: "LinkedIn TestCo"},
			{ID: "prof-3", Service: "facebook", Formatted: "Facebook TestPage"},
		}
		json.NewEncoder(w).Encode(profiles)
	}))
	defer server.Close()

	client := NewBufferClient("test-token", server.URL)
	profiles, err := client.ListProfiles(context.Background())

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(profiles) != 3 {
		t.Fatalf("Expected 3 profiles, got %d", len(profiles))
	}

	if profiles[0].ID != "prof-1" || profiles[0].Service != "twitter" {
		t.Errorf("Expected prof-1/twitter, got %s/%s", profiles[0].ID, profiles[0].Service)
	}
}

// TestBufferCreatePost tests creating a post via Buffer
func TestBufferCreatePost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/1/updates/create.json" {
			t.Errorf("Expected /1/updates/create.json, got %s", r.URL.Path)
		}

		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		// Parse form body
		if err := r.ParseForm(); err != nil {
			t.Fatalf("Failed to parse form: %v", err)
		}

		// Verify access_token in form body
		accessToken := r.FormValue("access_token")
		if accessToken != "test-token" {
			t.Errorf("Expected access_token=test-token, got %s", accessToken)
		}

		text := r.FormValue("text")
		if text != "Hello from Roxas!" {
			t.Errorf("Expected 'Hello from Roxas!', got %s", text)
		}

		profileIDs := r.Form["profile_ids[]"]
		if len(profileIDs) != 2 {
			t.Fatalf("Expected 2 profile IDs, got %d", len(profileIDs))
		}

		now := r.FormValue("now")
		if now != "true" {
			t.Errorf("Expected now=true, got %s", now)
		}

		response := bufferCreateResponse{
			Success: true,
			Updates: []bufferUpdate{
				{ID: "upd-1", Status: "sent", ProfileID: "prof-1"},
				{ID: "upd-2", Status: "sent", ProfileID: "prof-2"},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewBufferClient("test-token", server.URL)
	result, err := client.CreatePost(context.Background(), []string{"prof-1", "prof-2"}, "Hello from Roxas!", true)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !result.Success {
		t.Error("Expected success=true")
	}

	if len(result.Updates) != 2 {
		t.Fatalf("Expected 2 updates, got %d", len(result.Updates))
	}
}

// TestBufferCreatePost_Failure tests handling of Buffer API failure
func TestBufferCreatePost_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "Forbidden"}`))
	}))
	defer server.Close()

	client := NewBufferClient("bad-token", server.URL)
	_, err := client.CreatePost(context.Background(), []string{"prof-1"}, "test", true)

	if err == nil {
		t.Error("Expected error for forbidden response, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("Expected 403 error, got: %v", err)
	}
}

// TestBufferPost_SocialClientInterface tests the SocialClient interface implementation
func TestBufferPost_SocialClientInterface(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/1/profiles.json":
			profiles := []BufferProfile{
				{ID: "prof-1", Service: "twitter", Formatted: "Twitter @user"},
			}
			json.NewEncoder(w).Encode(profiles)
		case "/1/updates/create.json":
			response := bufferCreateResponse{
				Success: true,
				Updates: []bufferUpdate{
					{ID: "upd-1", Status: "sent", ProfileID: "prof-1"},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			t.Errorf("Unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewBufferClient("test-token", server.URL)
	// Use Post() which is the SocialClient interface method
	result, err := client.Post(context.Background(), BufferPostContent{Text: "Test post"})

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.PostID == "" {
		t.Error("Expected non-empty PostID")
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

// TestBufferPost_NoProfiles tests Post when no profiles are available
func TestBufferPost_NoProfiles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return empty profiles
		json.NewEncoder(w).Encode([]BufferProfile{})
	}))
	defer server.Close()

	client := NewBufferClient("token", server.URL)
	_, err := client.Post(context.Background(), BufferPostContent{Text: "test"})

	if err == nil {
		t.Error("Expected error when no profiles available")
	}
	if !strings.Contains(err.Error(), "no profiles") {
		t.Errorf("Expected 'no profiles' error, got: %v", err)
	}
}
