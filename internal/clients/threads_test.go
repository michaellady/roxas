package clients

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mikelady/roxas/internal/services"
)

func TestThreadsClient_Platform(t *testing.T) {
	client := &ThreadsClient{}
	if got := client.Platform(); got != services.PlatformThreads {
		t.Errorf("Platform() = %q, want %q", got, services.PlatformThreads)
	}
}

func TestThreadsClient_ValidateContent(t *testing.T) {
	client := &ThreadsClient{}

	tests := []struct {
		name    string
		content services.PostContent
		wantErr bool
	}{
		{
			name:    "valid short thread",
			content: services.PostContent{Text: "Hello, Threads!"},
			wantErr: false,
		},
		{
			name:    "valid 500 char thread",
			content: services.PostContent{Text: string(make([]byte, 500))},
			wantErr: false,
		},
		{
			name:    "too long thread",
			content: services.PostContent{Text: string(make([]byte, 501))},
			wantErr: true,
		},
		{
			name:    "empty thread without media",
			content: services.PostContent{Text: ""},
			wantErr: true,
		},
		{
			name: "empty text with media is valid",
			content: services.PostContent{
				Text:  "",
				Media: []services.MediaAttachment{{Type: services.MediaTypeImage, URL: "https://example.com/image.jpg"}},
			},
			wantErr: false,
		},
		{
			name: "too many media attachments",
			content: services.PostContent{
				Text: "Test",
				Media: []services.MediaAttachment{
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage}, // 11 is too many
				},
			},
			wantErr: true,
		},
		{
			name: "max media attachments is valid",
			content: services.PostContent{
				Text: "Test",
				Media: []services.MediaAttachment{
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage},
					{Type: services.MediaTypeImage}, // 10 is max
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.ValidateContent(tt.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateContent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestThreadsClient_Post(t *testing.T) {
	// Create test server that simulates Threads API two-step process
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Step 1: Create container
		if r.URL.Path == "/me/threads" && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id": "container-123",
			})
			return
		}
		// Step 2: Publish container
		if r.URL.Path == "/me/threads_publish" && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id": "post-456",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &ThreadsClient{
		accessToken: "test-token",
		baseURL:     server.URL,
		client:      http.DefaultClient,
		userID:      "testuser",
	}

	content := services.PostContent{Text: "Hello, Threads!"}
	result, err := client.Post(context.Background(), content)

	if err != nil {
		t.Fatalf("Post() error = %v", err)
	}

	if result.PostID != "post-456" {
		t.Errorf("Post().PostID = %q, want %q", result.PostID, "post-456")
	}
}

func TestThreadsClient_Post_TooLong(t *testing.T) {
	client := &ThreadsClient{
		accessToken: "test-token",
		client:      http.DefaultClient,
	}

	content := services.PostContent{Text: string(make([]byte, 600))}
	_, err := client.Post(context.Background(), content)

	if err == nil {
		t.Error("Post() should fail for too-long content")
	}
}

func TestThreadsClient_Post_RateLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"error": "rate limited"})
	}))
	defer server.Close()

	client := &ThreadsClient{
		accessToken: "test-token",
		baseURL:     server.URL,
		client:      http.DefaultClient,
	}

	content := services.PostContent{Text: "Test"}
	_, err := client.Post(context.Background(), content)

	if !errors.Is(err, ErrThreadsRateLimited) {
		t.Errorf("Post() error = %v, want ErrThreadsRateLimited", err)
	}
}

func TestThreadsClient_Post_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := &ThreadsClient{
		accessToken: "bad-token",
		baseURL:     server.URL,
		client:      http.DefaultClient,
	}

	content := services.PostContent{Text: "Test"}
	_, err := client.Post(context.Background(), content)

	if !errors.Is(err, ErrThreadsAuthentication) {
		t.Errorf("Post() error = %v, want ErrThreadsAuthentication", err)
	}
}

func TestThreadsClient_Post_WithMedia(t *testing.T) {
	var receivedMediaType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/me/threads" && r.Method == "POST" {
			var req map[string]interface{}
			json.NewDecoder(r.Body).Decode(&req)
			if mt, ok := req["media_type"].(string); ok {
				receivedMediaType = mt
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id": "container-123",
			})
			return
		}
		if r.URL.Path == "/me/threads_publish" && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id": "post-456",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &ThreadsClient{
		accessToken: "test-token",
		baseURL:     server.URL,
		client:      http.DefaultClient,
	}

	content := services.PostContent{
		Text: "Check out this image!",
		Media: []services.MediaAttachment{
			{Type: services.MediaTypeImage, URL: "https://example.com/image.jpg"},
		},
	}

	_, err := client.Post(context.Background(), content)
	if err != nil {
		t.Fatalf("Post() error = %v", err)
	}

	if receivedMediaType != "IMAGE" {
		t.Errorf("media_type = %q, want %q", receivedMediaType, "IMAGE")
	}
}

func TestThreadsClient_GetRateLimits(t *testing.T) {
	client := &ThreadsClient{
		rateLimit: services.RateLimitInfo{
			Limit:     250,
			Remaining: 245,
		},
	}

	limits := client.GetRateLimits()

	if limits.Limit != 250 {
		t.Errorf("GetRateLimits().Limit = %d, want 250", limits.Limit)
	}

	if limits.Remaining != 245 {
		t.Errorf("GetRateLimits().Remaining = %d, want 245", limits.Remaining)
	}
}

func TestThreadsClient_FetchRateLimits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/me/threads_publishing_limit" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"quota_usage": 5,
						"config": map[string]interface{}{
							"quota_total":    250,
							"quota_duration": 86400, // 24 hours in seconds
						},
					},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &ThreadsClient{
		accessToken: "test-token",
		baseURL:     server.URL,
		client:      http.DefaultClient,
	}

	limits, err := client.FetchRateLimits(context.Background())
	if err != nil {
		t.Fatalf("FetchRateLimits() error = %v", err)
	}

	if limits.Limit != 250 {
		t.Errorf("FetchRateLimits().Limit = %d, want 250", limits.Limit)
	}

	if limits.Remaining != 245 {
		t.Errorf("FetchRateLimits().Remaining = %d, want 245", limits.Remaining)
	}

	// Check that the cache was updated
	cachedLimits := client.GetRateLimits()
	if cachedLimits.Limit != 250 {
		t.Errorf("Cached GetRateLimits().Limit = %d, want 250", cachedLimits.Limit)
	}
}

func TestThreadsClient_getUserID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/me" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":       "123456789",
				"username": "testuser",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &ThreadsClient{
		accessToken: "test-token",
		baseURL:     server.URL,
		client:      http.DefaultClient,
	}

	userID, err := client.getUserID(context.Background())
	if err != nil {
		t.Fatalf("getUserID() error = %v", err)
	}

	if userID != "123456789" {
		t.Errorf("getUserID() = %q, want %q", userID, "123456789")
	}
}
