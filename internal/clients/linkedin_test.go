package clients

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// mockLinkedInServer creates a mock server that handles userinfo and other LinkedIn endpoints
func mockLinkedInServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle userinfo endpoint for client initialization
		if r.URL.Path == "/v2/userinfo" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"sub": "urn:li:person:test-person-123",
			})
			return
		}
		// Delegate to test-specific handler
		handler(w, r)
	}))
}

// TestLinkedInImageUpload tests successful image upload to LinkedIn
func TestLinkedInImageUpload(t *testing.T) {
	var serverURL string
	// Mock LinkedIn API server with proper image upload response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle userinfo endpoint for client initialization
		if r.URL.Path == "/v2/userinfo" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"sub": "urn:li:person:test-123"})
			return
		}

		// Handle image initialization endpoint
		if strings.Contains(r.URL.Path, "/images") {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				t.Error("Missing or invalid Authorization header")
			}
			if r.Method != "POST" {
				t.Errorf("Expected POST, got %s", r.Method)
			}
			response := map[string]interface{}{
				"value": map[string]interface{}{
					"uploadUrl":          serverURL + "/upload",
					"image":              "urn:li:image:test-image-123",
					"uploadUrlExpiresAt": 9999999999999,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}

		// Handle binary upload endpoint
		if strings.Contains(r.URL.Path, "/upload") {
			w.WriteHeader(http.StatusCreated)
			return
		}

		t.Errorf("Unexpected endpoint: %s", r.URL.Path)
	}))
	serverURL = server.URL
	defer server.Close()

	// Create test image file
	tmpFile, err := os.CreateTemp("", "test-image-*.png")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write([]byte("fake image data"))
	tmpFile.Close()

	// Create client with mock server URL
	client := NewLinkedInClient("test-access-token", server.URL)

	assetURN, err := client.UploadImage(tmpFile.Name())

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if assetURN == "" {
		t.Error("Expected non-empty asset URN")
	}

	if !strings.Contains(assetURN, "urn:li:") {
		t.Errorf("Expected URN format, got: %s", assetURN)
	}
}

// TestLinkedInCreatePost tests successful post creation
func TestLinkedInCreatePost(t *testing.T) {
	// Mock LinkedIn UGC API server
	server := mockLinkedInServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Verify endpoint
		if !strings.Contains(r.URL.Path, "/ugcPosts") && !strings.Contains(r.URL.Path, "/posts") {
			t.Errorf("Expected ugcPosts or posts endpoint, got %s", r.URL.Path)
		}

		// Verify Authorization header
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Error("Missing or invalid Authorization header")
		}

		// Verify Content-Type
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Expected application/json, got %s", contentType)
		}

		// Parse request body
		var requestBody map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Errorf("Failed to parse request body: %v", err)
		}

		// Verify required fields
		if requestBody["author"] == nil {
			t.Error("Request missing 'author' field")
		}

		// Send mock response
		response := map[string]interface{}{
			"id": "urn:li:share:7654321",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	})
	defer server.Close()

	client := NewLinkedInClient("test-access-token", server.URL)

	text := "Excited to share our latest achievement!"
	imageURN := "urn:li:digitalmediaAsset:test-123"

	postID, err := client.CreatePost(text, imageURN)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if postID == "" {
		t.Error("Expected non-empty post ID")
	}

	if !strings.Contains(postID, "urn:li:") {
		t.Errorf("Expected URN format, got: %s", postID)
	}
}

// TestLinkedInHandlesAuthError tests 401 unauthorized handling
func TestLinkedInHandlesAuthError(t *testing.T) {
	// Mock server returning 401 for posts (but 200 for userinfo)
	server := mockLinkedInServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message": "Invalid access token"}`))
	})
	defer server.Close()

	client := NewLinkedInClient("invalid-token", server.URL)

	_, err := client.CreatePost("test", "urn:li:test")

	if err == nil {
		t.Error("Expected error for unauthorized, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "401") && !strings.Contains(errMsg, "Unauthorized") {
		t.Errorf("Expected auth error, got: %v", err)
	}
}

// TestLinkedInHandles403Forbidden tests permission error handling
func TestLinkedInHandles403Forbidden(t *testing.T) {
	// Mock server returning 403 for posts
	server := mockLinkedInServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message": "Insufficient permissions"}`))
	})
	defer server.Close()

	client := NewLinkedInClient("test-token", server.URL)

	_, err := client.CreatePost("test", "urn:li:test")

	if err == nil {
		t.Error("Expected error for forbidden, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "403") && !strings.Contains(errMsg, "Forbidden") {
		t.Errorf("Expected forbidden error, got: %v", err)
	}
}

// TestLinkedInHandlesRateLimit tests 429 rate limit handling
func TestLinkedInHandlesRateLimit(t *testing.T) {
	// Mock server returning 429 for posts
	server := mockLinkedInServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"message": "Rate limit exceeded"}`))
	})
	defer server.Close()

	client := NewLinkedInClient("test-token", server.URL)

	_, err := client.CreatePost("test", "urn:li:test")

	if err == nil {
		t.Error("Expected error for rate limit, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "429") && !strings.Contains(errMsg, "rate limit") {
		t.Errorf("Expected rate limit error, got: %v", err)
	}
}

// TestLinkedInPostWithImage tests complete flow with image
func TestLinkedInPostWithImage(t *testing.T) {
	uploadCalled := false
	postCalled := false
	var serverURL string

	// Mock server handling userinfo, upload, and post
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle userinfo for client init
		if r.URL.Path == "/v2/userinfo" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"sub": "urn:li:person:test-123"})
			return
		}

		// Handle image init endpoint
		if strings.Contains(r.URL.Path, "image") && strings.Contains(r.URL.Path, "action=initializeUpload") || strings.Contains(r.URL.Path, "/rest/images") {
			uploadCalled = true
			response := map[string]interface{}{
				"value": map[string]interface{}{
					"uploadUrl":          serverURL + "/upload",
					"image":              "urn:li:image:uploaded-123",
					"uploadUrlExpiresAt": 9999999999999,
				},
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Handle binary upload
		if strings.Contains(r.URL.Path, "/upload") {
			w.WriteHeader(http.StatusCreated)
			return
		}

		// Handle post creation
		if strings.Contains(r.URL.Path, "post") {
			postCalled = true
			response := map[string]interface{}{
				"id": "urn:li:share:post-456",
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(response)
			return
		}
	}))
	serverURL = server.URL
	defer server.Close()

	// Create test image
	tmpFile, err := os.CreateTemp("", "test-*.png")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write([]byte("test image"))
	tmpFile.Close()

	client := NewLinkedInClient("test-token", server.URL)

	// Upload image
	assetURN, err := client.UploadImage(tmpFile.Name())
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	// Create post with uploaded image
	postID, err := client.CreatePost("Great achievement!", assetURN)
	if err != nil {
		t.Fatalf("Post creation failed: %v", err)
	}

	if !uploadCalled {
		t.Error("Expected upload to be called")
	}

	if !postCalled {
		t.Error("Expected post creation to be called")
	}

	if assetURN == "" || postID == "" {
		t.Error("Expected non-empty asset URN and post ID")
	}
}

// TestLinkedInHandlesMissingFile tests error handling for missing image file
func TestLinkedInHandlesMissingFile(t *testing.T) {
	server := mockLinkedInServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("Should not make API call for missing file")
	})
	defer server.Close()

	client := NewLinkedInClient("test-token", server.URL)

	_, err := client.UploadImage("/nonexistent/file.png")

	if err == nil {
		t.Error("Expected error for missing file, got nil")
	}
}

// TestLinkedInValidatesAccessToken tests token validation
func TestLinkedInValidatesAccessToken(t *testing.T) {
	server := mockLinkedInServer(t, func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		expectedAuth := "Bearer test-valid-token"

		if auth == expectedAuth {
			response := map[string]interface{}{"id": "urn:li:share:success"}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(response)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"message": "Invalid token"}`)
		}
	})
	defer server.Close()

	// Valid token should succeed
	validClient := NewLinkedInClient("test-valid-token", server.URL)
	_, err := validClient.CreatePost("test", "urn:li:asset:123")
	if err != nil {
		t.Errorf("Expected success with valid token, got: %v", err)
	}

	// Invalid token should fail
	invalidClient := NewLinkedInClient("wrong-token", server.URL)
	_, err = invalidClient.CreatePost("test", "urn:li:asset:123")
	if err == nil {
		t.Error("Expected error with invalid token, got nil")
	}
}

// TestLinkedInUploadBinary tests the uploadBinary helper method
func TestLinkedInUploadBinary(t *testing.T) {
	var receivedContentType string
	var receivedMethod string

	server := mockLinkedInServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/upload") {
			receivedMethod = r.Method
			receivedContentType = r.Header.Get("Content-Type")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := NewLinkedInClient("test-token", server.URL)

	err := client.uploadBinary(server.URL+"/upload", []byte("fake image data"), "test-image.png")
	if err != nil {
		t.Fatalf("uploadBinary() error = %v", err)
	}
	if receivedMethod != "PUT" {
		t.Errorf("uploadBinary() method = %q, want %q", receivedMethod, "PUT")
	}
	if !strings.Contains(receivedContentType, "multipart/form-data") {
		t.Errorf("uploadBinary() Content-Type = %q, want multipart/form-data", receivedContentType)
	}
}

// TestLinkedInUploadBinary_ServerError tests uploadBinary error handling
func TestLinkedInUploadBinary_ServerError(t *testing.T) {
	server := mockLinkedInServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/upload") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "upload failed"}`))
			return
		}
	})
	defer server.Close()

	client := NewLinkedInClient("test-token", server.URL)
	err := client.uploadBinary(server.URL+"/upload", []byte("data"), "file.png")
	if err == nil {
		t.Error("uploadBinary() expected error for server error")
	}
}

// TestLinkedInGetPersonURN_NonURNSub tests getPersonURN when sub is a plain ID (longer than 7 chars)
func TestLinkedInGetPersonURN_NonURNSub(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/userinfo" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"sub": "ABCDEFG123456", // Not a URN format, but >= 7 chars
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &LinkedInClient{
		accessToken: "test-token",
		baseURL:     server.URL,
		client:      &http.Client{},
	}

	urn, err := client.getPersonURN()
	if err != nil {
		t.Fatalf("getPersonURN() error = %v", err)
	}
	if urn != "urn:li:person:ABCDEFG123456" {
		t.Errorf("getPersonURN() = %q, want %q", urn, "urn:li:person:ABCDEFG123456")
	}
}

// TestLinkedInGetPersonURN_URNSub tests getPersonURN when sub is already a URN
func TestLinkedInGetPersonURN_URNSub(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/userinfo" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"sub": "urn:li:person:EXISTING_URN",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &LinkedInClient{
		accessToken: "test-token",
		baseURL:     server.URL,
		client:      &http.Client{},
	}

	urn, err := client.getPersonURN()
	if err != nil {
		t.Fatalf("getPersonURN() error = %v", err)
	}
	if urn != "urn:li:person:EXISTING_URN" {
		t.Errorf("getPersonURN() = %q, want %q", urn, "urn:li:person:EXISTING_URN")
	}
}

// TestLinkedInGetPersonURN_EmptySub tests getPersonURN when sub is empty
func TestLinkedInGetPersonURN_EmptySub(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/userinfo" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"sub": "",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &LinkedInClient{
		accessToken: "test-token",
		baseURL:     server.URL,
		client:      &http.Client{},
	}

	_, err := client.getPersonURN()
	if err == nil {
		t.Error("getPersonURN() expected error for empty sub")
	}
}

// TestLinkedInGetPersonURN_ServerError tests getPersonURN error handling
func TestLinkedInGetPersonURN_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`server error`))
	}))
	defer server.Close()

	client := &LinkedInClient{
		accessToken: "test-token",
		baseURL:     server.URL,
		client:      &http.Client{},
	}

	_, err := client.getPersonURN()
	if err == nil {
		t.Error("getPersonURN() expected error for server error")
	}
}

// TestLinkedInCreatePost_NoPostIDInResponse tests CreatePost when no ID in response
func TestLinkedInCreatePost_NoPostIDInResponse(t *testing.T) {
	server := mockLinkedInServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Return 201 Created but no x-restli-id header and empty body
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{}`))
	})
	defer server.Close()

	client := NewLinkedInClient("test-token", server.URL)
	_, err := client.CreatePost("test", "")

	if err == nil {
		t.Error("CreatePost() expected error when no post ID in response")
	}
}

// TestLinkedInCreatePost_PostIDFromHeader tests getting post ID from header
func TestLinkedInCreatePost_PostIDFromHeader(t *testing.T) {
	server := mockLinkedInServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-restli-id", "header-post-id-123")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{}`))
	})
	defer server.Close()

	client := NewLinkedInClient("test-token", server.URL)
	postID, err := client.CreatePost("test", "")

	if err != nil {
		t.Fatalf("CreatePost() error = %v", err)
	}
	if postID != "header-post-id-123" {
		t.Errorf("CreatePost() postID = %q, want %q", postID, "header-post-id-123")
	}
}

// TestLinkedInUploadImage_InitError tests UploadImage when initialization fails
func TestLinkedInUploadImage_InitError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/userinfo" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"sub": "urn:li:person:test"})
			return
		}
		if strings.Contains(r.URL.Path, "/images") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "init failed"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Create test image file
	tmpFile, err := os.CreateTemp("", "test-image-*.png")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write([]byte("fake image data"))
	tmpFile.Close()

	client := NewLinkedInClient("test-token", server.URL)
	_, err = client.UploadImage(tmpFile.Name())

	if err == nil {
		t.Error("UploadImage() expected error when initialization fails")
	}
}

// TestLinkedInUploadImage_MissingUploadURL tests when init response lacks upload URL
func TestLinkedInUploadImage_MissingUploadURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/userinfo" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"sub": "urn:li:person:test"})
			return
		}
		if strings.Contains(r.URL.Path, "/images") {
			response := map[string]interface{}{
				"value": map[string]interface{}{
					"uploadUrl": "",
					"image":     "",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tmpFile, err := os.CreateTemp("", "test-image-*.png")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write([]byte("fake image data"))
	tmpFile.Close()

	client := NewLinkedInClient("test-token", server.URL)
	_, err = client.UploadImage(tmpFile.Name())

	if err == nil {
		t.Error("UploadImage() expected error when upload URL is empty")
	}
}

// TestLinkedInUploadImage_UploadFailed tests when binary upload step fails
func TestLinkedInUploadImage_UploadFailed(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/userinfo" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"sub": "urn:li:person:test"})
			return
		}
		if strings.Contains(r.URL.Path, "/images") {
			response := map[string]interface{}{
				"value": map[string]interface{}{
					"uploadUrl": serverURL + "/upload-endpoint",
					"image":     "urn:li:image:test-123",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}
		if strings.Contains(r.URL.Path, "/upload-endpoint") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`upload failed`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	serverURL = server.URL
	defer server.Close()

	tmpFile, err := os.CreateTemp("", "test-image-*.png")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write([]byte("fake image data"))
	tmpFile.Close()

	client := NewLinkedInClient("test-token", server.URL)
	_, err = client.UploadImage(tmpFile.Name())

	if err == nil {
		t.Error("UploadImage() expected error when upload step fails")
	}
}

// TestLinkedInPostWithoutImage tests text-only post creation
func TestLinkedInPostWithoutImage(t *testing.T) {
	server := mockLinkedInServer(t, func(w http.ResponseWriter, r *http.Request) {
		var requestBody map[string]interface{}
		json.NewDecoder(r.Body).Decode(&requestBody)

		// Verify no media in request for text-only post
		// (implementation detail - adjust based on actual API structure)

		response := map[string]interface{}{
			"id": "urn:li:share:text-only-789",
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	})
	defer server.Close()

	client := NewLinkedInClient("test-token", server.URL)

	// Post without image (empty imageURN)
	postID, err := client.CreatePost("Text-only post", "")

	if err != nil {
		t.Fatalf("Expected text-only post to succeed, got: %v", err)
	}

	if postID == "" {
		t.Error("Expected non-empty post ID for text-only post")
	}
}
