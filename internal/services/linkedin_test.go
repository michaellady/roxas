package services

import (
	"errors"
	"strings"
	"testing"
)

// MockLinkedInClient simulates LinkedIn API for testing
type MockLinkedInClient struct {
	PostID       string
	Error        error
	AuthError    bool
	UploadCalled bool
	PostCalled   bool
}

func (m *MockLinkedInClient) UploadImage(imagePath string) (string, error) {
	m.UploadCalled = true
	if m.AuthError {
		return "", errors.New("401 Unauthorized: invalid access token")
	}
	if m.Error != nil {
		return "", m.Error
	}
	return "urn:li:digitalmediaAsset:12345", nil
}

func (m *MockLinkedInClient) CreatePost(text string, imageURN string) (string, error) {
	m.PostCalled = true
	if m.AuthError {
		return "", errors.New("401 Unauthorized: invalid access token")
	}
	if m.Error != nil {
		return "", m.Error
	}
	return m.PostID, nil
}

// TestPostToLinkedIn tests successful LinkedIn post creation
func TestPostToLinkedIn(t *testing.T) {
	mockClient := &MockLinkedInClient{
		PostID: "urn:li:share:123456",
	}

	poster := NewLinkedInPoster(mockClient, "fake-access-token")
	text := "Professional post about exciting software engineering achievement"
	imagePath := "/tmp/test-image.png"

	postURL, err := poster.Post(text, imagePath)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if postURL == "" {
		t.Error("Expected non-empty post URL")
	}

	if !strings.Contains(postURL, "linkedin.com") {
		t.Errorf("Expected LinkedIn URL, got: %s", postURL)
	}

	// Verify both upload and post were called
	if !mockClient.UploadCalled {
		t.Error("Expected image upload to be called")
	}

	if !mockClient.PostCalled {
		t.Error("Expected post creation to be called")
	}
}

// TestLinkedInImageUpload tests the image upload flow
func TestLinkedInImageUpload(t *testing.T) {
	mockClient := &MockLinkedInClient{
		PostID: "urn:li:share:789",
	}

	poster := NewLinkedInPoster(mockClient, "fake-token")
	text := "Test post with image"
	imagePath := "/tmp/professional-image.png"

	_, err := poster.Post(text, imagePath)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify upload was called
	if !mockClient.UploadCalled {
		t.Error("Image upload should have been called")
	}
}

// TestLinkedInHandlesAuthError tests authentication error handling
func TestLinkedInHandlesAuthError(t *testing.T) {
	mockClient := &MockLinkedInClient{
		AuthError: true,
	}

	poster := NewLinkedInPoster(mockClient, "invalid-token")
	text := "Test post"
	imagePath := "/tmp/image.png"

	_, err := poster.Post(text, imagePath)

	if err == nil {
		t.Error("Expected authentication error, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "401") && !strings.Contains(errMsg, "Unauthorized") && !strings.Contains(errMsg, "auth") {
		t.Errorf("Expected authentication error message, got: %v", err)
	}
}

// TestLinkedInHandlesUploadError tests error handling during image upload
func TestLinkedInHandlesUploadError(t *testing.T) {
	mockClient := &MockLinkedInClient{
		Error: errors.New("upload failed: file too large"),
	}

	poster := NewLinkedInPoster(mockClient, "fake-token")
	text := "Test post"
	imagePath := "/tmp/large-image.png"

	_, err := poster.Post(text, imagePath)

	if err == nil {
		t.Error("Expected upload error, got nil")
	}

	if !strings.Contains(err.Error(), "upload") && !strings.Contains(err.Error(), "failed") {
		t.Errorf("Expected upload error message, got: %v", err)
	}
}

// TestLinkedInHandlesPostError tests error handling during post creation
func TestLinkedInHandlesPostError(t *testing.T) {
	mockClient := &MockLinkedInClient{
		Error: errors.New("rate limit exceeded"),
	}

	poster := NewLinkedInPoster(mockClient, "fake-token")
	text := "Test post"
	imagePath := "/tmp/image.png"

	_, err := poster.Post(text, imagePath)

	if err == nil {
		t.Error("Expected post creation error, got nil")
	}

	if !strings.Contains(err.Error(), "rate limit") && !strings.Contains(err.Error(), "failed") {
		t.Errorf("Expected rate limit error message, got: %v", err)
	}
}

// TestLinkedInHandlesEmptyText tests handling of empty post text
func TestLinkedInHandlesEmptyText(t *testing.T) {
	mockClient := &MockLinkedInClient{
		PostID: "urn:li:share:999",
	}

	poster := NewLinkedInPoster(mockClient, "fake-token")
	text := ""
	imagePath := "/tmp/image.png"

	_, err := poster.Post(text, imagePath)

	// Should either return error or handle gracefully
	if err == nil {
		t.Log("Poster handles empty text gracefully")
	} else {
		if !strings.Contains(err.Error(), "empty") && !strings.Contains(err.Error(), "text") {
			t.Errorf("Expected empty text error, got: %v", err)
		}
	}
}

// TestLinkedInHandlesMissingImage tests handling of missing image file
func TestLinkedInHandlesMissingImage(t *testing.T) {
	mockClient := &MockLinkedInClient{
		PostID: "urn:li:share:888",
	}

	poster := NewLinkedInPoster(mockClient, "fake-token")
	text := "Test post"
	imagePath := "" // Empty image path

	_, err := poster.Post(text, imagePath)

	// Should either return error or handle gracefully
	if err == nil {
		t.Log("Poster handles missing image gracefully")
	} else {
		if !strings.Contains(err.Error(), "image") && !strings.Contains(err.Error(), "path") && !strings.Contains(err.Error(), "empty") {
			t.Errorf("Expected missing image error, got: %v", err)
		}
	}
}

// TestLinkedInPostURLFormat tests that returned URL is properly formatted
func TestLinkedInPostURLFormat(t *testing.T) {
	mockClient := &MockLinkedInClient{
		PostID: "urn:li:share:123456789",
	}

	poster := NewLinkedInPoster(mockClient, "fake-token")
	text := "Achievement unlocked!"
	imagePath := "/tmp/celebration.png"

	postURL, err := poster.Post(text, imagePath)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// URL should be a valid LinkedIn post URL
	if !strings.HasPrefix(postURL, "https://") {
		t.Errorf("Expected HTTPS URL, got: %s", postURL)
	}

	if !strings.Contains(postURL, "linkedin.com") {
		t.Errorf("Expected linkedin.com domain, got: %s", postURL)
	}
}

// TestLinkedInWithoutImage tests posting without an image (text-only)
func TestLinkedInWithoutImage(t *testing.T) {
	mockClient := &MockLinkedInClient{
		PostID: "urn:li:share:555",
	}

	poster := NewLinkedInPoster(mockClient, "fake-token")
	text := "Text-only post without image"
	imagePath := ""

	postURL, err := poster.Post(text, imagePath)

	// Should handle text-only posts
	if err != nil && strings.Contains(err.Error(), "required") {
		t.Log("Implementation requires image for posts")
		return
	}

	if err == nil {
		if postURL == "" {
			t.Error("Expected post URL for text-only post")
		}
		// Verify upload was NOT called for text-only
		if mockClient.UploadCalled {
			t.Error("Image upload should not be called for text-only post")
		}
	}
}
