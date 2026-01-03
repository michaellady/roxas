package services

import (
	"context"
	"errors"
	"testing"
	"time"
)

// =============================================================================
// SocialClient Interface Tests (TDD - RED phase)
// =============================================================================

// MockSocialClient implements SocialClient for testing
type MockSocialClient struct {
	platform     string
	postResult   *PostResult
	postError    error
	validateErr  error
	rateLimits   RateLimitInfo
	postCalled   bool
	lastContent  *PostContent
}

func (m *MockSocialClient) Post(ctx context.Context, content PostContent) (*PostResult, error) {
	m.postCalled = true
	m.lastContent = &content
	if m.postError != nil {
		return nil, m.postError
	}
	return m.postResult, nil
}

func (m *MockSocialClient) ValidateContent(content PostContent) error {
	return m.validateErr
}

func (m *MockSocialClient) Platform() string {
	return m.platform
}

func (m *MockSocialClient) GetRateLimits() RateLimitInfo {
	return m.rateLimits
}

// TestSocialClientPost tests successful posting
func TestSocialClientPost(t *testing.T) {
	mock := &MockSocialClient{
		platform: PlatformLinkedIn,
		postResult: &PostResult{
			PostID:      "urn:li:share:123456",
			PostURL:     "https://www.linkedin.com/feed/update/urn:li:share:123456",
			PlatformRaw: map[string]any{"id": "123456"},
		},
	}

	content := PostContent{
		Text: "Test post about software engineering",
	}

	result, err := mock.Post(context.Background(), content)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if result.PostID != "urn:li:share:123456" {
		t.Errorf("Expected post ID 'urn:li:share:123456', got %s", result.PostID)
	}

	if result.PostURL == "" {
		t.Error("Expected non-empty post URL")
	}

	if !mock.postCalled {
		t.Error("Expected Post to be called")
	}
}

// TestSocialClientPostWithMedia tests posting with media attachments
func TestSocialClientPostWithMedia(t *testing.T) {
	mock := &MockSocialClient{
		platform: PlatformInstagram,
		postResult: &PostResult{
			PostID:  "ig-post-789",
			PostURL: "https://instagram.com/p/abc123",
		},
	}

	content := PostContent{
		Text: "Check out this update! 🚀",
		Media: []MediaAttachment{
			{
				Type:     MediaTypeImage,
				URL:      "https://example.com/image.png",
				MimeType: "image/png",
				AltText:  "Screenshot of the new feature",
			},
		},
	}

	result, err := mock.Post(context.Background(), content)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if mock.lastContent == nil {
		t.Fatal("Expected content to be captured")
	}

	if len(mock.lastContent.Media) != 1 {
		t.Errorf("Expected 1 media attachment, got %d", len(mock.lastContent.Media))
	}
}

// TestSocialClientPostError tests error handling during posting
func TestSocialClientPostError(t *testing.T) {
	mock := &MockSocialClient{
		platform:  PlatformTwitter,
		postError: errors.New("rate limit exceeded"),
	}

	content := PostContent{
		Text: "Test post",
	}

	result, err := mock.Post(context.Background(), content)

	if err == nil {
		t.Error("Expected error, got nil")
	}

	if result != nil {
		t.Error("Expected nil result when error occurs")
	}
}

// TestSocialClientValidateContent tests content validation
func TestSocialClientValidateContent(t *testing.T) {
	tests := []struct {
		name        string
		platform    string
		content     PostContent
		validateErr error
		wantErr     bool
	}{
		{
			name:     "valid LinkedIn content",
			platform: PlatformLinkedIn,
			content: PostContent{
				Text: "Professional update about software development",
			},
			validateErr: nil,
			wantErr:     false,
		},
		{
			name:     "Twitter content too long",
			platform: PlatformTwitter,
			content: PostContent{
				Text: string(make([]byte, 300)), // Over 280 chars
			},
			validateErr: errors.New("content exceeds 280 characters"),
			wantErr:     true,
		},
		{
			name:     "empty content",
			platform: PlatformLinkedIn,
			content: PostContent{
				Text: "",
			},
			validateErr: errors.New("content cannot be empty"),
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockSocialClient{
				platform:    tt.platform,
				validateErr: tt.validateErr,
			}

			err := mock.ValidateContent(tt.content)

			if tt.wantErr && err == nil {
				t.Error("Expected validation error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Expected no validation error, got %v", err)
			}
		})
	}
}

// TestSocialClientPlatform tests platform identification
func TestSocialClientPlatform(t *testing.T) {
	platforms := []string{
		PlatformLinkedIn,
		PlatformTwitter,
		PlatformInstagram,
		PlatformYouTube,
	}

	for _, platform := range platforms {
		t.Run(platform, func(t *testing.T) {
			mock := &MockSocialClient{
				platform: platform,
			}

			got := mock.Platform()

			if got != platform {
				t.Errorf("Expected platform %s, got %s", platform, got)
			}
		})
	}
}

// TestSocialClientGetRateLimits tests rate limit information retrieval
func TestSocialClientGetRateLimits(t *testing.T) {
	resetTime := time.Now().Add(15 * time.Minute)

	mock := &MockSocialClient{
		platform: PlatformTwitter,
		rateLimits: RateLimitInfo{
			Limit:     300,
			Remaining: 150,
			ResetAt:   resetTime,
		},
	}

	limits := mock.GetRateLimits()

	if limits.Limit != 300 {
		t.Errorf("Expected limit 300, got %d", limits.Limit)
	}

	if limits.Remaining != 150 {
		t.Errorf("Expected remaining 150, got %d", limits.Remaining)
	}

	if !limits.ResetAt.Equal(resetTime) {
		t.Errorf("Expected reset time %v, got %v", resetTime, limits.ResetAt)
	}
}

// TestPostContentWithThread tests thread/reply functionality
func TestPostContentWithThread(t *testing.T) {
	mock := &MockSocialClient{
		platform: PlatformTwitter,
		postResult: &PostResult{
			PostID:  "tweet-456",
			PostURL: "https://twitter.com/user/status/456",
		},
	}

	parentID := "tweet-123"
	content := PostContent{
		Text:     "This is a reply in the thread",
		ThreadID: &parentID,
	}

	result, err := mock.Post(context.Background(), content)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if mock.lastContent.ThreadID == nil {
		t.Error("Expected thread ID to be set")
	}

	if *mock.lastContent.ThreadID != parentID {
		t.Errorf("Expected thread ID %s, got %s", parentID, *mock.lastContent.ThreadID)
	}
}

// TestPostContentWithMetadata tests platform-specific metadata
func TestPostContentWithMetadata(t *testing.T) {
	mock := &MockSocialClient{
		platform: PlatformLinkedIn,
		postResult: &PostResult{
			PostID:  "urn:li:share:789",
			PostURL: "https://linkedin.com/feed/update/urn:li:share:789",
		},
	}

	content := PostContent{
		Text: "Announcing our new feature",
		Metadata: map[string]any{
			"visibility": "PUBLIC",
			"hashtags":   []string{"#coding", "#opensource"},
		},
	}

	_, err := mock.Post(context.Background(), content)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if mock.lastContent.Metadata == nil {
		t.Error("Expected metadata to be captured")
	}

	if mock.lastContent.Metadata["visibility"] != "PUBLIC" {
		t.Error("Expected visibility metadata to be PUBLIC")
	}
}

// TestMediaAttachmentTypes tests different media types
func TestMediaAttachmentTypes(t *testing.T) {
	tests := []struct {
		name      string
		mediaType string
	}{
		{"image", MediaTypeImage},
		{"video", MediaTypeVideo},
		{"document", MediaTypeDocument},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attachment := MediaAttachment{
				Type:     tt.mediaType,
				URL:      "https://example.com/file",
				MimeType: "application/octet-stream",
			}

			if attachment.Type != tt.mediaType {
				t.Errorf("Expected type %s, got %s", tt.mediaType, attachment.Type)
			}
		})
	}
}

// TestRateLimitInfoIsLimited tests rate limit detection
func TestRateLimitInfoIsLimited(t *testing.T) {
	tests := []struct {
		name      string
		info      RateLimitInfo
		isLimited bool
	}{
		{
			name: "not limited",
			info: RateLimitInfo{
				Limit:     100,
				Remaining: 50,
				ResetAt:   time.Now().Add(1 * time.Hour),
			},
			isLimited: false,
		},
		{
			name: "limited - zero remaining",
			info: RateLimitInfo{
				Limit:     100,
				Remaining: 0,
				ResetAt:   time.Now().Add(15 * time.Minute),
			},
			isLimited: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.info.IsLimited()

			if got != tt.isLimited {
				t.Errorf("Expected IsLimited() = %v, got %v", tt.isLimited, got)
			}
		})
	}
}
