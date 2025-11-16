package services

import (
	"fmt"
)

// LinkedInClient interface for LinkedIn API operations
type LinkedInClient interface {
	UploadImage(imagePath string) (string, error)
	CreatePost(text string, imageURN string) (string, error)
}

// LinkedInPoster handles posting content to LinkedIn
type LinkedInPoster struct {
	client      LinkedInClient
	accessToken string
}

// NewLinkedInPoster creates a new LinkedIn poster with the given client and access token
func NewLinkedInPoster(client LinkedInClient, accessToken string) *LinkedInPoster {
	return &LinkedInPoster{
		client:      client,
		accessToken: accessToken,
	}
}

// Post creates a LinkedIn post with text and optional image
func (p *LinkedInPoster) Post(text string, imagePath string) (string, error) {
	// Validate text input
	if text == "" {
		return "", fmt.Errorf("post text is empty")
	}

	var imageURN string
	var err error

	// Upload image if provided
	if imagePath != "" {
		imageURN, err = p.client.UploadImage(imagePath)
		if err != nil {
			return "", fmt.Errorf("failed to upload image: %w", err)
		}
	}

	// Create post with text and optional image
	postID, err := p.client.CreatePost(text, imageURN)
	if err != nil {
		return "", fmt.Errorf("failed to create post: %w", err)
	}

	// Convert post ID to LinkedIn URL
	postURL := convertPostIDToURL(postID)

	return postURL, nil
}

// convertPostIDToURL converts a LinkedIn post URN to a shareable URL
func convertPostIDToURL(postID string) string {
	// LinkedIn post URNs are in format: urn:li:share:1234567890
	// Convert to URL format: https://www.linkedin.com/feed/update/urn:li:share:1234567890
	return fmt.Sprintf("https://www.linkedin.com/feed/update/%s", postID)
}
