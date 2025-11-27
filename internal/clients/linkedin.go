package clients

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

// LinkedInClient is the real production client for LinkedIn API
type LinkedInClient struct {
	accessToken    string
	baseURL        string
	client         *http.Client
	personURN      string // LinkedIn person URN (e.g., urn:li:person:ABC123)
	linkedInVersion string // LinkedIn API version (YYYYMM format)
}

// NewLinkedInClient creates a new LinkedIn API client
func NewLinkedInClient(accessToken string, baseURL string) *LinkedInClient {
	if baseURL == "" {
		baseURL = "https://api.linkedin.com"
	}

	client := &LinkedInClient{
		accessToken:     accessToken,
		baseURL:         baseURL,
		client:          &http.Client{},
		linkedInVersion: "202510", // LinkedIn API version (October 2025)
	}

	// Fetch the person URN from /me endpoint
	personURN, err := client.getPersonURN()
	if err != nil {
		// Log error but don't fail - will fail later when trying to post
		fmt.Printf("Warning: Failed to get LinkedIn person URN: %v\n", err)
		client.personURN = "urn:li:person:UNKNOWN"
	} else {
		client.personURN = personURN
	}

	return client
}

// getPersonURN fetches the authenticated user's LinkedIn person URN
func (c *LinkedInClient) getPersonURN() (string, error) {
	// Try OpenID Connect userinfo endpoint (requires openid + profile scopes)
	req, err := http.NewRequest("GET", c.baseURL+"/v2/userinfo", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call /userinfo endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("/userinfo endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Sub string `json:"sub"` // OpenID Connect subject identifier
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode /userinfo response: %w", err)
	}

	if result.Sub == "" {
		return "", fmt.Errorf("no sub found in /userinfo response")
	}

	// sub format is already a URN like "urn:li:person:ABC123" or just the ID
	// If it's already a URN, use it; otherwise format it
	if len(result.Sub) > 0 && result.Sub[:7] == "urn:li:" {
		return result.Sub, nil
	}

	// Format as LinkedIn person URN
	return "urn:li:person:" + result.Sub, nil
}

// UploadImage uploads an image to LinkedIn and returns the asset URN
func (c *LinkedInClient) UploadImage(imagePath string) (string, error) {
	// Verify file exists
	file, err := os.Open(imagePath)
	if err != nil {
		return "", fmt.Errorf("failed to open image file: %w", err)
	}
	defer file.Close()

	// Read file content for validation
	_, err = io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("failed to read image file: %w", err)
	}

	// Step 1: Initialize upload using new Images API
	initURL := c.baseURL + "/rest/images?action=initializeUpload"

	initRequest := map[string]interface{}{
		"initializeUploadRequest": map[string]interface{}{
			"owner": c.personURN,
		},
	}

	jsonData, err := json.Marshal(initRequest)
	if err != nil {
		return "", fmt.Errorf("failed to marshal init request: %w", err)
	}

	req, err := http.NewRequest("POST", initURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create init request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Linkedin-Version", c.linkedInVersion)
	req.Header.Set("X-Restli-Protocol-Version", "2.0.0")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to initialize upload: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read init response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("initialize upload failed %d: %s", resp.StatusCode, string(body))
	}

	var initResponse struct {
		Value struct {
			UploadURL          string `json:"uploadUrl"`
			Image              string `json:"image"`
			UploadURLExpiresAt int64  `json:"uploadUrlExpiresAt"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &initResponse); err != nil {
		return "", fmt.Errorf("failed to parse init response: %w", err)
	}

	uploadURL := initResponse.Value.UploadURL
	imageURN := initResponse.Value.Image

	if uploadURL == "" || imageURN == "" {
		return "", fmt.Errorf("missing upload URL or image URN in response: %s", string(body))
	}

	// Step 2: Upload image binary to the upload URL
	// Re-read the image file for uploading
	imageData, err := os.ReadFile(imagePath)
	if err != nil {
		return "", fmt.Errorf("failed to re-read image file: %w", err)
	}

	uploadReq, err := http.NewRequest("POST", uploadURL, bytes.NewBuffer(imageData))
	if err != nil {
		return "", fmt.Errorf("failed to create upload request: %w", err)
	}

	uploadReq.Header.Set("Authorization", "Bearer "+c.accessToken)
	uploadReq.Header.Set("Content-Type", "application/octet-stream")

	uploadResp, err := c.client.Do(uploadReq)
	if err != nil {
		return "", fmt.Errorf("failed to upload image: %w", err)
	}
	defer uploadResp.Body.Close()

	if uploadResp.StatusCode != http.StatusCreated && uploadResp.StatusCode != http.StatusOK {
		uploadBody, _ := io.ReadAll(uploadResp.Body)
		return "", fmt.Errorf("image upload failed %d: %s", uploadResp.StatusCode, string(uploadBody))
	}

	return imageURN, nil
}

// CreatePost creates a LinkedIn post using the new Posts API
func (c *LinkedInClient) CreatePost(text string, imageURN string) (string, error) {
	url := c.baseURL + "/rest/posts"

	// Build post request using new Posts API format
	postRequest := map[string]interface{}{
		"author":         c.personURN,
		"commentary":     text,
		"visibility":     "PUBLIC",
		"lifecycleState": "PUBLISHED",
		"distribution": map[string]interface{}{
			"feedDistribution":    "MAIN_FEED",
			"targetEntities":      []interface{}{},
			"thirdPartyDistributionChannels": []interface{}{},
		},
		"isReshareDisabledByAuthor": false,
	}

	// Add media if image URN provided
	if imageURN != "" {
		postRequest["content"] = map[string]interface{}{
			"media": map[string]interface{}{
				"id": imageURN,
			},
		}
	}

	jsonData, err := json.Marshal(postRequest)
	if err != nil {
		return "", fmt.Errorf("failed to marshal post request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create post request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("LinkedIn-Version", c.linkedInVersion)
	req.Header.Set("X-Restli-Protocol-Version", "2.0.0")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to create post: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read post response: %w", err)
	}

	// Handle non-success responses
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("create post failed %d: %s", resp.StatusCode, string(body))
	}

	// Get post ID from x-restli-id header (new Posts API returns ID in header)
	postID := resp.Header.Get("x-restli-id")
	if postID == "" {
		// Fallback: try to parse from body
		var postResponse struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &postResponse); err == nil && postResponse.ID != "" {
			postID = postResponse.ID
		}
	}

	if postID == "" {
		return "", fmt.Errorf("no post ID in response (header or body)")
	}

	return postID, nil
}

// uploadBinary uploads the binary image content to LinkedIn
// (helper method for production use - not needed for MVP testing)
func (c *LinkedInClient) uploadBinary(uploadURL string, imageData []byte, filename string) error {
	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", filepath.Base(filename))
	if err != nil {
		return fmt.Errorf("failed to create form file: %w", err)
	}

	if _, err := part.Write(imageData); err != nil {
		return fmt.Errorf("failed to write image data: %w", err)
	}

	writer.Close()

	req, err := http.NewRequest("PUT", uploadURL, body)
	if err != nil {
		return fmt.Errorf("failed to create upload request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload binary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("binary upload failed %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}
