package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// BufferMaxCharLimit is the smallest character limit across Buffer-supported platforms.
// X/Twitter at 280 characters is the constraining platform.
const BufferMaxCharLimit = 280

// BufferClient posts to social media through the Buffer API.
// Uses the Buffer legacy REST API (v1) for reliability and simplicity.
// Implements a SocialClient-like interface for posting.
type BufferClient struct {
	accessToken string
	baseURL     string
	client      *http.Client
}

// BufferPostContent represents content to post through Buffer.
type BufferPostContent struct {
	Text string
}

// BufferPostResult represents the result of posting through Buffer.
type BufferPostResult struct {
	PostID   string
	Updates  []bufferUpdate
	Platform string
}

// bufferProfile represents a Buffer profile/channel (internal API response type).
type bufferProfile struct {
	ID        string `json:"id"`
	Service   string `json:"service"`
	Formatted string `json:"formatted_username"`
}

// bufferCreateResponse is the response from Buffer's create update API.
type bufferCreateResponse struct {
	Success bool           `json:"success"`
	Updates []bufferUpdate `json:"updates"`
	Message string         `json:"message"`
}

// bufferUpdate represents a single update in a Buffer response.
type bufferUpdate struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	ProfileID string `json:"profile_id"`
}

// NewBufferClient creates a new Buffer API client.
// accessToken: Buffer personal access token (Bearer token)
// baseURL: Override for testing (empty uses production URL)
func NewBufferClient(accessToken, baseURL string) *BufferClient {
	if baseURL == "" {
		baseURL = "https://api.bufferapp.com"
	}

	return &BufferClient{
		accessToken: accessToken,
		baseURL:     baseURL,
		client:      &http.Client{Timeout: 15 * time.Second},
	}
}

// ListProfiles returns all connected Buffer profiles/channels.
func (c *BufferClient) ListProfiles(ctx context.Context) ([]bufferProfile, error) {
	reqURL := c.baseURL + "/1/profiles.json"

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch profiles: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Buffer API error %d: %s", resp.StatusCode, string(body))
	}

	var profiles []bufferProfile
	if err := json.Unmarshal(body, &profiles); err != nil {
		return nil, fmt.Errorf("failed to parse profiles: %w", err)
	}

	return profiles, nil
}

// CreatePost creates a post across the specified Buffer profiles.
// profileIDs: list of Buffer profile IDs to post to
// text: the post content
// now: if true, post immediately; otherwise add to queue
func (c *BufferClient) CreatePost(ctx context.Context, profileIDs []string, text string, now bool) (*bufferCreateResponse, error) {
	reqURL := c.baseURL + "/1/updates/create.json"

	// Build form data
	form := url.Values{}
	form.Set("text", text)
	for _, id := range profileIDs {
		form.Add("profile_ids[]", id)
	}
	if now {
		form.Set("now", "true")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create post: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Buffer API error %d: %s", resp.StatusCode, string(body))
	}

	var result bufferCreateResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// Post implements a SocialClient-like interface for Buffer.
// It lists all profiles and posts to all of them.
func (c *BufferClient) Post(ctx context.Context, content BufferPostContent) (*BufferPostResult, error) {
	if err := c.ValidateContent(content); err != nil {
		return nil, err
	}

	// List all connected profiles
	profiles, err := c.ListProfiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list profiles: %w", err)
	}

	if len(profiles) == 0 {
		return nil, fmt.Errorf("no profiles connected in Buffer - connect at least one social account")
	}

	// Collect all profile IDs
	profileIDs := make([]string, len(profiles))
	for i, p := range profiles {
		profileIDs[i] = p.ID
	}

	// Post to all profiles immediately
	result, err := c.CreatePost(ctx, profileIDs, content.Text, true)
	if err != nil {
		return nil, err
	}

	if !result.Success {
		return nil, fmt.Errorf("Buffer post failed: %s", result.Message)
	}

	// Return first update ID as the post ID
	postID := ""
	if len(result.Updates) > 0 {
		postID = result.Updates[0].ID
	}

	return &BufferPostResult{
		PostID:   postID,
		Updates:  result.Updates,
		Platform: "buffer",
	}, nil
}

// ValidateContent checks if content meets Buffer's cross-platform requirements.
// Enforces 280 char limit (X/Twitter is the smallest platform).
func (c *BufferClient) ValidateContent(content BufferPostContent) error {
	if content.Text == "" {
		return fmt.Errorf("post text cannot be empty")
	}
	if len(content.Text) > BufferMaxCharLimit {
		return fmt.Errorf("post text exceeds %d character limit (got %d)", BufferMaxCharLimit, len(content.Text))
	}
	return nil
}

// Platform returns the platform identifier.
func (c *BufferClient) Platform() string {
	return "buffer"
}
