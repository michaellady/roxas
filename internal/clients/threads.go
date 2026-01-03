package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/mikelady/roxas/internal/services"
)

// Threads API error definitions
var (
	ErrThreadsRateLimited    = errors.New("rate limited by Threads API")
	ErrThreadsAuthentication = errors.New("Threads authentication failed")
	ErrThreadsPostFailed     = errors.New("Threads post creation failed")
)

// Threads platform constants
const (
	ThreadsCharLimit  = 500
	ThreadsMediaLimit = 10
)

// Compile-time interface compliance check
var _ services.SocialClient = (*ThreadsClient)(nil)

// ThreadsClient implements SocialClient for Meta Threads API
type ThreadsClient struct {
	accessToken string
	baseURL     string
	client      *http.Client
	userID      string // Threads user ID

	// Rate limit state (cached from last API call)
	rateLimitMu sync.RWMutex
	rateLimit   services.RateLimitInfo
}

// NewThreadsClient creates a new Threads API client
func NewThreadsClient(accessToken string, baseURL string) *ThreadsClient {
	if baseURL == "" {
		baseURL = "https://graph.threads.net/v1.0"
	}

	tc := &ThreadsClient{
		accessToken: accessToken,
		baseURL:     baseURL,
		client:      &http.Client{Timeout: 30 * time.Second},
	}

	// Fetch the user ID from /me endpoint
	userID, err := tc.getUserID(context.Background())
	if err != nil {
		fmt.Printf("Warning: Failed to get Threads user ID: %v\n", err)
		tc.userID = ""
	} else {
		tc.userID = userID
	}

	return tc
}

// Platform returns the platform identifier
func (c *ThreadsClient) Platform() string {
	return services.PlatformThreads
}

// getUserID fetches the authenticated user's Threads ID
func (c *ThreadsClient) getUserID(ctx context.Context) (string, error) {
	url := fmt.Sprintf("%s/me?fields=id,username&access_token=%s", c.baseURL, c.accessToken)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call /me: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("/me returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result.ID, nil
}

// Post creates a new thread post.
// Threads API uses a two-step process:
// 1. Create a media container
// 2. Publish the container
func (c *ThreadsClient) Post(ctx context.Context, content services.PostContent) (*services.PostResult, error) {
	// Validate content first
	if err := c.ValidateContent(content); err != nil {
		return nil, err
	}

	// Step 1: Create media container
	containerID, err := c.createMediaContainer(ctx, content)
	if err != nil {
		return nil, fmt.Errorf("failed to create media container: %w", err)
	}

	// Step 2: Publish the container
	postID, err := c.publishContainer(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to publish thread: %w", err)
	}

	return &services.PostResult{
		PostID:  postID,
		PostURL: fmt.Sprintf("https://www.threads.net/@%s/post/%s", c.userID, postID),
	}, nil
}

// createMediaContainer creates a Threads media container
func (c *ThreadsClient) createMediaContainer(ctx context.Context, content services.PostContent) (string, error) {
	// Build the request body
	params := map[string]interface{}{
		"media_type":   "TEXT",
		"text":         content.Text,
		"access_token": c.accessToken,
	}

	// If there are media attachments, handle them
	if len(content.Media) > 0 {
		// For now, we only support images
		// Threads API requires image_url for IMAGE type
		media := content.Media[0]
		if media.URL != "" {
			params["media_type"] = "IMAGE"
			params["image_url"] = media.URL
		}
	}

	// Add reply reference if this is a reply (via ThreadID)
	if content.ThreadID != nil && *content.ThreadID != "" {
		params["reply_to_id"] = *content.ThreadID
	}

	jsonData, err := json.Marshal(params)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/me/threads", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Check for rate limiting
	if resp.StatusCode == http.StatusTooManyRequests {
		return "", ErrThreadsRateLimited
	}

	// Check for auth errors
	if resp.StatusCode == http.StatusUnauthorized {
		return "", ErrThreadsAuthentication
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("%w: %d - %s", ErrThreadsPostFailed, resp.StatusCode, string(body))
	}

	var containerResp struct {
		ID string `json:"id"`
	}

	if err := json.Unmarshal(body, &containerResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	return containerResp.ID, nil
}

// publishContainer publishes a previously created media container
func (c *ThreadsClient) publishContainer(ctx context.Context, containerID string) (string, error) {
	params := map[string]interface{}{
		"creation_id":  containerID,
		"access_token": c.accessToken,
	}

	jsonData, err := json.Marshal(params)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/me/threads_publish", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to publish thread: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return "", ErrThreadsRateLimited
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return "", ErrThreadsAuthentication
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("%w: %d - %s", ErrThreadsPostFailed, resp.StatusCode, string(body))
	}

	var publishResp struct {
		ID string `json:"id"`
	}

	if err := json.Unmarshal(body, &publishResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	return publishResp.ID, nil
}

// ValidateContent checks if content is valid for Threads.
// Returns an error describing validation failures, or nil if valid.
func (c *ThreadsClient) ValidateContent(content services.PostContent) error {
	// Check character limit
	if len(content.Text) > ThreadsCharLimit {
		return fmt.Errorf("text exceeds %d character limit (got %d)", ThreadsCharLimit, len(content.Text))
	}

	// Check if text is empty (required for non-media posts)
	if len(content.Text) == 0 && len(content.Media) == 0 {
		return errors.New("thread must have text or media")
	}

	// Check media limit
	if len(content.Media) > ThreadsMediaLimit {
		return fmt.Errorf("too many media attachments (max %d, got %d)", ThreadsMediaLimit, len(content.Media))
	}

	return nil
}

// GetRateLimits returns current rate limit status.
// Note: This returns cached rate limit info. For fresh data, call fetchRateLimits.
func (c *ThreadsClient) GetRateLimits() services.RateLimitInfo {
	c.rateLimitMu.RLock()
	defer c.rateLimitMu.RUnlock()
	return c.rateLimit
}

// FetchRateLimits fetches current rate limit status from the Threads API.
// This is a convenience method that updates the cached rate limits.
func (c *ThreadsClient) FetchRateLimits(ctx context.Context) (services.RateLimitInfo, error) {
	url := fmt.Sprintf("%s/me/threads_publishing_limit?fields=quota_usage,config&access_token=%s",
		c.baseURL, c.accessToken)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return services.RateLimitInfo{}, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return services.RateLimitInfo{}, fmt.Errorf("failed to get rate limits: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return services.RateLimitInfo{}, fmt.Errorf("failed to get rate limits: %d - %s", resp.StatusCode, string(body))
	}

	var limitResp struct {
		Data []struct {
			QuotaUsage int `json:"quota_usage"`
			Config     struct {
				QuotaTotal    int `json:"quota_total"`
				QuotaDuration int `json:"quota_duration"` // in seconds
			} `json:"config"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&limitResp); err != nil {
		return services.RateLimitInfo{}, fmt.Errorf("failed to decode response: %w", err)
	}

	var info services.RateLimitInfo
	if len(limitResp.Data) > 0 {
		data := limitResp.Data[0]
		info = services.RateLimitInfo{
			Limit:     data.Config.QuotaTotal,
			Remaining: data.Config.QuotaTotal - data.QuotaUsage,
			ResetAt:   time.Now().Add(time.Duration(data.Config.QuotaDuration) * time.Second),
		}
	}

	// Cache the rate limit info
	c.rateLimitMu.Lock()
	c.rateLimit = info
	c.rateLimitMu.Unlock()

	return info, nil
}
