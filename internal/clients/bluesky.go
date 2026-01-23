package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mikelady/roxas/internal/services"
)

// Bluesky API error definitions
var (
	ErrBlueskyRateLimited    = errors.New("rate limited by Bluesky API")
	ErrBlueskyAuthentication = errors.New("Bluesky authentication failed")
	ErrBlueskyPostFailed     = errors.New("Bluesky post creation failed")
)

// Bluesky platform constants
const (
	BlueskyCharLimit  = 300
	BlueskyDefaultPDS = "https://bsky.social"
)

// Compile-time interface compliance check
var _ services.SocialClient = (*BlueskyClient)(nil)

// BlueskyClient implements SocialClient for Bluesky (AT Protocol)
type BlueskyClient struct {
	handle      string
	appPassword string
	pdsURL      string
	client      *http.Client

	// Session state (populated after auth)
	accessJwt  string
	refreshJwt string
	did        string
}

// NewBlueskyClient creates a new Bluesky API client
func NewBlueskyClient(handle, appPassword, pdsURL string) *BlueskyClient {
	if pdsURL == "" {
		pdsURL = BlueskyDefaultPDS
	}

	return &BlueskyClient{
		handle:      handle,
		appPassword: appPassword,
		pdsURL:      pdsURL,
		client:      &http.Client{Timeout: 30 * time.Second},
	}
}

// Platform returns the platform identifier
func (c *BlueskyClient) Platform() string {
	return "bluesky"
}

// Authenticate creates a session with Bluesky
func (c *BlueskyClient) Authenticate(ctx context.Context) error {
	return c.createSession(ctx)
}

// createSession authenticates with Bluesky and gets session tokens
func (c *BlueskyClient) createSession(ctx context.Context) error {
	url := fmt.Sprintf("%s/xrpc/com.atproto.server.createSession", c.pdsURL)

	payload := map[string]string{
		"identifier": c.handle,
		"password":   c.appPassword,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest {
		return ErrBlueskyAuthentication
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %d - %s", ErrBlueskyAuthentication, resp.StatusCode, string(body))
	}

	var sessionResp struct {
		AccessJwt  string `json:"accessJwt"`
		RefreshJwt string `json:"refreshJwt"`
		DID        string `json:"did"`
		Handle     string `json:"handle"`
	}

	if err := json.Unmarshal(body, &sessionResp); err != nil {
		return fmt.Errorf("failed to parse session response: %w", err)
	}

	c.accessJwt = sessionResp.AccessJwt
	c.refreshJwt = sessionResp.RefreshJwt
	c.did = sessionResp.DID

	return nil
}

// Post creates a new Bluesky post
func (c *BlueskyClient) Post(ctx context.Context, content services.PostContent) (*services.PostResult, error) {
	// Validate content first
	if err := c.ValidateContent(content); err != nil {
		return nil, err
	}

	// Authenticate if we don't have a session
	if c.accessJwt == "" {
		if err := c.createSession(ctx); err != nil {
			return nil, fmt.Errorf("failed to authenticate: %w", err)
		}
	}

	// Create post record
	url := fmt.Sprintf("%s/xrpc/com.atproto.repo.createRecord", c.pdsURL)

	now := time.Now().UTC().Format(time.RFC3339)

	record := map[string]interface{}{
		"$type":     "app.bsky.feed.post",
		"text":      content.Text,
		"createdAt": now,
	}

	// Add reply reference if this is a reply
	if content.ThreadID != nil && *content.ThreadID != "" {
		record["reply"] = map[string]interface{}{
			"root": map[string]string{
				"uri": *content.ThreadID,
				"cid": "",
			},
			"parent": map[string]string{
				"uri": *content.ThreadID,
				"cid": "",
			},
		}
	}

	payload := map[string]interface{}{
		"repo":       c.did,
		"collection": "app.bsky.feed.post",
		"record":     record,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.accessJwt)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create post: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, ErrBlueskyRateLimited
	}

	if resp.StatusCode == http.StatusUnauthorized {
		c.accessJwt = "" // Clear session to force re-auth
		return nil, ErrBlueskyAuthentication
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d - %s", ErrBlueskyPostFailed, resp.StatusCode, string(body))
	}

	var postResp struct {
		URI string `json:"uri"`
		CID string `json:"cid"`
	}

	if err := json.Unmarshal(body, &postResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Convert AT URI to web URL
	postURL := c.ATURIToWebURL(postResp.URI)

	return &services.PostResult{
		PostID:  postResp.URI,
		PostURL: postURL,
	}, nil
}

// ATURIToWebURL converts an AT Protocol URI to a Bluesky web URL
func (c *BlueskyClient) ATURIToWebURL(atURI string) string {
	// Parse: at://did:plc:xxx/app.bsky.feed.post/rkey
	// Result: https://bsky.app/profile/handle/post/rkey

	// Find the rkey (last path segment after "app.bsky.feed.post/")
	parts := strings.Split(atURI, "/")
	if len(parts) >= 5 {
		rkey := parts[len(parts)-1]
		return fmt.Sprintf("https://bsky.app/profile/%s/post/%s", c.handle, rkey)
	}

	return atURI // Fallback to AT URI if parsing fails
}

// ValidateContent checks if content is valid for Bluesky
func (c *BlueskyClient) ValidateContent(content services.PostContent) error {
	// Check if text is empty
	if len(content.Text) == 0 && len(content.Media) == 0 {
		return errors.New("post must have text or media")
	}

	// Check character limit
	if len(content.Text) > BlueskyCharLimit {
		return fmt.Errorf("text exceeds %d character limit (got %d)", BlueskyCharLimit, len(content.Text))
	}

	return nil
}

// GetRateLimits returns current rate limit status
// Note: Bluesky doesn't expose rate limits in the same way as other platforms
func (c *BlueskyClient) GetRateLimits() services.RateLimitInfo {
	return services.RateLimitInfo{
		Limit:     1666, // Approximate: 5000 posts per day / 3 = posts per 8 hours
		Remaining: 1666, // Unknown - would need to track
		ResetAt:   time.Now().Add(8 * time.Hour),
	}
}

// GetDID returns the authenticated user's DID
func (c *BlueskyClient) GetDID() string {
	return c.did
}

// IsAuthenticated returns true if the client has a valid session
func (c *BlueskyClient) IsAuthenticated() bool {
	return c.accessJwt != ""
}

// IsAuthError returns true if the error is an authentication error
func (c *BlueskyClient) IsAuthError(err error) bool {
	return errors.Is(err, ErrBlueskyAuthentication)
}

// IsRateLimitError returns true if the error is a rate limit error
func (c *BlueskyClient) IsRateLimitError(err error) bool {
	return errors.Is(err, ErrBlueskyRateLimited)
}
