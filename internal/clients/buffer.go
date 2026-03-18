package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// BufferMaxCharLimit is the smallest character limit across Buffer-supported platforms.
// X/Twitter at 280 characters is the constraining platform.
const BufferMaxCharLimit = 280

// BufferClient posts to social media through the Buffer GraphQL API.
// Uses the Buffer GraphQL API at api.buffer.com with Bearer token auth.
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

// BufferProfile represents a Buffer channel.
type BufferProfile struct {
	ID        string `json:"id"`
	Service   string `json:"service"`
	Formatted string `json:"formatted_username"`
}

// bufferCreateResponse is the aggregated response from Buffer's createPost mutations.
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

// GraphQL response types

type graphqlResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type organizationsResponse struct {
	Account struct {
		Organizations []struct {
			ID string `json:"id"`
		} `json:"organizations"`
	} `json:"account"`
}

type channelsResponse struct {
	Channels []struct {
		ID                string `json:"id"`
		Service           string `json:"service"`
		FormattedUsername string `json:"formattedUsername"`
	} `json:"channels"`
}

type createPostResponse struct {
	CreatePost struct {
		Post *struct {
			ID   string `json:"id"`
			Text string `json:"text"`
		} `json:"post"`
		Message string `json:"message"`
	} `json:"createPost"`
}

// NewBufferClient creates a new Buffer API client.
// accessToken: Buffer personal access token (Bearer token)
// baseURL: Override for testing (empty uses production URL)
func NewBufferClient(accessToken, baseURL string) *BufferClient {
	if baseURL == "" {
		baseURL = "https://api.buffer.com"
	}

	return &BufferClient{
		accessToken: accessToken,
		baseURL:     baseURL,
		client:      &http.Client{Timeout: 15 * time.Second},
	}
}

// graphql sends a GraphQL request to the Buffer API and returns the data field.
func (c *BufferClient) graphql(ctx context.Context, query string, variables map[string]interface{}) (json.RawMessage, error) {
	reqBody := map[string]interface{}{
		"query": query,
	}
	if variables != nil {
		reqBody["variables"] = variables
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GraphQL request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Buffer API error %d: %s", resp.StatusCode, string(body))
	}

	var gqlResp graphqlResponse
	if err := json.Unmarshal(body, &gqlResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL error: %s", gqlResp.Errors[0].Message)
	}

	return gqlResp.Data, nil
}

// getOrganizationID fetches the first organization ID from the account.
func (c *BufferClient) getOrganizationID(ctx context.Context) (string, error) {
	query := `query { account { organizations { id } } }`

	data, err := c.graphql(ctx, query, nil)
	if err != nil {
		return "", fmt.Errorf("failed to fetch organizations: %w", err)
	}

	var result organizationsResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return "", fmt.Errorf("failed to parse organizations: %w", err)
	}

	if len(result.Account.Organizations) == 0 {
		return "", fmt.Errorf("no organizations found in Buffer account")
	}

	return result.Account.Organizations[0].ID, nil
}

// ListProfiles returns all connected Buffer channels.
func (c *BufferClient) ListProfiles(ctx context.Context) ([]BufferProfile, error) {
	orgID, err := c.getOrganizationID(ctx)
	if err != nil {
		return nil, err
	}

	query := `query($input: ChannelsInput!) { channels(input: $input) { id service formattedUsername } }`
	variables := map[string]interface{}{
		"input": map[string]interface{}{
			"organizationId": orgID,
		},
	}

	data, err := c.graphql(ctx, query, variables)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch channels: %w", err)
	}

	var result channelsResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse channels: %w", err)
	}

	profiles := make([]BufferProfile, len(result.Channels))
	for i, ch := range result.Channels {
		profiles[i] = BufferProfile{
			ID:        ch.ID,
			Service:   ch.Service,
			Formatted: ch.FormattedUsername,
		}
	}

	return profiles, nil
}

// CreatePost creates a post across the specified Buffer channels.
// profileIDs: list of Buffer channel IDs to post to
// text: the post content
// now: if true, post immediately; otherwise add to queue
func (c *BufferClient) CreatePost(ctx context.Context, profileIDs []string, text string, now bool) (*bufferCreateResponse, error) {
	mutation := `mutation($input: CreatePostInput!) {
		createPost(input: $input) {
			... on PostActionSuccess { post { id text } }
			... on MutationError { message }
		}
	}`

	var updates []bufferUpdate
	for _, channelID := range profileIDs {
		input := map[string]interface{}{
			"text":      text,
			"channelId": channelID,
		}
		if now {
			input["dueAt"] = time.Now().UTC().Format(time.RFC3339)
			input["schedulingType"] = "now"
		}

		variables := map[string]interface{}{
			"input": input,
		}

		data, err := c.graphql(ctx, mutation, variables)
		if err != nil {
			return nil, fmt.Errorf("failed to create post for channel %s: %w", channelID, err)
		}

		var result createPostResponse
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("failed to parse create post response: %w", err)
		}

		if result.CreatePost.Message != "" {
			return &bufferCreateResponse{
				Success: false,
				Message: result.CreatePost.Message,
			}, nil
		}

		if result.CreatePost.Post != nil {
			updates = append(updates, bufferUpdate{
				ID:        result.CreatePost.Post.ID,
				Status:    "sent",
				ProfileID: channelID,
			})
		}
	}

	return &bufferCreateResponse{
		Success: true,
		Updates: updates,
	}, nil
}

// Post implements a SocialClient-like interface for Buffer.
// It lists all channels and posts to all of them.
func (c *BufferClient) Post(ctx context.Context, content BufferPostContent) (*BufferPostResult, error) {
	if err := c.ValidateContent(content); err != nil {
		return nil, err
	}

	// List all connected channels
	profiles, err := c.ListProfiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list profiles: %w", err)
	}

	if len(profiles) == 0 {
		return nil, fmt.Errorf("no profiles connected in Buffer - connect at least one social account")
	}

	// Collect all channel IDs
	profileIDs := make([]string, len(profiles))
	for i, p := range profiles {
		profileIDs[i] = p.ID
	}

	// Post to all channels immediately
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
