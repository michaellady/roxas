// Package clients provides HTTP clients for external API integrations.
// This includes OpenAI (GPT-4, DALL-E) and LinkedIn API clients.
package clients

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Default models - cheap options for testing, can be overridden for production
const (
	DefaultChatModel  = "gpt-4o-mini" // ~200x cheaper than gpt-4
	DefaultImageModel = "dall-e-2"   // ~3-6x cheaper than dall-e-3
)

// OpenAIClient is the real production client for OpenAI API
type OpenAIClient struct {
	apiKey     string
	baseURL    string
	chatModel  string
	imageModel string
	client     *http.Client
}

// NewOpenAIClient creates a new OpenAI API client
// chatModel and imageModel can be empty to use defaults (gpt-4o-mini, dall-e-2)
func NewOpenAIClient(apiKey, baseURL, chatModel, imageModel string) *OpenAIClient {
	if baseURL == "" {
		baseURL = "https://api.openai.com"
	}
	if chatModel == "" {
		chatModel = DefaultChatModel
	}
	if imageModel == "" {
		imageModel = DefaultImageModel
	}

	return &OpenAIClient{
		apiKey:     apiKey,
		baseURL:    baseURL,
		chatModel:  chatModel,
		imageModel: imageModel,
		client:     &http.Client{},
	}
}

// CreateChatCompletion calls the ChatGPT API to generate text completions
func (c *OpenAIClient) CreateChatCompletion(prompt string) (string, error) {
	url := c.baseURL + "/v1/chat/completions"

	requestBody := map[string]interface{}{
		"model": c.chatModel,
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": 0.7,
		"max_tokens":  500,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Handle non-200 responses
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var response struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if response.Error.Message != "" {
		return "", fmt.Errorf("API error: %s", response.Error.Message)
	}

	if len(response.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}

	return response.Choices[0].Message.Content, nil
}

// GenerateImage calls the DALL-E API to generate images
func (c *OpenAIClient) GenerateImage(prompt string) (string, error) {
	url := c.baseURL + "/v1/images/generations"

	requestBody := map[string]interface{}{
		"model":  c.imageModel,
		"prompt": prompt,
		"n":      1,
		"size":   "1024x1024", // LinkedIn-optimized size
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Handle non-200 responses
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var response struct {
		Data []struct {
			URL string `json:"url"`
		} `json:"data"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if response.Error.Message != "" {
		return "", fmt.Errorf("API error: %s", response.Error.Message)
	}

	if len(response.Data) == 0 {
		return "", fmt.Errorf("no images in response")
	}

	return response.Data[0].URL, nil
}
