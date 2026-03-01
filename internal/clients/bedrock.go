package clients

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

// DefaultBedrockModel is the default Claude model for Bedrock.
// Sonnet 4.5 provides a good balance of quality and speed.
const DefaultBedrockModel = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"

// BedrockClient calls the AWS Bedrock Converse API for Claude chat completions.
// It implements the ChatClient interface (services/post_generator.go).
// Uses SigV4-signed HTTP requests to avoid needing the bedrockruntime SDK module.
type BedrockClient struct {
	region  string
	modelID string
	baseURL string // Override for testing; empty uses real Bedrock endpoint
	creds   aws.CredentialsProvider
	client  *http.Client
}

// NewBedrockClient creates a new Bedrock client.
// region: AWS region (defaults to us-east-1)
// modelID: Bedrock model ID (defaults to DefaultBedrockModel)
// baseURL: Override endpoint for testing (empty for production)
func NewBedrockClient(region, modelID, baseURL string) *BedrockClient {
	if region == "" {
		region = "us-east-1"
	}
	if modelID == "" {
		modelID = DefaultBedrockModel
	}

	return &BedrockClient{
		region:  region,
		modelID: modelID,
		baseURL: baseURL,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// BedrockConverseRequest is the request body for the Bedrock Converse API.
type BedrockConverseRequest struct {
	Messages        []BedrockMessage       `json:"messages"`
	InferenceConfig BedrockInferenceConfig `json:"inferenceConfig"`
}

// BedrockMessage represents a message in the Bedrock Converse API.
type BedrockMessage struct {
	Role    string           `json:"role"`
	Content []BedrockContent `json:"content"`
}

// BedrockContent represents a content block in a Bedrock message.
type BedrockContent struct {
	Text string `json:"text"`
}

// BedrockInferenceConfig holds inference parameters for the Converse API.
type BedrockInferenceConfig struct {
	MaxTokens   int     `json:"maxTokens"`
	Temperature float64 `json:"temperature"`
}

// BedrockConverseResponse is the response from the Bedrock Converse API.
type BedrockConverseResponse struct {
	Output BedrockOutput `json:"output"`
}

// BedrockOutput is the output wrapper in a Converse response.
type BedrockOutput struct {
	Message BedrockMessage `json:"message"`
}

// ModelID returns the configured Bedrock model ID.
func (c *BedrockClient) ModelID() string {
	return c.modelID
}

// CreateChatCompletion calls the Bedrock Converse API to generate text.
// Implements the ChatClient interface used by PostGenerator.
func (c *BedrockClient) CreateChatCompletion(prompt string) (string, error) {
	reqBody := BedrockConverseRequest{
		Messages: []BedrockMessage{
			{
				Role: "user",
				Content: []BedrockContent{
					{Text: prompt},
				},
			},
		},
		InferenceConfig: BedrockInferenceConfig{
			MaxTokens:   500,
			Temperature: 0.7,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Build endpoint URL
	endpoint := c.baseURL
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com", c.region)
	}

	// URL-encode the model ID: colons in model IDs need encoding
	encodedModelID := strings.ReplaceAll(c.modelID, ":", "%3A")
	url := fmt.Sprintf("%s/model/%s/converse", endpoint, encodedModelID)

	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Sign with SigV4 for real Bedrock calls (skip for test servers)
	if c.baseURL == "" {
		if err := c.signRequest(req, jsonData); err != nil {
			return "", fmt.Errorf("failed to sign request: %w", err)
		}
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Bedrock API error %d: %s", resp.StatusCode, string(body))
	}

	var response BedrockConverseResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(response.Output.Message.Content) == 0 {
		return "", fmt.Errorf("no content in Bedrock response")
	}

	return response.Output.Message.Content[0].Text, nil
}

// signRequest adds SigV4 signature headers to the HTTP request.
func (c *BedrockClient) signRequest(req *http.Request, payload []byte) error {
	ctx := context.Background()

	// Load credentials from the default chain (env vars, IAM role, etc.)
	if c.creds == nil {
		cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(c.region))
		if err != nil {
			return fmt.Errorf("failed to load AWS config: %w", err)
		}
		c.creds = cfg.Credentials
	}

	credentials, err := c.creds.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve credentials: %w", err)
	}

	// Compute payload hash
	hash := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(hash[:])

	// Sign the request
	signer := v4.NewSigner()
	err = signer.SignHTTP(ctx, credentials, req, payloadHash, "bedrock", c.region, time.Now())
	if err != nil {
		return fmt.Errorf("failed to sign HTTP request: %w", err)
	}

	return nil
}
