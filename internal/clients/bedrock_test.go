package clients

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBedrockChatCompletion tests successful Bedrock Converse API call
func TestBedrockChatCompletion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request path contains /model/ and /converse
		if !strings.Contains(r.URL.Path, "/model/") || !strings.Contains(r.URL.Path, "/converse") {
			t.Errorf("Expected /model/{modelId}/converse path, got %s", r.URL.Path)
		}

		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		// Verify Content-Type header
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", ct)
		}

		// Parse and verify request body
		var reqBody BedrockConverseRequest
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}

		if len(reqBody.Messages) == 0 {
			t.Error("Expected at least one message")
		}

		if reqBody.Messages[0].Role != "user" {
			t.Errorf("Expected role 'user', got %s", reqBody.Messages[0].Role)
		}

		// Send mock Bedrock Converse response
		response := BedrockConverseResponse{
			Output: BedrockOutput{
				Message: BedrockMessage{
					Role: "assistant",
					Content: []BedrockContent{
						{Text: "This is a test summary about database optimization from Claude via Bedrock."},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create client with mock server (skips SigV4 signing in test mode)
	client := NewBedrockClient("us-east-1", "", server.URL)

	result, err := client.CreateChatCompletion("Summarize this commit for social media")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == "" {
		t.Error("Expected non-empty result")
	}

	if !strings.Contains(result, "database optimization") {
		t.Errorf("Expected result to contain 'database optimization', got: %s", result)
	}
}

// TestBedrockHandlesAPIError tests handling of Bedrock API errors
func TestBedrockHandlesAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"message": "Rate exceeded"}`))
	}))
	defer server.Close()

	client := NewBedrockClient("us-east-1", "", server.URL)

	_, err := client.CreateChatCompletion("test prompt")
	if err == nil {
		t.Error("Expected error for rate limit, got nil")
	}

	if !strings.Contains(err.Error(), "429") {
		t.Errorf("Expected 429 error, got: %v", err)
	}
}

// TestBedrockHandlesNetworkError tests handling of network failures
func TestBedrockHandlesNetworkError(t *testing.T) {
	client := NewBedrockClient("us-east-1", "", "http://invalid-domain-that-does-not-exist-12345.com")

	_, err := client.CreateChatCompletion("test prompt")
	if err == nil {
		t.Error("Expected network error, got nil")
	}
}

// TestBedrockEmptyContent tests handling of empty response content
func TestBedrockEmptyContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := BedrockConverseResponse{
			Output: BedrockOutput{
				Message: BedrockMessage{
					Role:    "assistant",
					Content: []BedrockContent{},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewBedrockClient("us-east-1", "", server.URL)
	_, err := client.CreateChatCompletion("test")

	if err == nil {
		t.Error("Expected error for empty content")
	}
	if !strings.Contains(err.Error(), "no content") {
		t.Errorf("Expected 'no content' error, got: %v", err)
	}
}

// TestBedrockInvalidJSON tests handling of invalid JSON response
func TestBedrockInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`not valid json`))
	}))
	defer server.Close()

	client := NewBedrockClient("us-east-1", "", server.URL)
	_, err := client.CreateChatCompletion("test")

	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

// TestBedrockCustomModelID tests custom model ID configuration
func TestBedrockCustomModelID(t *testing.T) {
	var capturedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		response := BedrockConverseResponse{
			Output: BedrockOutput{
				Message: BedrockMessage{
					Role:    "assistant",
					Content: []BedrockContent{{Text: "ok"}},
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewBedrockClient("us-west-2", "us.anthropic.claude-sonnet-4-5-20250929-v1:0", server.URL)
	_, err := client.CreateChatCompletion("test")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !strings.Contains(capturedPath, "us.anthropic.claude-sonnet-4-5-20250929-v1") {
		t.Errorf("Expected custom model ID in path, got: %s", capturedPath)
	}
}

// TestBedrockDefaultModelID tests default model ID fallback
func TestBedrockDefaultModelID(t *testing.T) {
	var capturedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		response := BedrockConverseResponse{
			Output: BedrockOutput{
				Message: BedrockMessage{
					Role:    "assistant",
					Content: []BedrockContent{{Text: "ok"}},
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewBedrockClient("us-east-1", "", server.URL)
	_, _ = client.CreateChatCompletion("test")

	if !strings.Contains(capturedPath, DefaultBedrockModel) {
		t.Errorf("Expected default model ID '%s' in path, got: %s", DefaultBedrockModel, capturedPath)
	}
}

// TestBedrockRequestBody tests that the request body is correctly formed
func TestBedrockRequestBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody BedrockConverseRequest
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}

		// Verify message structure
		if len(reqBody.Messages) != 1 {
			t.Fatalf("Expected 1 message, got %d", len(reqBody.Messages))
		}
		if reqBody.Messages[0].Role != "user" {
			t.Errorf("Expected role 'user', got %s", reqBody.Messages[0].Role)
		}
		if len(reqBody.Messages[0].Content) != 1 {
			t.Fatalf("Expected 1 content block, got %d", len(reqBody.Messages[0].Content))
		}
		if reqBody.Messages[0].Content[0].Text != "hello world" {
			t.Errorf("Expected text 'hello world', got %s", reqBody.Messages[0].Content[0].Text)
		}

		// Verify inference config
		if reqBody.InferenceConfig.MaxTokens != 500 {
			t.Errorf("Expected maxTokens 500, got %d", reqBody.InferenceConfig.MaxTokens)
		}
		if reqBody.InferenceConfig.Temperature != 0.7 {
			t.Errorf("Expected temperature 0.7, got %f", reqBody.InferenceConfig.Temperature)
		}

		response := BedrockConverseResponse{
			Output: BedrockOutput{
				Message: BedrockMessage{
					Role:    "assistant",
					Content: []BedrockContent{{Text: "response"}},
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewBedrockClient("us-east-1", "", server.URL)
	_, err := client.CreateChatCompletion("hello world")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

// TestNewBedrockClient_Defaults tests client creation with defaults
func TestNewBedrockClient_Defaults(t *testing.T) {
	client := NewBedrockClient("", "", "")
	if client == nil {
		t.Error("Expected non-nil client")
	}
}
