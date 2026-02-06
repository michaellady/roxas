package clients

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestChatGPTCompletion tests successful ChatGPT API call
func TestChatGPTCompletion(t *testing.T) {
	// Mock OpenAI API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("Expected /v1/chat/completions, got %s", r.URL.Path)
		}

		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		// Verify Authorization header
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Error("Missing or invalid Authorization header")
		}

		// Send mock response
		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]string{
						"content": "This is a test summary for LinkedIn post about database optimization.",
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create client with mock server URL
	client := NewOpenAIClient("test-api-key", server.URL, "", "")

	prompt := "Summarize this commit for LinkedIn"
	result, err := client.CreateChatCompletion(prompt)

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

// TestChatGPTHandlesAPIError tests handling of API errors (rate limit)
func TestChatGPTHandlesAPIError(t *testing.T) {
	// Mock server returning 429 rate limit
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error": {"message": "Rate limit exceeded"}}`))
	}))
	defer server.Close()

	client := NewOpenAIClient("test-api-key", server.URL, "", "")

	_, err := client.CreateChatCompletion("test prompt")

	if err == nil {
		t.Error("Expected error for rate limit, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "429") && !strings.Contains(errMsg, "rate limit") {
		t.Errorf("Expected rate limit error, got: %v", err)
	}
}

// TestChatGPTHandlesNetworkError tests handling of network failures
func TestChatGPTHandlesNetworkError(t *testing.T) {
	// Use invalid URL to simulate network error
	client := NewOpenAIClient("test-api-key", "http://invalid-domain-that-does-not-exist-12345.com", "", "")

	_, err := client.CreateChatCompletion("test prompt")

	if err == nil {
		t.Error("Expected network error, got nil")
	}
}

// TestDALLEImageGeneration tests successful DALL-E image generation
func TestDALLEImageGeneration(t *testing.T) {
	// Mock OpenAI DALL-E API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.URL.Path != "/v1/images/generations" {
			t.Errorf("Expected /v1/images/generations, got %s", r.URL.Path)
		}

		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		// Verify Authorization header
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Error("Missing or invalid Authorization header")
		}

		// Send mock response
		response := map[string]interface{}{
			"data": []map[string]string{
				{
					"url": "https://example.com/generated-image.png",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create client with mock server URL
	client := NewOpenAIClient("test-api-key", server.URL, "", "")

	prompt := "Professional LinkedIn image about software engineering"
	imageURL, err := client.GenerateImage(prompt)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if imageURL == "" {
		t.Error("Expected non-empty image URL")
	}

	if !strings.HasPrefix(imageURL, "http") {
		t.Errorf("Expected valid URL, got: %s", imageURL)
	}
}

// TestDALLEHandlesAPIError tests DALL-E API error handling
func TestDALLEHandlesAPIError(t *testing.T) {
	// Mock server returning error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": {"message": "Invalid prompt"}}`))
	}))
	defer server.Close()

	client := NewOpenAIClient("test-api-key", server.URL, "", "")

	_, err := client.GenerateImage("test prompt")

	if err == nil {
		t.Error("Expected error for bad request, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "400") && !strings.Contains(errMsg, "error") {
		t.Errorf("Expected API error, got: %v", err)
	}
}

// TestOpenAIClientValidatesAPIKey tests API key validation
func TestOpenAIClientValidatesAPIKey(t *testing.T) {
	// Mock server that checks API key
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-valid-key" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": {"message": "Invalid API key"}}`))
			return
		}

		// Valid response
		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": "success"}},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Test with valid key
	validClient := NewOpenAIClient("test-valid-key", server.URL, "", "")
	_, err := validClient.CreateChatCompletion("test")
	if err != nil {
		t.Errorf("Expected success with valid key, got error: %v", err)
	}

	// Test with invalid key
	invalidClient := NewOpenAIClient("invalid-key", server.URL, "", "")
	_, err = invalidClient.CreateChatCompletion("test")
	if err == nil {
		t.Error("Expected error with invalid API key, got nil")
	}
}

// TestChatGPTCompletion_EmptyChoices tests handling of empty choices
func TestChatGPTCompletion_EmptyChoices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"choices": []map[string]interface{}{},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewOpenAIClient("test-api-key", server.URL, "", "")
	_, err := client.CreateChatCompletion("test")

	if err == nil {
		t.Error("Expected error for empty choices")
	}
	if !strings.Contains(err.Error(), "no choices") {
		t.Errorf("Expected 'no choices' error, got: %v", err)
	}
}

// TestChatGPTCompletion_APIErrorMessage tests handling of error in response body
func TestChatGPTCompletion_APIErrorMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"error": map[string]string{
				"message": "model overloaded",
			},
			"choices": []map[string]interface{}{},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewOpenAIClient("test-api-key", server.URL, "", "")
	_, err := client.CreateChatCompletion("test")

	if err == nil {
		t.Error("Expected error for API error message")
	}
	if !strings.Contains(err.Error(), "model overloaded") {
		t.Errorf("Expected 'model overloaded' error, got: %v", err)
	}
}

// TestChatGPTCompletion_InvalidJSON tests handling of invalid JSON response
func TestChatGPTCompletion_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not valid json`))
	}))
	defer server.Close()

	client := NewOpenAIClient("test-api-key", server.URL, "", "")
	_, err := client.CreateChatCompletion("test")

	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

// TestDALLEGenerateImage_EmptyData tests handling of empty data array
func TestDALLEGenerateImage_EmptyData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"data": []map[string]string{},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewOpenAIClient("test-api-key", server.URL, "", "")
	_, err := client.GenerateImage("test")

	if err == nil {
		t.Error("Expected error for empty data")
	}
	if !strings.Contains(err.Error(), "no images") {
		t.Errorf("Expected 'no images' error, got: %v", err)
	}
}

// TestDALLEGenerateImage_APIErrorMessage tests handling of error in image response
func TestDALLEGenerateImage_APIErrorMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"error": map[string]string{
				"message": "content policy violation",
			},
			"data": []map[string]string{},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewOpenAIClient("test-api-key", server.URL, "", "")
	_, err := client.GenerateImage("test")

	if err == nil {
		t.Error("Expected error for API error message")
	}
	if !strings.Contains(err.Error(), "content policy violation") {
		t.Errorf("Expected 'content policy violation' error, got: %v", err)
	}
}

// TestDALLEGenerateImage_InvalidJSON tests invalid JSON response
func TestDALLEGenerateImage_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not valid json`))
	}))
	defer server.Close()

	client := NewOpenAIClient("test-api-key", server.URL, "", "")
	_, err := client.GenerateImage("test")

	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

// TestDALLEGenerateImage_NetworkError tests network failure
func TestDALLEGenerateImage_NetworkError(t *testing.T) {
	client := NewOpenAIClient("test-api-key", "http://invalid-domain-that-does-not-exist-12345.com", "", "")
	_, err := client.GenerateImage("test")

	if err == nil {
		t.Error("Expected network error")
	}
}

// TestNewOpenAIClient_CustomModels tests custom model configuration
func TestNewOpenAIClient_CustomModels(t *testing.T) {
	client := NewOpenAIClient("key", "https://api.example.com", "gpt-4", "dall-e-3")
	// Verify client was created (models are private but we can test the client works)
	if client == nil {
		t.Error("Expected non-nil client")
	}
}

// TestNewOpenAIClient_DefaultModels tests default model fallback
func TestNewOpenAIClient_DefaultModels(t *testing.T) {
	client := NewOpenAIClient("key", "", "", "")
	if client == nil {
		t.Error("Expected non-nil client")
	}
}

// TestDALLEImageSize tests that DALL-E uses correct image size
func TestDALLEImageSize(t *testing.T) {
	// Mock server that verifies image size parameter
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var requestBody map[string]interface{}
		json.NewDecoder(r.Body).Decode(&requestBody)

		// Verify size parameter (should be 1024x1024 for LinkedIn)
		size, ok := requestBody["size"].(string)
		if !ok || (size != "1024x1024" && size != "1792x1024") {
			t.Errorf("Expected size 1024x1024 or 1792x1024, got: %v", requestBody["size"])
		}

		response := map[string]interface{}{
			"data": []map[string]string{
				{"url": "https://example.com/image.png"},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewOpenAIClient("test-api-key", server.URL, "", "")
	_, err := client.GenerateImage("test prompt")

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}
