package services

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// MockDALLEClient simulates DALL-E API for testing
type MockDALLEClient struct {
	ImageURL string
	Error    error
}

func (m *MockDALLEClient) GenerateImage(prompt string) (string, error) {
	if m.Error != nil {
		return "", m.Error
	}
	return m.ImageURL, nil
}

// TestGenerateImageReturnsPath tests that image generation returns a file path
func TestGenerateImageReturnsPath(t *testing.T) {
	mockClient := &MockDALLEClient{
		ImageURL: "https://fake.openai.com/images/test-image.png",
	}

	generator := NewImageGenerator(mockClient)
	summary := "Professional summary about performance improvement with metrics and business impact"

	imagePath, err := generator.Generate(summary)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if imagePath == "" {
		t.Error("Expected non-empty image path")
	}

	// Clean up
	if imagePath != "" {
		os.Remove(imagePath)
	}
}

// TestImageFileExists tests that generated image file actually exists
func TestImageFileExists(t *testing.T) {
	mockClient := &MockDALLEClient{
		ImageURL: "https://fake.openai.com/images/test.png",
	}

	generator := NewImageGenerator(mockClient)
	summary := "Security improvement with OAuth2 authentication for enterprise access"

	imagePath, err := generator.Generate(summary)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(imagePath); os.IsNotExist(err) {
		t.Errorf("Image file does not exist at path: %s", imagePath)
	}

	// Clean up
	os.Remove(imagePath)
}

// TestImagePromptBuilding tests that DALL-E prompt is constructed properly
func TestImagePromptBuilding(t *testing.T) {
	summary := "Enhanced database performance through intelligent query optimization"

	prompt := buildImagePrompt(summary)

	// Prompt should include the summary context
	if !strings.Contains(prompt, "performance") || !strings.Contains(prompt, "database") {
		t.Error("Image prompt should include summary keywords")
	}

	// Prompt should specify professional/LinkedIn style
	if !strings.Contains(prompt, "professional") && !strings.Contains(prompt, "LinkedIn") {
		t.Error("Image prompt should mention professional or LinkedIn context")
	}

	// Prompt should avoid text overlays
	lowerPrompt := strings.ToLower(prompt)
	if !strings.Contains(lowerPrompt, "no text") || !strings.Contains(lowerPrompt, "minimal") {
		t.Error("Image prompt should specify minimal or no text overlays")
	}
}

// TestGenerateImageHandlesAPIError tests error handling when DALL-E API fails
func TestGenerateImageHandlesAPIError(t *testing.T) {
	mockClient := &MockDALLEClient{
		Error: errors.New("DALL-E API rate limit exceeded"),
	}

	generator := NewImageGenerator(mockClient)
	summary := "Bug fix for authentication"

	_, err := generator.Generate(summary)

	if err == nil {
		t.Error("Expected error when API fails, got nil")
	}

	if !strings.Contains(err.Error(), "API") && !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("Expected API error message, got: %v", err)
	}
}

// TestImageDownloadFromURL tests downloading image from URL
func TestImageDownloadFromURL(t *testing.T) {
	// This test will verify the download mechanism
	// For now, we'll use a fake URL and mock the download
	mockClient := &MockDALLEClient{
		ImageURL: "https://example.com/test.png",
	}

	generator := NewImageGenerator(mockClient)
	summary := "Infrastructure update"

	// Generate should download the image from the URL
	imagePath, err := generator.Generate(summary)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if imagePath == "" {
		t.Error("Expected valid file path after download")
	}

	// Clean up
	os.Remove(imagePath)
}

// TestImageFormatValidation tests that images are in correct format
func TestImageFormatValidation(t *testing.T) {
	mockClient := &MockDALLEClient{
		ImageURL: "https://example.com/image.png",
	}

	generator := NewImageGenerator(mockClient)
	summary := "Feature addition"

	imagePath, err := generator.Generate(summary)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check file extension
	if !strings.HasSuffix(imagePath, ".png") && !strings.HasSuffix(imagePath, ".jpg") {
		t.Errorf("Expected .png or .jpg extension, got: %s", imagePath)
	}

	// Clean up
	os.Remove(imagePath)
}

// TestGenerateImageHandlesEmptySummary tests handling of empty input
func TestGenerateImageHandlesEmptySummary(t *testing.T) {
	mockClient := &MockDALLEClient{
		ImageURL: "https://example.com/default.png",
	}

	generator := NewImageGenerator(mockClient)
	summary := ""

	_, err := generator.Generate(summary)

	// Should either return error or handle gracefully
	if err == nil {
		t.Log("Generator handles empty summary gracefully")
	} else {
		if !strings.Contains(err.Error(), "empty") && !strings.Contains(err.Error(), "invalid") {
			t.Errorf("Expected empty/invalid error, got: %v", err)
		}
	}
}

// TestImagePromptOptimizedForLinkedIn tests LinkedIn-specific styling
func TestImagePromptOptimizedForLinkedIn(t *testing.T) {
	summary := "Cloud cost optimization reducing infrastructure spend by 40%"

	prompt := buildImagePrompt(summary)

	lowerPrompt := strings.ToLower(prompt)

	// Should mention professional business context
	hasBusinessContext := strings.Contains(lowerPrompt, "professional") ||
		strings.Contains(lowerPrompt, "business") ||
		strings.Contains(lowerPrompt, "corporate") ||
		strings.Contains(lowerPrompt, "linkedin")

	if !hasBusinessContext {
		t.Error("Image prompt should include business/professional context for LinkedIn")
	}

	// Should specify visual style appropriate for executives
	hasStyleGuidance := strings.Contains(lowerPrompt, "modern") ||
		strings.Contains(lowerPrompt, "clean") ||
		strings.Contains(lowerPrompt, "tech")

	if !hasStyleGuidance {
		t.Error("Image prompt should include visual style guidance")
	}
}
