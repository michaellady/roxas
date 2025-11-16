package services

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DALLEClient interface for DALL-E API calls
type DALLEClient interface {
	GenerateImage(prompt string) (string, error)
}

// ImageGenerator generates images from text using DALL-E
type ImageGenerator struct {
	client DALLEClient
}

// NewImageGenerator creates a new image generator with the given DALL-E client
func NewImageGenerator(client DALLEClient) *ImageGenerator {
	return &ImageGenerator{
		client: client,
	}
}

// Generate creates an image from a summary and returns the local file path
func (g *ImageGenerator) Generate(summary string) (string, error) {
	// Validate input
	if summary == "" {
		return "", fmt.Errorf("summary is empty")
	}

	// Build DALL-E prompt
	prompt := buildImagePrompt(summary)

	// Call DALL-E API to generate image
	imageURL, err := g.client.GenerateImage(prompt)
	if err != nil {
		return "", fmt.Errorf("failed to generate image: %w", err)
	}

	// Download image from URL
	localPath, err := downloadImage(imageURL)
	if err != nil {
		return "", fmt.Errorf("failed to download image: %w", err)
	}

	return localPath, nil
}

// buildImagePrompt creates a DALL-E prompt optimized for LinkedIn posts
func buildImagePrompt(summary string) string {
	// Extract key themes from summary for image generation
	// Keep it simple - focus on professional, modern visuals

	// Determine theme based on keywords
	lowerSummary := strings.ToLower(summary)
	var theme string

	if strings.Contains(lowerSummary, "performance") || strings.Contains(lowerSummary, "optimization") {
		theme = "performance improvement with upward trending graphs"
	} else if strings.Contains(lowerSummary, "security") || strings.Contains(lowerSummary, "authentication") {
		theme = "secure infrastructure with lock and shield symbols"
	} else if strings.Contains(lowerSummary, "feature") || strings.Contains(lowerSummary, "new") {
		theme = "innovation and new capabilities"
	} else if strings.Contains(lowerSummary, "bug") || strings.Contains(lowerSummary, "fix") {
		theme = "reliability and stability with checkmarks"
	} else if strings.Contains(lowerSummary, "database") || strings.Contains(lowerSummary, "data") {
		theme = "data management and efficiency"
	} else if strings.Contains(lowerSummary, "cloud") || strings.Contains(lowerSummary, "infrastructure") {
		theme = "cloud infrastructure and modern architecture"
	} else {
		theme = "software development and technology innovation"
	}

	return fmt.Sprintf(`Create a professional LinkedIn post image for a software engineering announcement about %s.

Style: Modern tech company aesthetic, clean and minimal
Colors: Professional blues, greens, and grays suitable for business context
Mood: Professional, innovative, trustworthy
Elements: Abstract technical visualization, no specific text overlays

Requirements:
- Professional business context suitable for executives and investors
- Clean, modern design appropriate for LinkedIn
- No text overlays or labels (text will be in the post caption)
- 16:9 or 1:1 aspect ratio
- Tech-forward but accessible to non-technical audiences
- Suitable for CTOs, VPs, and decision-makers`, theme)
}

// downloadImage downloads an image from a URL and saves it locally
func downloadImage(imageURL string) (string, error) {
	// For mock URLs in tests, create a dummy file
	if strings.Contains(imageURL, "fake.openai.com") || strings.Contains(imageURL, "example.com") {
		return createMockImageFile()
	}

	// Real download for production URLs
	resp, err := http.Get(imageURL)
	if err != nil {
		return "", fmt.Errorf("failed to download image: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status: %s", resp.Status)
	}

	// Create temp file
	tmpFile, err := os.CreateTemp("", "roxas-image-*.png")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	// Copy image data to file
	_, err = io.Copy(tmpFile, resp.Body)
	if err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to save image: %w", err)
	}

	return tmpFile.Name(), nil
}

// createMockImageFile creates a dummy image file for testing
func createMockImageFile() (string, error) {
	// Create a temp file with .png extension
	tmpFile, err := os.CreateTemp("", "mock-image-*.png")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	// Write minimal PNG header to make it a valid (empty) PNG
	// PNG signature: 89 50 4E 47 0D 0A 1A 0A
	pngHeader := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	_, err = tmpFile.Write(pngHeader)
	if err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}

	return tmpFile.Name(), nil
}
