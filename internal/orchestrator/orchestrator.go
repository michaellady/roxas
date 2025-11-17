// Package orchestrator coordinates the end-to-end workflow from GitHub commit to LinkedIn post.
// It chains together summarization, image generation, and social media posting services.
package orchestrator

import (
	"fmt"
	"log"

	"github.com/mikelady/roxas/internal/models"
	"github.com/mikelady/roxas/internal/services"
)

// Orchestrator coordinates the full pipeline from commit to LinkedIn post
type Orchestrator struct {
	summarizer     *services.Summarizer
	imageGenerator *services.ImageGenerator
	linkedInPoster *services.LinkedInPoster
}

// NewOrchestrator creates a new orchestrator with all required services
func NewOrchestrator(
	summarizer *services.Summarizer,
	imageGenerator *services.ImageGenerator,
	linkedInPoster *services.LinkedInPoster,
) *Orchestrator {
	return &Orchestrator{
		summarizer:     summarizer,
		imageGenerator: imageGenerator,
		linkedInPoster: linkedInPoster,
	}
}

// ProcessCommit orchestrates the full pipeline: summarize → generate image → post to LinkedIn
func (o *Orchestrator) ProcessCommit(commit models.Commit) (string, error) {
	log.Printf("Processing commit: %s by %s", commit.Message, commit.Author)

	// Step 1: Summarize commit into LinkedIn post text
	log.Println("Step 1: Generating LinkedIn summary...")
	summary, err := o.summarizer.Summarize(commit)
	if err != nil {
		return "", fmt.Errorf("failed to summarize commit: %w", err)
	}
	log.Printf("Summary generated: %s", summary)

	// Step 2: Generate professional image for the post
	log.Println("Step 2: Generating image...")
	imagePath, err := o.imageGenerator.Generate(summary)
	if err != nil {
		return "", fmt.Errorf("failed to generate image: %w", err)
	}
	log.Printf("Image generated: %s", imagePath)

	// Step 3: Post to LinkedIn with text and image
	log.Println("Step 3: Posting to LinkedIn...")
	postURL, err := o.linkedInPoster.Post(summary, imagePath)
	if err != nil {
		return "", fmt.Errorf("failed to post to LinkedIn: %w", err)
	}
	log.Printf("Posted to LinkedIn: %s", postURL)

	return postURL, nil
}
