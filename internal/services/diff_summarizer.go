// Package services implements the core business logic for roxas.
package services

import (
	"fmt"
	"regexp"
	"strings"
)

// DiffThreshold is the line count threshold for diff summarization.
// Diffs with more lines than this threshold are summarized instead of sent in full.
const DiffThreshold = 500

// DiffSummarizer handles intelligent summarization of git diffs based on size.
// Implements Requirements 5.11 and 5.12 from SPEC.md.
type DiffSummarizer struct {
	threshold int
}

// NewDiffSummarizer creates a new DiffSummarizer with the default threshold.
func NewDiffSummarizer() *DiffSummarizer {
	return &DiffSummarizer{
		threshold: DiffThreshold,
	}
}

// NewDiffSummarizerWithThreshold creates a DiffSummarizer with a custom threshold.
func NewDiffSummarizerWithThreshold(threshold int) *DiffSummarizer {
	return &DiffSummarizer{
		threshold: threshold,
	}
}

// ProcessResult contains the result of processing a diff.
type ProcessResult struct {
	Content      string
	IsSummarized bool
	LineCount    int
}

// Process determines whether to summarize or send the full diff based on line count.
// - If diff has >= threshold lines, returns a file-level summary (Requirement 5.11)
// - If diff has < threshold lines, returns the full diff content (Requirement 5.12)
func (ds *DiffSummarizer) Process(diff string) ProcessResult {
	lineCount := countLines(diff)

	if lineCount >= ds.threshold {
		summary := ds.summarize(diff)
		return ProcessResult{
			Content:      summary,
			IsSummarized: true,
			LineCount:    lineCount,
		}
	}

	return ProcessResult{
		Content:      diff,
		IsSummarized: false,
		LineCount:    lineCount,
	}
}

// summarize creates a file-level summary of the diff including:
// - List of files changed
// - Insertions/deletions count per file
// - Overall statistics
func (ds *DiffSummarizer) summarize(diff string) string {
	fileStats := parseDiffStats(diff)
	if len(fileStats) == 0 {
		return fmt.Sprintf("Large diff (%d lines). No file changes detected.", countLines(diff))
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Diff Summary (%d lines total, summarized for brevity):\n\n", countLines(diff)))

	totalInsertions := 0
	totalDeletions := 0

	for _, stat := range fileStats {
		sb.WriteString(fmt.Sprintf("- %s: +%d/-%d lines\n", stat.FileName, stat.Insertions, stat.Deletions))
		totalInsertions += stat.Insertions
		totalDeletions += stat.Deletions
	}

	sb.WriteString(fmt.Sprintf("\nTotal: %d files changed, %d insertions(+), %d deletions(-)",
		len(fileStats), totalInsertions, totalDeletions))

	return sb.String()
}

// FileStat contains statistics for a single file in the diff.
type FileStat struct {
	FileName   string
	Insertions int
	Deletions  int
}

// countLines counts the number of lines in a string.
func countLines(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

// parseDiffStats extracts file-level statistics from a unified diff.
func parseDiffStats(diff string) []FileStat {
	var stats []FileStat

	// Pattern to match diff file headers: "diff --git a/path/file b/path/file"
	diffHeaderPattern := regexp.MustCompile(`(?m)^diff --git a/(.+?) b/(.+?)$`)
	// Pattern to match file change indicators
	addPattern := regexp.MustCompile(`(?m)^\+[^+]`)
	delPattern := regexp.MustCompile(`(?m)^-[^-]`)

	matches := diffHeaderPattern.FindAllStringSubmatchIndex(diff, -1)

	for i, match := range matches {
		if len(match) < 4 {
			continue
		}

		// Extract filename from the match (use "b/" path as it's the new filename)
		fileNameStart := match[4]
		fileNameEnd := match[5]
		fileName := diff[fileNameStart:fileNameEnd]

		// Find the content of this file's diff section
		sectionStart := match[0]
		sectionEnd := len(diff)
		if i+1 < len(matches) {
			sectionEnd = matches[i+1][0]
		}

		section := diff[sectionStart:sectionEnd]

		// Count insertions and deletions in this section
		insertions := len(addPattern.FindAllString(section, -1))
		deletions := len(delPattern.FindAllString(section, -1))

		stats = append(stats, FileStat{
			FileName:   fileName,
			Insertions: insertions,
			Deletions:  deletions,
		})
	}

	return stats
}
