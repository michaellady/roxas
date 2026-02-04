// Package services contains property tests for diff summarization.
// Property 19: Diffs >500 lines summarized, <500 lines sent in full to GPT.
// Validates Requirements 5.11, 5.12
package services

import (
	"fmt"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// Property 19: Diff Summarization by Size
// Property 19a: For any diff with threshold or fewer lines, the full diff is returned
// Property 19b: For any diff with more than threshold lines, a summarized version is returned
// Property 19c: Summary preserves file-level information
// Property 19d: Processing is deterministic (same input always produces same output)

// generateDiffWithExactLines creates a diff string with exactly the specified number of lines.
// This ensures predictable line counts for threshold testing.
func generateDiffWithExactLines(targetLineCount int) string {
	if targetLineCount <= 0 {
		return ""
	}

	var sb strings.Builder

	// Write header first (5 lines)
	sb.WriteString("diff --git a/file1.go b/file1.go\n")
	sb.WriteString("index abc1234..def5678 100644\n")
	sb.WriteString("--- a/file1.go\n")
	sb.WriteString("+++ b/file1.go\n")
	sb.WriteString("@@ -1,10 +1,12 @@\n")

	linesWritten := 5

	// Write content lines until we have target - 1 lines (last line has no trailing newline)
	for linesWritten < targetLineCount {
		if linesWritten%3 == 0 {
			sb.WriteString(fmt.Sprintf("+added line %d\n", linesWritten))
		} else if linesWritten%3 == 1 {
			sb.WriteString(fmt.Sprintf("-deleted line %d\n", linesWritten))
		} else {
			sb.WriteString(fmt.Sprintf(" context line %d\n", linesWritten))
		}
		linesWritten++
	}

	result := sb.String()
	// Remove trailing newline so line count is exact
	if len(result) > 0 && result[len(result)-1] == '\n' {
		result = result[:len(result)-1]
	}

	return result
}

// generateDiff creates a realistic-looking diff with multiple files.
// The actual line count may not be exact but will be close to target.
func generateDiff(targetLineCount int, fileCount int) string {
	if targetLineCount <= 0 || fileCount <= 0 {
		return ""
	}

	// For simple cases or when file count is 1, use exact line generation
	if fileCount == 1 {
		return generateDiffWithExactLines(targetLineCount)
	}

	// Each file has 5 header lines: diff --git, index, ---, +++, @@
	const headerLinesPerFile = 5

	var sb strings.Builder
	linesPerFile := (targetLineCount - (fileCount * headerLinesPerFile)) / fileCount
	if linesPerFile < 0 {
		linesPerFile = 0
	}

	for i := 0; i < fileCount; i++ {
		fileName := fmt.Sprintf("file%d.go", i+1)
		sb.WriteString(fmt.Sprintf("diff --git a/%s b/%s\n", fileName, fileName))
		sb.WriteString("index abc1234..def5678 100644\n")
		sb.WriteString(fmt.Sprintf("--- a/%s\n", fileName))
		sb.WriteString(fmt.Sprintf("+++ b/%s\n", fileName))
		sb.WriteString("@@ -1,10 +1,12 @@\n")

		// Generate diff content lines
		for j := 0; j < linesPerFile; j++ {
			if j%3 == 0 {
				sb.WriteString(fmt.Sprintf("+added line %d in %s\n", j, fileName))
			} else if j%3 == 1 {
				sb.WriteString(fmt.Sprintf("-deleted line %d in %s\n", j, fileName))
			} else {
				sb.WriteString(fmt.Sprintf(" context line %d in %s\n", j, fileName))
			}
		}
	}

	result := sb.String()
	// Remove trailing newline for exact count
	if len(result) > 0 && result[len(result)-1] == '\n' {
		result = result[:len(result)-1]
	}

	return result
}

// TestPropertySmallDiffsSentInFull verifies that diffs at or below the threshold are sent in full.
// Validates Requirement 5.12: WHEN a commit diff is under 500 lines,
// THE System SHALL send the full diff content to GPT
func TestPropertySmallDiffsSentInFull(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("diffs at or under threshold are sent in full", prop.ForAll(
		func(lineCount int) bool {
			// Skip edge cases
			if lineCount <= 0 {
				return true // vacuously true
			}

			// Ensure we're at or under threshold (lineCount is already constrained by generator)
			diff := generateDiffWithExactLines(lineCount)
			summarizer := NewDiffSummarizer()
			result := summarizer.Process(diff)

			actualLines := countLines(diff)

			// Property: Small diffs MUST NOT be summarized
			if result.IsSummarized {
				t.Logf("FAILED: diff with %d actual lines was incorrectly summarized (threshold: %d)", actualLines, DiffThreshold)
				return false
			}

			// Property: Content MUST be the original diff (unchanged)
			if result.Content != diff {
				t.Logf("FAILED: diff content was modified for %d-line diff", actualLines)
				return false
			}

			return true
		},
		gen.IntRange(1, DiffThreshold), // lineCount at or under threshold
	))

	properties.TestingRun(t)
}

// TestPropertyLargeDiffsSummarized verifies that diffs above the threshold are summarized.
// Validates Requirement 5.11: WHEN a commit diff exceeds 500 lines,
// THE System SHALL send a file-level summary instead of the full diff
func TestPropertyLargeDiffsSummarized(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("diffs above threshold are summarized", prop.ForAll(
		func(lineCount int, fileCount int) bool {
			// Skip edge cases
			if fileCount <= 0 {
				return true // vacuously true
			}

			// Ensure we're above threshold
			if lineCount <= DiffThreshold {
				return true // not testing this case here
			}

			diff := generateDiff(lineCount, fileCount)
			actualLineCount := countLines(diff)

			// generateDiff may not produce exact line counts for multi-file diffs
			// due to integer division, so check actual line count
			if actualLineCount <= DiffThreshold {
				return true // actual diff is at or under threshold, skip
			}

			summarizer := NewDiffSummarizer()
			result := summarizer.Process(diff)

			// Property: Large diffs MUST be summarized
			if !result.IsSummarized {
				t.Logf("FAILED: diff with %d actual lines was not summarized (threshold: %d)", actualLineCount, DiffThreshold)
				return false
			}

			// Property: Summary MUST be different from original (shorter)
			if result.Content == diff {
				t.Logf("FAILED: summary is identical to original diff for %d lines", actualLineCount)
				return false
			}

			// Property: Summary MUST be shorter than original
			if len(result.Content) >= len(diff) {
				t.Logf("FAILED: summary (%d chars) is not shorter than original (%d chars)",
					len(result.Content), len(diff))
				return false
			}

			return true
		},
		gen.IntRange(DiffThreshold+1, DiffThreshold+500), // lineCount above threshold
		gen.IntRange(1, 10),                               // fileCount
	))

	properties.TestingRun(t)
}

// TestPropertyThresholdBoundary verifies the exact threshold boundary behavior.
// Tests the transition point between full diff and summary modes.
// Per spec: "exceeds 500 lines" means > 500, so exactly 500 lines is NOT summarized.
func TestPropertyThresholdBoundary(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("threshold boundary is correctly respected", prop.ForAll(
		func(_ int) bool {
			summarizer := NewDiffSummarizer()

			// Test just under threshold using exact line generator
			underDiff := generateDiffWithExactLines(DiffThreshold - 1)
			underResult := summarizer.Process(underDiff)
			underActual := countLines(underDiff)
			if underResult.IsSummarized {
				t.Logf("FAILED: diff with %d lines (threshold-1) was summarized", underActual)
				return false
			}

			// Test exactly at threshold - should NOT be summarized (spec says "exceeds" = >)
			atDiff := generateDiffWithExactLines(DiffThreshold)
			atResult := summarizer.Process(atDiff)
			atActual := countLines(atDiff)
			if atResult.IsSummarized {
				t.Logf("FAILED: diff with %d lines (threshold) was incorrectly summarized", atActual)
				return false
			}

			// Test just above threshold - should be summarized
			aboveDiff := generateDiffWithExactLines(DiffThreshold + 1)
			aboveResult := summarizer.Process(aboveDiff)
			aboveActual := countLines(aboveDiff)
			if !aboveResult.IsSummarized {
				t.Logf("FAILED: diff with %d lines (threshold+1) was not summarized", aboveActual)
				return false
			}

			return true
		},
		gen.IntRange(1, 100), // dummy generator to run property multiple times
	))

	properties.TestingRun(t)
}

// TestPropertySummaryPreservesFileInfo verifies that summaries contain file-level information.
// The summary should include file names and change statistics.
func TestPropertySummaryPreservesFileInfo(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("summary contains file-level information", prop.ForAll(
		func(lineCount int, fileCount int) bool {
			// Only test large diffs that get summarized
			if fileCount <= 0 || lineCount <= DiffThreshold {
				return true
			}

			diff := generateDiff(lineCount, fileCount)
			summarizer := NewDiffSummarizer()
			result := summarizer.Process(diff)

			// Must be summarized
			if !result.IsSummarized {
				return true // not testing this case
			}

			// Property: Summary MUST contain file names
			for i := 1; i <= fileCount; i++ {
				expectedFileName := fmt.Sprintf("file%d.go", i)
				if !strings.Contains(result.Content, expectedFileName) {
					t.Logf("FAILED: summary missing file name %s", expectedFileName)
					return false
				}
			}

			// Property: Summary MUST contain statistics indicator
			if !strings.Contains(result.Content, "+") || !strings.Contains(result.Content, "-") {
				t.Logf("FAILED: summary missing insertion/deletion statistics")
				return false
			}

			return true
		},
		gen.IntRange(DiffThreshold+1, DiffThreshold+200), // lineCount (above threshold)
		gen.IntRange(1, 5),                                // fileCount (smaller range for file count check)
	))

	properties.TestingRun(t)
}

// TestPropertyDeterministicProcessing verifies that diff processing is deterministic.
// The same input must always produce the same output.
func TestPropertyDeterministicProcessing(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("processing is deterministic", prop.ForAll(
		func(lineCount int, fileCount int) bool {
			if lineCount <= 0 || fileCount <= 0 {
				return true
			}

			diff := generateDiff(lineCount, fileCount)
			summarizer := NewDiffSummarizer()

			// Process the same diff multiple times
			result1 := summarizer.Process(diff)
			result2 := summarizer.Process(diff)
			result3 := summarizer.Process(diff)

			// Property: All results MUST be identical
			if result1.Content != result2.Content || result2.Content != result3.Content {
				t.Logf("FAILED: non-deterministic processing for %d-line diff", lineCount)
				return false
			}

			if result1.IsSummarized != result2.IsSummarized || result2.IsSummarized != result3.IsSummarized {
				t.Logf("FAILED: non-deterministic summarization flag")
				return false
			}

			if result1.LineCount != result2.LineCount || result2.LineCount != result3.LineCount {
				t.Logf("FAILED: non-deterministic line count")
				return false
			}

			return true
		},
		gen.IntRange(1, DiffThreshold+200), // lineCount (covers both summarized and non-summarized)
		gen.IntRange(1, 10),                 // fileCount
	))

	properties.TestingRun(t)
}

// TestPropertyLineCountAccuracy verifies that line count tracking is accurate.
func TestPropertyLineCountAccuracy(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("line count is accurately reported", prop.ForAll(
		func(lineCount int, fileCount int) bool {
			if lineCount <= 0 || fileCount <= 0 {
				return true
			}

			diff := generateDiff(lineCount, fileCount)
			summarizer := NewDiffSummarizer()
			result := summarizer.Process(diff)

			// Property: Reported line count MUST match actual line count
			actualLineCount := countLines(diff)
			if result.LineCount != actualLineCount {
				t.Logf("FAILED: reported %d lines, actual %d lines", result.LineCount, actualLineCount)
				return false
			}

			return true
		},
		gen.IntRange(1, DiffThreshold+200),
		gen.IntRange(1, 10),
	))

	properties.TestingRun(t)
}

// TestPropertyCustomThreshold verifies that custom thresholds work correctly.
func TestPropertyCustomThreshold(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("custom threshold is respected", prop.ForAll(
		func(threshold int, lineCount int, fileCount int) bool {
			// Skip invalid inputs
			if threshold <= 0 || lineCount <= 0 || fileCount <= 0 {
				return true
			}

			diff := generateDiff(lineCount, fileCount)
			summarizer := NewDiffSummarizerWithThreshold(threshold)
			result := summarizer.Process(diff)

			actualLineCount := countLines(diff)

			// Property: Summarization decision MUST be based on custom threshold (> not >=)
			if actualLineCount > threshold && !result.IsSummarized {
				t.Logf("FAILED: %d lines should be summarized with threshold %d", actualLineCount, threshold)
				return false
			}

			if actualLineCount <= threshold && result.IsSummarized {
				t.Logf("FAILED: %d lines should not be summarized with threshold %d", actualLineCount, threshold)
				return false
			}

			return true
		},
		gen.IntRange(50, 200),  // threshold
		gen.IntRange(1, 250),   // lineCount
		gen.IntRange(1, 10),    // fileCount
	))

	properties.TestingRun(t)
}

// TestPropertyEmptyDiffHandling verifies correct handling of empty diffs.
func TestPropertyEmptyDiffHandling(t *testing.T) {
	summarizer := NewDiffSummarizer()

	// Empty string
	result := summarizer.Process("")
	if result.IsSummarized {
		t.Error("Empty diff should not be summarized")
	}
	if result.Content != "" {
		t.Error("Empty diff content should remain empty")
	}
	if result.LineCount != 0 {
		t.Errorf("Empty diff line count should be 0, got %d", result.LineCount)
	}
}
