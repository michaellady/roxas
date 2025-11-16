package models

import "testing"

// TestCommitStructure verifies the Commit model is properly defined
func TestCommitStructure(t *testing.T) {
	commit := Commit{
		Message: "test commit",
		Diff:    "sample diff",
		Author:  "test-author",
		RepoURL: "https://github.com/test/repo",
	}

	if commit.Message != "test commit" {
		t.Errorf("Expected message 'test commit', got '%s'", commit.Message)
	}

	if commit.Author != "test-author" {
		t.Errorf("Expected author 'test-author', got '%s'", commit.Author)
	}
}
