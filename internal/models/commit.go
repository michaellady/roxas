package models

// Commit represents a git commit from a GitHub webhook
type Commit struct {
	Message string
	Diff    string
	Author  string
	RepoURL string
}
