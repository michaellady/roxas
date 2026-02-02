package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// =============================================================================
// Property Test: Commit Diff Fetching (Property 18)
// Push with M commits fetches M diffs via GitHub API.
// Validates Requirements 5.10
// =============================================================================

// CommitDiffFetcher defines the interface for fetching commit diffs from GitHub.
// This interface abstracts the GitHub API call for getting commit diffs,
// allowing for easy testing and mocking.
type CommitDiffFetcher interface {
	// FetchCommitDiff retrieves the diff for a specific commit in a repository.
	// Returns the diff as a string or an error if the fetch fails.
	FetchCommitDiff(ctx context.Context, owner, repo, commitSHA string) (string, error)
}

// PushEvent represents a GitHub push webhook event with multiple commits.
type PushEvent struct {
	Ref        string       `json:"ref"`
	Before     string       `json:"before"`
	After      string       `json:"after"`
	Repository PushEventRepo `json:"repository"`
	Commits    []PushCommit `json:"commits"`
}

// PushEventRepo represents repository information in a push event.
type PushEventRepo struct {
	Owner    PushRepoOwner `json:"owner"`
	Name     string        `json:"name"`
	FullName string        `json:"full_name"`
}

// PushRepoOwner represents the repository owner in a push event.
type PushRepoOwner struct {
	Login string `json:"login"`
}

// PushCommit represents a single commit in a push event.
type PushCommit struct {
	ID        string           `json:"id"`
	Message   string           `json:"message"`
	Timestamp string           `json:"timestamp"`
	Author    PushCommitAuthor `json:"author"`
	Added     []string         `json:"added"`
	Removed   []string         `json:"removed"`
	Modified  []string         `json:"modified"`
}

// PushCommitAuthor represents the author of a commit.
type PushCommitAuthor struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// PushEventProcessor processes push events and fetches diffs for all commits.
// This demonstrates the behavior required by the spec: for each commit in a push,
// the system must fetch its diff via the GitHub API.
type PushEventProcessor struct {
	diffFetcher CommitDiffFetcher
}

// NewPushEventProcessor creates a new push event processor.
func NewPushEventProcessor(fetcher CommitDiffFetcher) *PushEventProcessor {
	return &PushEventProcessor{diffFetcher: fetcher}
}

// ProcessPushEvent processes a push event and fetches diffs for all commits.
// Returns a slice of diffs (one per commit) and any error encountered.
func (p *PushEventProcessor) ProcessPushEvent(ctx context.Context, event *PushEvent) ([]string, error) {
	if len(event.Commits) == 0 {
		return nil, nil
	}

	owner := event.Repository.Owner.Login
	repo := event.Repository.Name

	diffs := make([]string, 0, len(event.Commits))
	for _, commit := range event.Commits {
		diff, err := p.diffFetcher.FetchCommitDiff(ctx, owner, repo, commit.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch diff for commit %s: %w", commit.ID, err)
		}
		diffs = append(diffs, diff)
	}

	return diffs, nil
}

// MockDiffFetcher is a mock implementation of CommitDiffFetcher that tracks API calls.
type MockDiffFetcher struct {
	mu         sync.Mutex
	fetchCalls []DiffFetchCall
	diffs      map[string]string // commitSHA -> diff
}

// DiffFetchCall records details of a diff fetch API call.
type DiffFetchCall struct {
	Owner     string
	Repo      string
	CommitSHA string
}

// NewMockDiffFetcher creates a new mock diff fetcher.
func NewMockDiffFetcher() *MockDiffFetcher {
	return &MockDiffFetcher{
		fetchCalls: make([]DiffFetchCall, 0),
		diffs:      make(map[string]string),
	}
}

// SetDiff sets the diff response for a specific commit SHA.
func (m *MockDiffFetcher) SetDiff(commitSHA, diff string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.diffs[commitSHA] = diff
}

// FetchCommitDiff implements CommitDiffFetcher.
func (m *MockDiffFetcher) FetchCommitDiff(ctx context.Context, owner, repo, commitSHA string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.fetchCalls = append(m.fetchCalls, DiffFetchCall{
		Owner:     owner,
		Repo:      repo,
		CommitSHA: commitSHA,
	})

	if diff, ok := m.diffs[commitSHA]; ok {
		return diff, nil
	}
	return fmt.Sprintf("diff for %s", commitSHA), nil
}

// GetFetchCalls returns all recorded fetch calls.
func (m *MockDiffFetcher) GetFetchCalls() []DiffFetchCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]DiffFetchCall, len(m.fetchCalls))
	copy(result, m.fetchCalls)
	return result
}

// Reset clears all recorded calls.
func (m *MockDiffFetcher) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fetchCalls = make([]DiffFetchCall, 0)
}

// =============================================================================
// Generators for Property Testing
// =============================================================================

// genCommitSHA generates a random commit SHA (40 hex characters).
func genCommitSHA() gopter.Gen {
	return gen.RegexMatch(`[0-9a-f]{40}`)
}

// genCommitMessage generates a random commit message.
func genCommitMessage() gopter.Gen {
	prefixes := []string{"feat:", "fix:", "docs:", "refactor:", "test:", "chore:"}
	return gopter.CombineGens(
		gen.OneConstOf(prefixes[0], prefixes[1], prefixes[2], prefixes[3], prefixes[4], prefixes[5]),
		gen.AlphaString(),
	).Map(func(vals []interface{}) string {
		prefix := vals[0].(string)
		msg := vals[1].(string)
		if msg == "" {
			msg = "update"
		}
		return prefix + " " + msg
	})
}

// genPushCommit generates a random push commit.
func genPushCommit() gopter.Gen {
	return gopter.CombineGens(
		genCommitSHA(),
		genCommitMessage(),
		gen.AlphaString(), // author name
	).Map(func(vals []interface{}) PushCommit {
		sha := vals[0].(string)
		msg := vals[1].(string)
		author := vals[2].(string)
		if author == "" {
			author = "developer"
		}
		return PushCommit{
			ID:        sha,
			Message:   msg,
			Timestamp: "2024-01-15T10:30:00Z",
			Author: PushCommitAuthor{
				Name:  author,
				Email: author + "@example.com",
			},
			Added:    []string{},
			Removed:  []string{},
			Modified: []string{"file.go"},
		}
	})
}

// genPushEvent generates a push event with M commits (M between min and max).
func genPushEvent(minCommits, maxCommits int) gopter.Gen {
	return gen.IntRange(minCommits, maxCommits).FlatMap(func(v interface{}) gopter.Gen {
		numCommits := v.(int)
		commitGens := make([]gopter.Gen, numCommits)
		for i := 0; i < numCommits; i++ {
			commitGens[i] = genPushCommit()
		}

		if len(commitGens) == 0 {
			return gen.Const(PushEvent{
				Ref:    "refs/heads/main",
				Before: "0000000000000000000000000000000000000000",
				After:  "1111111111111111111111111111111111111111",
				Repository: PushEventRepo{
					Owner:    PushRepoOwner{Login: "testowner"},
					Name:     "testrepo",
					FullName: "testowner/testrepo",
				},
				Commits: []PushCommit{},
			})
		}

		return gopter.CombineGens(commitGens...).Map(func(vals []interface{}) PushEvent {
			commits := make([]PushCommit, len(vals))
			for i, v := range vals {
				commits[i] = v.(PushCommit)
			}
			return PushEvent{
				Ref:    "refs/heads/main",
				Before: "0000000000000000000000000000000000000000",
				After:  commits[len(commits)-1].ID,
				Repository: PushEventRepo{
					Owner:    PushRepoOwner{Login: "testowner"},
					Name:     "testrepo",
					FullName: "testowner/testrepo",
				},
				Commits: commits,
			}
		})
	}, nil)
}

// =============================================================================
// Property Tests
// =============================================================================

// TestProperty18_PushWithMCommitsFetchesMDiffs verifies Property 18:
// Push with M commits fetches M diffs via GitHub API.
func TestProperty18_PushWithMCommitsFetchesMDiffs(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 50

	properties := gopter.NewProperties(parameters)

	// Property 18a: M commits in push event results in exactly M diff fetches
	properties.Property("push with M commits fetches exactly M diffs", prop.ForAll(
		func(event PushEvent) bool {
			mockFetcher := NewMockDiffFetcher()
			processor := NewPushEventProcessor(mockFetcher)

			ctx := context.Background()
			_, err := processor.ProcessPushEvent(ctx, &event)
			if err != nil {
				t.Logf("Unexpected error processing push event: %v", err)
				return false
			}

			fetchCalls := mockFetcher.GetFetchCalls()
			numCommits := len(event.Commits)
			numFetches := len(fetchCalls)

			if numFetches != numCommits {
				t.Logf("Expected %d diff fetches for %d commits, got %d",
					numCommits, numCommits, numFetches)
				return false
			}

			return true
		},
		genPushEvent(1, 50), // 1 to 50 commits per push
	))

	properties.TestingRun(t)
}

// TestProperty18_DiffFetchesMatchCommitSHAs verifies that diff fetches
// are made for the correct commit SHAs.
func TestProperty18_DiffFetchesMatchCommitSHAs(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 30

	properties := gopter.NewProperties(parameters)

	// Property 18b: Each diff fetch is for a commit SHA from the push event
	properties.Property("diff fetches are for correct commit SHAs", prop.ForAll(
		func(event PushEvent) bool {
			if len(event.Commits) == 0 {
				return true // Skip empty push events
			}

			mockFetcher := NewMockDiffFetcher()
			processor := NewPushEventProcessor(mockFetcher)

			ctx := context.Background()
			_, err := processor.ProcessPushEvent(ctx, &event)
			if err != nil {
				t.Logf("Unexpected error: %v", err)
				return false
			}

			fetchCalls := mockFetcher.GetFetchCalls()

			// Build set of commit SHAs from push event
			commitSHAs := make(map[string]bool)
			for _, commit := range event.Commits {
				commitSHAs[commit.ID] = true
			}

			// Verify each fetch call is for a valid commit SHA
			for _, call := range fetchCalls {
				if !commitSHAs[call.CommitSHA] {
					t.Logf("Diff fetched for unknown commit SHA: %s", call.CommitSHA)
					return false
				}
			}

			// Verify all commit SHAs were fetched
			fetchedSHAs := make(map[string]bool)
			for _, call := range fetchCalls {
				fetchedSHAs[call.CommitSHA] = true
			}

			for sha := range commitSHAs {
				if !fetchedSHAs[sha] {
					t.Logf("Missing diff fetch for commit SHA: %s", sha)
					return false
				}
			}

			return true
		},
		genPushEvent(1, 30),
	))

	properties.TestingRun(t)
}

// TestProperty18_DiffFetchesUseCorrectRepository verifies that diff fetches
// are made for the correct repository.
func TestProperty18_DiffFetchesUseCorrectRepository(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 30

	properties := gopter.NewProperties(parameters)

	// Property 18c: All diff fetches use the correct owner and repo from push event
	properties.Property("diff fetches use correct repository info", prop.ForAll(
		func(event PushEvent) bool {
			if len(event.Commits) == 0 {
				return true
			}

			mockFetcher := NewMockDiffFetcher()
			processor := NewPushEventProcessor(mockFetcher)

			ctx := context.Background()
			_, err := processor.ProcessPushEvent(ctx, &event)
			if err != nil {
				return false
			}

			fetchCalls := mockFetcher.GetFetchCalls()
			expectedOwner := event.Repository.Owner.Login
			expectedRepo := event.Repository.Name

			for _, call := range fetchCalls {
				if call.Owner != expectedOwner {
					t.Logf("Expected owner %s, got %s", expectedOwner, call.Owner)
					return false
				}
				if call.Repo != expectedRepo {
					t.Logf("Expected repo %s, got %s", expectedRepo, call.Repo)
					return false
				}
			}

			return true
		},
		genPushEvent(1, 30),
	))

	properties.TestingRun(t)
}

// TestProperty18_ZeroCommitsMeansZeroFetches verifies edge case: empty push.
func TestProperty18_ZeroCommitsMeansZeroFetches(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50

	properties := gopter.NewProperties(parameters)

	// Property 18d: Push with 0 commits makes 0 diff fetches
	properties.Property("push with 0 commits makes 0 diff fetches", prop.ForAll(
		func(_ int) bool {
			mockFetcher := NewMockDiffFetcher()
			processor := NewPushEventProcessor(mockFetcher)

			event := &PushEvent{
				Ref:    "refs/heads/main",
				Before: "0000000000000000000000000000000000000000",
				After:  "1111111111111111111111111111111111111111",
				Repository: PushEventRepo{
					Owner:    PushRepoOwner{Login: "testowner"},
					Name:     "testrepo",
					FullName: "testowner/testrepo",
				},
				Commits: []PushCommit{}, // Empty commits
			}

			ctx := context.Background()
			diffs, err := processor.ProcessPushEvent(ctx, event)
			if err != nil {
				t.Logf("Unexpected error: %v", err)
				return false
			}

			fetchCalls := mockFetcher.GetFetchCalls()

			// Property: 0 commits = 0 fetches and 0 diffs returned
			return len(fetchCalls) == 0 && len(diffs) == 0
		},
		gen.IntRange(0, 10), // Dummy generator to run multiple times
	))

	properties.TestingRun(t)
}

// TestProperty18_DiffsReturnedMatchCommitOrder verifies that diffs are
// returned in the same order as commits in the push event.
func TestProperty18_DiffsReturnedMatchCommitOrder(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 30

	properties := gopter.NewProperties(parameters)

	// Property 18e: Diffs are returned in the same order as commits
	properties.Property("diffs returned in commit order", prop.ForAll(
		func(event PushEvent) bool {
			if len(event.Commits) == 0 {
				return true
			}

			mockFetcher := NewMockDiffFetcher()
			// Set up unique diffs for each commit to verify ordering
			for i, commit := range event.Commits {
				mockFetcher.SetDiff(commit.ID, fmt.Sprintf("diff-%d-%s", i, commit.ID[:8]))
			}

			processor := NewPushEventProcessor(mockFetcher)

			ctx := context.Background()
			diffs, err := processor.ProcessPushEvent(ctx, &event)
			if err != nil {
				return false
			}

			// Verify diffs are in the same order as commits
			for i, commit := range event.Commits {
				expectedDiff := fmt.Sprintf("diff-%d-%s", i, commit.ID[:8])
				if diffs[i] != expectedDiff {
					t.Logf("Diff at index %d: expected %s, got %s",
						i, expectedDiff, diffs[i])
					return false
				}
			}

			return true
		},
		genPushEvent(1, 30),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Integration Test with Mock HTTP Server
// =============================================================================

// GitHubDiffFetcher implements CommitDiffFetcher using the GitHub API.
type GitHubDiffFetcher struct {
	client  *GitHubClient
	baseURL string
}

// NewGitHubDiffFetcher creates a new GitHub diff fetcher.
func NewGitHubDiffFetcher(client *GitHubClient) *GitHubDiffFetcher {
	return &GitHubDiffFetcher{
		client:  client,
		baseURL: client.baseURL,
	}
}

// FetchCommitDiff implements CommitDiffFetcher using GitHub API.
func (f *GitHubDiffFetcher) FetchCommitDiff(ctx context.Context, owner, repo, commitSHA string) (string, error) {
	reqURL := fmt.Sprintf("%s/repos/%s/%s/commits/%s", f.baseURL, owner, repo, commitSHA)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+f.client.accessToken)
	req.Header.Set("Accept", "application/vnd.github.diff")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := f.client.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call GitHub API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return "", ErrGitHubRateLimited
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return "", ErrGitHubAuthentication
	}

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("commit not found: %s/%s@%s", owner, repo, commitSHA)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: %d", ErrGitHubAPIError, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return string(body), nil
}

// TestProperty18_HTTPIntegration tests the property with a mock HTTP server.
func TestProperty18_HTTPIntegration(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	parameters.MaxSize = 20

	properties := gopter.NewProperties(parameters)

	properties.Property("M commits trigger M HTTP requests to GitHub API", prop.ForAll(
		func(event PushEvent) bool {
			if len(event.Commits) == 0 {
				return true
			}

			var mu sync.Mutex
			requestedSHAs := make([]string, 0)

			// Create mock server that tracks requests
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Extract commit SHA from URL path
				// Expected path: /repos/owner/repo/commits/SHA
				// parts[0]="" parts[1]="repos" parts[2]="owner" parts[3]="repo" parts[4]="commits" parts[5]="SHA"
				parts := strings.Split(r.URL.Path, "/")
				if len(parts) >= 6 && parts[4] == "commits" {
					sha := parts[5]
					mu.Lock()
					requestedSHAs = append(requestedSHAs, sha)
					mu.Unlock()
				}

				// Return mock diff
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("diff --git a/file.go b/file.go\n+// changes"))
			}))
			defer server.Close()

			// Create fetcher using mock server
			client := NewGitHubClient("test-token", server.URL)
			fetcher := NewGitHubDiffFetcher(client)
			processor := NewPushEventProcessor(fetcher)

			ctx := context.Background()
			_, err := processor.ProcessPushEvent(ctx, &event)
			if err != nil {
				t.Logf("Error processing push: %v", err)
				return false
			}

			mu.Lock()
			numRequests := len(requestedSHAs)
			mu.Unlock()

			// Property: M commits = M HTTP requests
			if numRequests != len(event.Commits) {
				t.Logf("Expected %d HTTP requests, got %d", len(event.Commits), numRequests)
				return false
			}

			return true
		},
		genPushEvent(1, 20),
	))

	properties.TestingRun(t)
}

// TestProperty18_HTTPRequestsContainCorrectHeaders verifies that HTTP requests
// include proper authentication and accept headers for diff format.
func TestProperty18_HTTPRequestsContainCorrectHeaders(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50

	properties := gopter.NewProperties(parameters)

	properties.Property("diff fetch requests have correct headers", prop.ForAll(
		func(event PushEvent) bool {
			if len(event.Commits) == 0 {
				return true
			}

			var mu sync.Mutex
			var headersValid = true

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()

				// Verify Authorization header
				auth := r.Header.Get("Authorization")
				if !strings.HasPrefix(auth, "Bearer ") {
					t.Logf("Missing or invalid Authorization header: %s", auth)
					headersValid = false
				}

				// Verify Accept header for diff format
				accept := r.Header.Get("Accept")
				if accept != "application/vnd.github.diff" {
					t.Logf("Expected Accept: application/vnd.github.diff, got: %s", accept)
					headersValid = false
				}

				// Verify API version header
				apiVersion := r.Header.Get("X-GitHub-Api-Version")
				if apiVersion != "2022-11-28" {
					t.Logf("Expected X-GitHub-Api-Version: 2022-11-28, got: %s", apiVersion)
					headersValid = false
				}

				w.WriteHeader(http.StatusOK)
				w.Write([]byte("mock diff"))
			}))
			defer server.Close()

			client := NewGitHubClient("test-token", server.URL)
			fetcher := NewGitHubDiffFetcher(client)
			processor := NewPushEventProcessor(fetcher)

			ctx := context.Background()
			processor.ProcessPushEvent(ctx, &event)

			mu.Lock()
			result := headersValid
			mu.Unlock()

			return result
		},
		genPushEvent(1, 10),
	))

	properties.TestingRun(t)
}

// TestPushEventJSONParsing tests that push events can be properly serialized/deserialized.
func TestPushEventJSONParsing(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50

	properties := gopter.NewProperties(parameters)

	properties.Property("push events roundtrip through JSON", prop.ForAll(
		func(event PushEvent) bool {
			// Serialize to JSON
			data, err := json.Marshal(event)
			if err != nil {
				t.Logf("Failed to marshal: %v", err)
				return false
			}

			// Deserialize back
			var parsed PushEvent
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Logf("Failed to unmarshal: %v", err)
				return false
			}

			// Verify commit count is preserved
			if len(parsed.Commits) != len(event.Commits) {
				t.Logf("Commit count mismatch: expected %d, got %d",
					len(event.Commits), len(parsed.Commits))
				return false
			}

			// Verify commit SHAs are preserved
			for i, commit := range event.Commits {
				if parsed.Commits[i].ID != commit.ID {
					t.Logf("Commit SHA mismatch at index %d", i)
					return false
				}
			}

			return true
		},
		genPushEvent(0, 30),
	))

	properties.TestingRun(t)
}
