package clients

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGitHubClient_ListUserRepos tests basic repo listing
func TestGitHubClient_ListUserRepos(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user/repos" {
			t.Errorf("Expected path /user/repos, got %s", r.URL.Path)
		}

		// Verify authorization header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("Expected Authorization 'Bearer test-token', got %q", auth)
		}

		// Return mock repos
		repos := []map[string]interface{}{
			{
				"id":        123,
				"name":      "my-repo",
				"full_name": "user/my-repo",
				"html_url":  "https://github.com/user/my-repo",
				"private":   false,
				"permissions": map[string]bool{
					"admin": true,
					"push":  true,
					"pull":  true,
				},
			},
			{
				"id":        456,
				"name":      "another-repo",
				"full_name": "user/another-repo",
				"html_url":  "https://github.com/user/another-repo",
				"private":   true,
				"permissions": map[string]bool{
					"admin": true,
					"push":  true,
					"pull":  true,
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(repos)
	}))
	defer server.Close()

	client := NewGitHubClient("test-token", server.URL)
	repos, err := client.ListUserRepos(context.Background())

	if err != nil {
		t.Fatalf("ListUserRepos() error = %v", err)
	}

	if len(repos) != 2 {
		t.Errorf("ListUserRepos() returned %d repos, want 2", len(repos))
	}

	// Verify first repo
	if repos[0].ID != 123 {
		t.Errorf("repos[0].ID = %d, want 123", repos[0].ID)
	}
	if repos[0].Name != "my-repo" {
		t.Errorf("repos[0].Name = %q, want %q", repos[0].Name, "my-repo")
	}
	if repos[0].FullName != "user/my-repo" {
		t.Errorf("repos[0].FullName = %q, want %q", repos[0].FullName, "user/my-repo")
	}
	if repos[0].Private {
		t.Error("repos[0].Private = true, want false")
	}
}

// TestGitHubClient_ListUserRepos_FilterAdminOnly tests that only repos with admin access are returned
func TestGitHubClient_ListUserRepos_FilterAdminOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		repos := []map[string]interface{}{
			{
				"id":        1,
				"name":      "admin-repo",
				"full_name": "user/admin-repo",
				"html_url":  "https://github.com/user/admin-repo",
				"private":   false,
				"permissions": map[string]bool{
					"admin": true,
					"push":  true,
					"pull":  true,
				},
			},
			{
				"id":        2,
				"name":      "contributor-repo",
				"full_name": "org/contributor-repo",
				"html_url":  "https://github.com/org/contributor-repo",
				"private":   false,
				"permissions": map[string]bool{
					"admin": false, // No admin access
					"push":  true,
					"pull":  true,
				},
			},
			{
				"id":        3,
				"name":      "readonly-repo",
				"full_name": "org/readonly-repo",
				"html_url":  "https://github.com/org/readonly-repo",
				"private":   true,
				"permissions": map[string]bool{
					"admin": false,
					"push":  false,
					"pull":  true,
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(repos)
	}))
	defer server.Close()

	client := NewGitHubClient("test-token", server.URL)
	repos, err := client.ListUserRepos(context.Background(), WithAdminOnly(true))

	if err != nil {
		t.Fatalf("ListUserRepos() error = %v", err)
	}

	// Should only return repos where user has admin permission
	if len(repos) != 1 {
		t.Errorf("ListUserRepos(WithAdminOnly) returned %d repos, want 1", len(repos))
	}

	if repos[0].Name != "admin-repo" {
		t.Errorf("repos[0].Name = %q, want %q", repos[0].Name, "admin-repo")
	}
}

// TestGitHubClient_ListUserRepos_Pagination tests paginated API responses
func TestGitHubClient_ListUserRepos_Pagination(t *testing.T) {
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++

		// Check pagination params
		perPage := r.URL.Query().Get("per_page")
		if perPage != "100" {
			t.Errorf("Expected per_page=100, got %s", perPage)
		}

		var repos []map[string]interface{}
		if page == 1 {
			// First page - add Link header for next page
			w.Header().Set("Link", `<`+r.URL.Scheme+`://`+r.Host+`/user/repos?page=2>; rel="next"`)
			for i := 1; i <= 100; i++ {
				repos = append(repos, map[string]interface{}{
					"id":        i,
					"name":      "repo-" + string(rune('0'+i%10)),
					"full_name": "user/repo",
					"html_url":  "https://github.com/user/repo",
					"private":   false,
					"permissions": map[string]bool{
						"admin": true,
						"push":  true,
						"pull":  true,
					},
				})
			}
		} else if page == 2 {
			// Second page - no Link header (last page)
			for i := 101; i <= 150; i++ {
				repos = append(repos, map[string]interface{}{
					"id":        i,
					"name":      "repo-" + string(rune('0'+i%10)),
					"full_name": "user/repo",
					"html_url":  "https://github.com/user/repo",
					"private":   false,
					"permissions": map[string]bool{
						"admin": true,
						"push":  true,
						"pull":  true,
					},
				})
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(repos)
	}))
	defer server.Close()

	client := NewGitHubClient("test-token", server.URL)
	repos, err := client.ListUserRepos(context.Background())

	if err != nil {
		t.Fatalf("ListUserRepos() error = %v", err)
	}

	// Should have fetched both pages
	if len(repos) != 150 {
		t.Errorf("ListUserRepos() returned %d repos, want 150", len(repos))
	}

	if page != 2 {
		t.Errorf("Expected 2 API calls for pagination, got %d", page)
	}
}

// TestGitHubClient_ListUserRepos_RateLimited tests rate limit handling
func TestGitHubClient_ListUserRepos_RateLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", "1234567890")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "API rate limit exceeded",
		})
	}))
	defer server.Close()

	client := NewGitHubClient("test-token", server.URL)
	_, err := client.ListUserRepos(context.Background())

	if err == nil {
		t.Fatal("ListUserRepos() should return error on rate limit")
	}

	if !errors.Is(err, ErrGitHubRateLimited) {
		t.Errorf("ListUserRepos() error = %v, want ErrGitHubRateLimited", err)
	}
}

// TestGitHubClient_ListUserRepos_Unauthorized tests auth failure handling
func TestGitHubClient_ListUserRepos_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Bad credentials",
		})
	}))
	defer server.Close()

	client := NewGitHubClient("bad-token", server.URL)
	_, err := client.ListUserRepos(context.Background())

	if err == nil {
		t.Fatal("ListUserRepos() should return error on unauthorized")
	}

	if !errors.Is(err, ErrGitHubAuthentication) {
		t.Errorf("ListUserRepos() error = %v, want ErrGitHubAuthentication", err)
	}
}

// TestGitHubClient_ListUserRepos_ServerError tests server error handling
func TestGitHubClient_ListUserRepos_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Internal server error",
		})
	}))
	defer server.Close()

	client := NewGitHubClient("test-token", server.URL)
	_, err := client.ListUserRepos(context.Background())

	if err == nil {
		t.Fatal("ListUserRepos() should return error on server error")
	}

	if !errors.Is(err, ErrGitHubAPIError) {
		t.Errorf("ListUserRepos() error = %v, want ErrGitHubAPIError", err)
	}
}

// TestGitHubClient_ListUserRepos_EmptyResponse tests empty repo list
func TestGitHubClient_ListUserRepos_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer server.Close()

	client := NewGitHubClient("test-token", server.URL)
	repos, err := client.ListUserRepos(context.Background())

	if err != nil {
		t.Fatalf("ListUserRepos() error = %v", err)
	}

	if len(repos) != 0 {
		t.Errorf("ListUserRepos() returned %d repos, want 0", len(repos))
	}
}

// TestGitHubClient_ListUserRepos_RepoFields tests that all repo fields are populated
func TestGitHubClient_ListUserRepos_RepoFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		repos := []map[string]interface{}{
			{
				"id":          12345,
				"name":        "test-repo",
				"full_name":   "testuser/test-repo",
				"html_url":    "https://github.com/testuser/test-repo",
				"description": "A test repository",
				"private":     true,
				"fork":        false,
				"updated_at":  "2026-01-20T10:30:00Z",
				"pushed_at":   "2026-01-19T15:45:00Z",
				"permissions": map[string]bool{
					"admin": true,
					"push":  true,
					"pull":  true,
				},
				"owner": map[string]interface{}{
					"login": "testuser",
					"id":    999,
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(repos)
	}))
	defer server.Close()

	client := NewGitHubClient("test-token", server.URL)
	repos, err := client.ListUserRepos(context.Background())

	if err != nil {
		t.Fatalf("ListUserRepos() error = %v", err)
	}

	if len(repos) != 1 {
		t.Fatalf("ListUserRepos() returned %d repos, want 1", len(repos))
	}

	repo := repos[0]
	if repo.ID != 12345 {
		t.Errorf("repo.ID = %d, want 12345", repo.ID)
	}
	if repo.Name != "test-repo" {
		t.Errorf("repo.Name = %q, want %q", repo.Name, "test-repo")
	}
	if repo.FullName != "testuser/test-repo" {
		t.Errorf("repo.FullName = %q, want %q", repo.FullName, "testuser/test-repo")
	}
	if repo.HTMLURL != "https://github.com/testuser/test-repo" {
		t.Errorf("repo.HTMLURL = %q, want %q", repo.HTMLURL, "https://github.com/testuser/test-repo")
	}
	if repo.Description != "A test repository" {
		t.Errorf("repo.Description = %q, want %q", repo.Description, "A test repository")
	}
	if !repo.Private {
		t.Error("repo.Private = false, want true")
	}
	if !repo.Permissions.Admin {
		t.Error("repo.Permissions.Admin = false, want true")
	}
}

// TestGitHubClient_ListUserRepos_NetworkError tests network failure handling
func TestGitHubClient_ListUserRepos_NetworkError(t *testing.T) {
	// Use an invalid URL to trigger a network error
	client := NewGitHubClient("test-token", "http://localhost:99999")
	_, err := client.ListUserRepos(context.Background())

	if err == nil {
		t.Fatal("ListUserRepos() should return error on network failure")
	}
}

// TestGitHubClient_ListUserRepos_InvalidJSON tests malformed response handling
func TestGitHubClient_ListUserRepos_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client := NewGitHubClient("test-token", server.URL)
	_, err := client.ListUserRepos(context.Background())

	if err == nil {
		t.Fatal("ListUserRepos() should return error on invalid JSON")
	}
}

// TestGitHubClient_ListUserRepos_ContextCancellation tests context cancellation
func TestGitHubClient_ListUserRepos_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		select {
		case <-r.Context().Done():
			return
		}
	}))
	defer server.Close()

	client := NewGitHubClient("test-token", server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := client.ListUserRepos(ctx)

	if err == nil {
		t.Fatal("ListUserRepos() should return error on context cancellation")
	}
}
