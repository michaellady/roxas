package clients

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mikelady/roxas/internal/services"
)

func TestGitHubClient_Platform(t *testing.T) {
	client := NewGitHubClient("test-token", "")
	if got := client.Platform(); got != services.PlatformGitHub {
		t.Errorf("Platform() = %q, want %q", got, services.PlatformGitHub)
	}
}

func TestGitHubClient_ListUserRepos(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify auth header
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization header = %q, want %q", r.Header.Get("Authorization"), "Bearer test-token")
		}

		repos := []GitHubRepo{
			{
				ID:       1,
				Name:     "repo1",
				FullName: "user/repo1",
				Private:  false,
				HTMLURL:  "https://github.com/user/repo1",
				Permissions: &GitHubRepoPermissions{
					Admin: true,
					Push:  true,
					Pull:  true,
				},
			},
			{
				ID:       2,
				Name:     "repo2",
				FullName: "user/repo2",
				Private:  true,
				HTMLURL:  "https://github.com/user/repo2",
				Permissions: &GitHubRepoPermissions{
					Admin: false,
					Push:  true,
					Pull:  true,
				},
			},
			{
				ID:       3,
				Name:     "repo3",
				FullName: "org/repo3",
				Private:  false,
				HTMLURL:  "https://github.com/org/repo3",
				Permissions: &GitHubRepoPermissions{
					Admin: true,
					Push:  true,
					Pull:  true,
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(repos)
	}))
	defer server.Close()

	client := NewGitHubClient("test-token", server.URL)

	t.Run("all repos", func(t *testing.T) {
		repos, err := client.ListUserRepos(context.Background(), false)
		if err != nil {
			t.Fatalf("ListUserRepos() error = %v", err)
		}
		if len(repos) != 3 {
			t.Errorf("ListUserRepos() returned %d repos, want 3", len(repos))
		}
	})

	t.Run("admin only", func(t *testing.T) {
		repos, err := client.ListUserRepos(context.Background(), true)
		if err != nil {
			t.Fatalf("ListUserRepos(adminOnly=true) error = %v", err)
		}
		if len(repos) != 2 {
			t.Errorf("ListUserRepos(adminOnly=true) returned %d repos, want 2", len(repos))
		}
		for _, repo := range repos {
			if repo.Permissions == nil || !repo.Permissions.Admin {
				t.Errorf("Repo %s should have admin access", repo.FullName)
			}
		}
	})
}

func TestGitHubClient_ListUserRepos_Pagination(t *testing.T) {
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		var repos []GitHubRepo

		if page == 1 {
			// Return full page (100 repos) to trigger pagination
			for i := 0; i < 100; i++ {
				repos = append(repos, GitHubRepo{
					ID:       int64(i),
					Name:     "repo",
					FullName: "user/repo",
					Permissions: &GitHubRepoPermissions{
						Admin: true,
					},
				})
			}
		} else {
			// Return partial page to end pagination
			for i := 0; i < 10; i++ {
				repos = append(repos, GitHubRepo{
					ID:       int64(100 + i),
					Name:     "repo",
					FullName: "user/repo",
					Permissions: &GitHubRepoPermissions{
						Admin: true,
					},
				})
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(repos)
	}))
	defer server.Close()

	client := NewGitHubClient("test-token", server.URL)
	repos, err := client.ListUserRepos(context.Background(), false)
	if err != nil {
		t.Fatalf("ListUserRepos() error = %v", err)
	}

	if len(repos) != 110 {
		t.Errorf("ListUserRepos() returned %d repos, want 110", len(repos))
	}

	if page != 2 {
		t.Errorf("Expected 2 pages of requests, got %d", page)
	}
}

func TestGitHubClient_ListUserRepos_AuthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message": "Bad credentials"}`))
	}))
	defer server.Close()

	client := NewGitHubClient("bad-token", server.URL)
	_, err := client.ListUserRepos(context.Background(), false)

	if err != ErrGitHubAuthentication {
		t.Errorf("ListUserRepos() error = %v, want %v", err, ErrGitHubAuthentication)
	}
}

func TestGitHubClient_ListUserRepos_RateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message": "API rate limit exceeded"}`))
	}))
	defer server.Close()

	client := NewGitHubClient("test-token", server.URL)
	_, err := client.ListUserRepos(context.Background(), false)

	if err != ErrGitHubRateLimited {
		t.Errorf("ListUserRepos() error = %v, want %v", err, ErrGitHubRateLimited)
	}
}

func TestGitHubClient_GetRepo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/repo" {
			t.Errorf("Unexpected path: %s", r.URL.Path)
		}

		repo := GitHubRepo{
			ID:       123,
			Name:     "repo",
			FullName: "owner/repo",
			Private:  false,
			HTMLURL:  "https://github.com/owner/repo",
			Permissions: &GitHubRepoPermissions{
				Admin: true,
				Push:  true,
				Pull:  true,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(repo)
	}))
	defer server.Close()

	client := NewGitHubClient("test-token", server.URL)
	repo, err := client.GetRepo(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("GetRepo() error = %v", err)
	}

	if repo.FullName != "owner/repo" {
		t.Errorf("GetRepo() FullName = %q, want %q", repo.FullName, "owner/repo")
	}

	if repo.Permissions == nil || !repo.Permissions.Admin {
		t.Error("GetRepo() should return repo with admin permissions")
	}
}

func TestGitHubClient_GetRepo_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "Not Found"}`))
	}))
	defer server.Close()

	client := NewGitHubClient("test-token", server.URL)
	_, err := client.GetRepo(context.Background(), "owner", "nonexistent")

	if err == nil {
		t.Error("GetRepo() expected error for non-existent repo")
	}
}
