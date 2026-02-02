package clients

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// Property 7: Repository Filtering by Admin Access
// For any list of repositories fetched from GitHub, only repositories where
// the user has admin access should be included in the filtered result.
// Validates: Requirements 2.5

// genPermissions generates random GitHubRepoPermissions
func genPermissions() gopter.Gen {
	return gopter.CombineGens(
		gen.Bool(), // Admin
		gen.Bool(), // Maintain
		gen.Bool(), // Push
		gen.Bool(), // Triage
		gen.Bool(), // Pull
	).Map(func(vals []interface{}) *GitHubRepoPermissions {
		return &GitHubRepoPermissions{
			Admin:    vals[0].(bool),
			Maintain: vals[1].(bool),
			Push:     vals[2].(bool),
			Triage:   vals[3].(bool),
			Pull:     vals[4].(bool),
		}
	})
}

// genOptionalPermissions generates either nil or random permissions
func genOptionalPermissions() gopter.Gen {
	return gen.OneGenOf(
		gen.Const((*GitHubRepoPermissions)(nil)),
		genPermissions(),
	)
}

// genRepo generates a random GitHubRepo with optional permissions
func genRepo(id int64) gopter.Gen {
	return gopter.CombineGens(
		gen.AlphaString(),      // Name
		gen.Bool(),             // Private
		genOptionalPermissions(), // Permissions
	).Map(func(vals []interface{}) GitHubRepo {
		name := vals[0].(string)
		if name == "" {
			name = "repo"
		}
		return GitHubRepo{
			ID:          id,
			Name:        name,
			FullName:    "user/" + name,
			Private:     vals[1].(bool),
			HTMLURL:     "https://github.com/user/" + name,
			Permissions: vals[2].(*GitHubRepoPermissions),
		}
	})
}

// genRepoList generates a slice of repositories with varying permissions
func genRepoList() gopter.Gen {
	return gen.IntRange(0, 50).FlatMap(func(v interface{}) gopter.Gen {
		count := v.(int)
		gens := make([]gopter.Gen, count)
		for i := 0; i < count; i++ {
			gens[i] = genRepo(int64(i + 1))
		}
		if len(gens) == 0 {
			return gen.Const([]GitHubRepo{})
		}
		return gopter.CombineGens(gens...).Map(func(vals []interface{}) []GitHubRepo {
			repos := make([]GitHubRepo, len(vals))
			for i, v := range vals {
				repos[i] = v.(GitHubRepo)
			}
			return repos
		})
	}, reflect.TypeOf([]GitHubRepo{}))
}

// hasAdminAccess returns true if the repo has admin permissions
func hasAdminAccess(repo GitHubRepo) bool {
	return repo.Permissions != nil && repo.Permissions.Admin
}

// TestProperty_AdminFilterIncludesOnlyAdminRepos verifies Property 7:
// When adminOnly=true, all returned repos must have admin access
func TestProperty_AdminFilterIncludesOnlyAdminRepos(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 50

	properties := gopter.NewProperties(parameters)

	properties.Property("admin filter returns only repos with admin access", prop.ForAll(
		func(repos []GitHubRepo) bool {
			// Create mock server that returns the generated repos
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(repos)
			}))
			defer server.Close()

			client := NewGitHubClient("test-token", server.URL)
			filtered, err := client.ListUserRepos(context.Background(), true)
			if err != nil {
				t.Logf("Unexpected error: %v", err)
				return false
			}

			// Property: Every returned repo must have admin access
			for _, repo := range filtered {
				if !hasAdminAccess(repo) {
					t.Logf("Found repo without admin access: %s (permissions: %+v)",
						repo.FullName, repo.Permissions)
					return false
				}
			}

			return true
		},
		genRepoList(),
	))

	properties.TestingRun(t)
}

// TestProperty_AdminFilterExcludesNonAdminRepos verifies that non-admin repos are excluded
func TestProperty_AdminFilterExcludesNonAdminRepos(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 50

	properties := gopter.NewProperties(parameters)

	properties.Property("admin filter excludes repos without admin access", prop.ForAll(
		func(repos []GitHubRepo) bool {
			// Create mock server that returns the generated repos
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(repos)
			}))
			defer server.Close()

			client := NewGitHubClient("test-token", server.URL)
			filtered, err := client.ListUserRepos(context.Background(), true)
			if err != nil {
				t.Logf("Unexpected error: %v", err)
				return false
			}

			// Count expected admin repos
			expectedAdminCount := 0
			for _, repo := range repos {
				if hasAdminAccess(repo) {
					expectedAdminCount++
				}
			}

			// Property: The count of filtered repos must equal expected admin repos
			if len(filtered) != expectedAdminCount {
				t.Logf("Expected %d admin repos, got %d", expectedAdminCount, len(filtered))
				return false
			}

			return true
		},
		genRepoList(),
	))

	properties.TestingRun(t)
}

// TestProperty_NonAdminFilterReturnsAllRepos verifies adminOnly=false returns everything
func TestProperty_NonAdminFilterReturnsAllRepos(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 50

	properties := gopter.NewProperties(parameters)

	properties.Property("non-admin filter returns all repos", prop.ForAll(
		func(repos []GitHubRepo) bool {
			// Create mock server that returns the generated repos
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(repos)
			}))
			defer server.Close()

			client := NewGitHubClient("test-token", server.URL)
			result, err := client.ListUserRepos(context.Background(), false)
			if err != nil {
				t.Logf("Unexpected error: %v", err)
				return false
			}

			// Property: All repos should be returned when adminOnly=false
			if len(result) != len(repos) {
				t.Logf("Expected %d repos, got %d", len(repos), len(result))
				return false
			}

			return true
		},
		genRepoList(),
	))

	properties.TestingRun(t)
}

// TestProperty_AdminFilterPreservesRepoData verifies filtered repos maintain data integrity
func TestProperty_AdminFilterPreservesRepoData(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 50

	properties := gopter.NewProperties(parameters)

	properties.Property("admin filter preserves repository data", prop.ForAll(
		func(repos []GitHubRepo) bool {
			// Create mock server that returns the generated repos
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(repos)
			}))
			defer server.Close()

			client := NewGitHubClient("test-token", server.URL)
			filtered, err := client.ListUserRepos(context.Background(), true)
			if err != nil {
				t.Logf("Unexpected error: %v", err)
				return false
			}

			// Build a map of original repos by ID for lookup
			originalByID := make(map[int64]GitHubRepo)
			for _, repo := range repos {
				originalByID[repo.ID] = repo
			}

			// Property: Each filtered repo must match its original data
			for _, filteredRepo := range filtered {
				original, exists := originalByID[filteredRepo.ID]
				if !exists {
					t.Logf("Filtered repo ID %d not found in original", filteredRepo.ID)
					return false
				}
				if filteredRepo.Name != original.Name ||
					filteredRepo.FullName != original.FullName ||
					filteredRepo.Private != original.Private {
					t.Logf("Repo data mismatch for %s", filteredRepo.FullName)
					return false
				}
			}

			return true
		},
		genRepoList(),
	))

	properties.TestingRun(t)
}
