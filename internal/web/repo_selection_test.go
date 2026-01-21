//go:build browser

package web

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Repository Selection Page Tests (TDD Red Phase)
//
// These tests verify the new repository selection page at /repositories/new
// which allows users to select repositories from their GitHub account via
// checkboxes instead of manually entering URLs.
//
// Expected behavior:
// - Page fetches user's GitHub repositories via OAuth
// - Displays repositories as a list with checkboxes
// - Already-connected repositories are shown but disabled
// - Form submission connects selected repositories
//
// Run with: go test -tags=browser -v ./internal/web -run TestBrowser_RepoSelection
// =============================================================================

// MockGitHubRepoLister simulates fetching repos from GitHub API
type MockGitHubRepoLister struct {
	repos []GitHubRepo
}

// Note: GitHubRepo is defined in router.go

func NewMockGitHubRepoLister() *MockGitHubRepoLister {
	return &MockGitHubRepoLister{
		repos: []GitHubRepo{
			{ID: 1, Name: "repo-one", FullName: "testuser/repo-one", HTMLURL: "https://github.com/testuser/repo-one", Description: "First test repo", Private: false},
			{ID: 2, Name: "repo-two", FullName: "testuser/repo-two", HTMLURL: "https://github.com/testuser/repo-two", Description: "Second test repo", Private: false},
			{ID: 3, Name: "private-repo", FullName: "testuser/private-repo", HTMLURL: "https://github.com/testuser/private-repo", Description: "Private repo", Private: true},
		},
	}
}

func (m *MockGitHubRepoLister) ListUserRepos(ctx context.Context, accessToken string) ([]GitHubRepo, error) {
	return m.repos, nil
}

func (m *MockGitHubRepoLister) AddRepo(repo GitHubRepo) {
	m.repos = append(m.repos, repo)
}

// TestBrowser_RepoSelection_RendersRepoList tests that the page displays a list of GitHub repos
func TestBrowser_RepoSelection_RendersRepoList(t *testing.T) {
	// Setup test server with GitHub repo lister
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	githubLister := NewMockGitHubRepoLister()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}

	// Router should accept GitHubRepoLister for the new selection page
	router := NewRouterWithGitHubRepoLister(userStore, repoStore, nil, nil, secretGen, "https://api.test", githubLister)

	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	// Create and login user
	testEmail := "repo-select-test@example.com"
	testPassword := "securepassword123"

	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Login
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Navigate to repo selection page
	page.MustNavigate(ts.URL + "/repositories/new").MustWaitLoad()
	page.MustWaitStable()

	// =========================================================================
	// Test: Page renders list of GitHub repositories
	// =========================================================================
	t.Log("Testing: Page renders list of GitHub repositories")

	// Should show repo list container
	repoList := page.MustElement(".repo-list")
	if repoList == nil {
		t.Fatal("FAILED: Expected .repo-list container on page")
	}

	// Should display all repos from GitHub
	bodyText := page.MustElement("body").MustText()

	if !strings.Contains(bodyText, "repo-one") {
		t.Error("FAILED: Expected 'repo-one' in repo list")
	}
	if !strings.Contains(bodyText, "repo-two") {
		t.Error("FAILED: Expected 'repo-two' in repo list")
	}
	if !strings.Contains(bodyText, "private-repo") {
		t.Error("FAILED: Expected 'private-repo' in repo list")
	}

	t.Log("PASSED: Page renders list of GitHub repositories")
}

// TestBrowser_RepoSelection_CheckboxSelection tests that repos can be selected via checkboxes
func TestBrowser_RepoSelection_CheckboxSelection(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	githubLister := NewMockGitHubRepoLister()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}

	router := NewRouterWithGitHubRepoLister(userStore, repoStore, nil, nil, secretGen, "https://api.test", githubLister)

	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	// Create and login user
	testEmail := "checkbox-test@example.com"
	testPassword := "securepassword123"

	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	page.MustNavigate(ts.URL + "/repositories/new").MustWaitLoad()
	page.MustWaitStable()

	// =========================================================================
	// Test: Checkboxes are present for each repository
	// =========================================================================
	t.Log("Testing: Checkboxes are present for each repository")

	checkboxes := page.MustElements("input[type='checkbox'][name='repos']")
	if len(checkboxes) < 3 {
		t.Fatalf("FAILED: Expected at least 3 checkboxes, got %d", len(checkboxes))
	}

	// =========================================================================
	// Test: Checkboxes can be selected
	// =========================================================================
	t.Log("Testing: Checkboxes can be selected")

	// Select first two repos
	checkboxes[0].MustClick()
	checkboxes[1].MustClick()

	// Verify they are checked
	isChecked0 := checkboxes[0].MustProperty("checked").Bool()
	isChecked1 := checkboxes[1].MustProperty("checked").Bool()
	isChecked2 := checkboxes[2].MustProperty("checked").Bool()

	if !isChecked0 {
		t.Error("FAILED: First checkbox should be checked")
	}
	if !isChecked1 {
		t.Error("FAILED: Second checkbox should be checked")
	}
	if isChecked2 {
		t.Error("FAILED: Third checkbox should NOT be checked")
	}

	t.Log("PASSED: Checkboxes can be selected")
}

// TestBrowser_RepoSelection_FormSubmission tests that selected repos are submitted correctly
func TestBrowser_RepoSelection_FormSubmission(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	githubLister := NewMockGitHubRepoLister()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}

	router := NewRouterWithGitHubRepoLister(userStore, repoStore, nil, nil, secretGen, "https://api.test", githubLister)

	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	// Create and login user
	testEmail := "form-submit-test@example.com"
	testPassword := "securepassword123"

	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Get user for later verification
	user, _ := userStore.GetUserByEmail(context.Background(), testEmail)

	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	page.MustNavigate(ts.URL + "/repositories/new").MustWaitLoad()
	page.MustWaitStable()

	// =========================================================================
	// Test: Form submission connects selected repositories
	// =========================================================================
	t.Log("Testing: Form submission connects selected repositories")

	// Select first repo
	checkboxes := page.MustElements("input[type='checkbox'][name='repos']")
	checkboxes[0].MustClick()

	// Submit form using JS submit (more reliable for checkbox forms in browser automation)
	page.MustElement("form.auth-form").MustEval(`() => this.submit()`)
	page.MustWaitLoad()
	page.MustWaitStable()

	// Should redirect to success or repositories page
	currentURL := page.MustInfo().URL
	if !strings.Contains(currentURL, "/repositories") {
		t.Fatalf("FAILED: Expected redirect to repositories page, got: %s", currentURL)
	}

	// Verify repository was created in store
	repos, _ := repoStore.ListRepositoriesByUser(context.Background(), user.ID)
	if len(repos) == 0 {
		t.Fatal("FAILED: Expected at least one repository to be created")
	}

	// Verify it's the correct repo
	found := false
	for _, repo := range repos {
		if strings.Contains(repo.GitHubURL, "repo-one") {
			found = true
			break
		}
	}
	if !found {
		t.Error("FAILED: Expected 'repo-one' to be in connected repositories")
	}

	t.Log("PASSED: Form submission connects selected repositories")
}

// TestBrowser_RepoSelection_AlreadyConnectedDisabled tests that already-connected repos are disabled
func TestBrowser_RepoSelection_AlreadyConnectedDisabled(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	githubLister := NewMockGitHubRepoLister()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}

	router := NewRouterWithGitHubRepoLister(userStore, repoStore, nil, nil, secretGen, "https://api.test", githubLister)

	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	// Create and login user
	testEmail := "already-connected-test@example.com"
	testPassword := "securepassword123"

	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Get user and pre-connect a repository
	user, _ := userStore.GetUserByEmail(context.Background(), testEmail)
	repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/testuser/repo-one", "secret")

	// Login
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	page.MustNavigate(ts.URL + "/repositories/new").MustWaitLoad()
	page.MustWaitStable()

	// =========================================================================
	// Test: Already-connected repo checkbox is disabled
	// =========================================================================
	t.Log("Testing: Already-connected repo checkbox is disabled")

	// Find the checkbox for repo-one (already connected)
	repoOneCheckbox := page.MustElement("input[type='checkbox'][value='https://github.com/testuser/repo-one']")
	if repoOneCheckbox == nil {
		t.Fatal("FAILED: Could not find checkbox for repo-one")
	}

	// Check if disabled
	isDisabled := repoOneCheckbox.MustProperty("disabled").Bool()
	if !isDisabled {
		t.Error("FAILED: Already-connected repo checkbox should be disabled")
	}

	// =========================================================================
	// Test: Already-connected repo shows "Connected" label
	// =========================================================================
	t.Log("Testing: Already-connected repo shows 'Connected' label")

	bodyText := page.MustElement("body").MustText()
	// The repo-one entry should have a "Connected" indicator
	if !strings.Contains(bodyText, "Connected") {
		t.Error("FAILED: Expected 'Connected' label for already-connected repo")
	}

	// =========================================================================
	// Test: Non-connected repos are still selectable
	// =========================================================================
	t.Log("Testing: Non-connected repos are still selectable")

	repoTwoCheckbox := page.MustElement("input[type='checkbox'][value='https://github.com/testuser/repo-two']")
	if repoTwoCheckbox == nil {
		t.Fatal("FAILED: Could not find checkbox for repo-two")
	}

	isDisabledTwo := repoTwoCheckbox.MustProperty("disabled").Bool()
	if isDisabledTwo {
		t.Error("FAILED: Non-connected repo checkbox should NOT be disabled")
	}

	t.Log("PASSED: Already-connected repos are disabled, others are selectable")
}

// TestBrowser_RepoSelection_EmptyState tests the page when user has no GitHub repos
func TestBrowser_RepoSelection_EmptyState(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	// Empty repo lister
	githubLister := &MockGitHubRepoLister{repos: []GitHubRepo{}}
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}

	router := NewRouterWithGitHubRepoLister(userStore, repoStore, nil, nil, secretGen, "https://api.test", githubLister)

	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	// Create and login user
	testEmail := "empty-repos-test@example.com"
	testPassword := "securepassword123"

	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	page.MustNavigate(ts.URL + "/repositories/new").MustWaitLoad()
	page.MustWaitStable()

	// =========================================================================
	// Test: Empty state message is shown
	// =========================================================================
	t.Log("Testing: Empty state message is shown when no repos")

	bodyText := page.MustElement("body").MustText()

	// Should show empty state message
	if !strings.Contains(bodyText, "No repositories found") && !strings.Contains(bodyText, "no repositories") {
		t.Error("FAILED: Expected empty state message when user has no GitHub repos")
	}

	t.Log("PASSED: Empty state message shown for users with no repos")
}

// TestBrowser_RepoSelection_RequiresAuth tests that the page requires authentication
func TestBrowser_RepoSelection_RequiresAuth(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	githubLister := NewMockGitHubRepoLister()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}

	router := NewRouterWithGitHubRepoLister(userStore, repoStore, nil, nil, secretGen, "https://api.test", githubLister)

	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	// =========================================================================
	// Test: Unauthenticated access redirects to login
	// =========================================================================
	t.Log("Testing: Unauthenticated access redirects to login")

	page.MustNavigate(ts.URL + "/repositories/new").MustWaitLoad()
	page.MustWaitStable()

	currentURL := page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/login") {
		t.Fatalf("FAILED: Expected redirect to /login, got: %s", currentURL)
	}

	t.Log("PASSED: Unauthenticated access redirects to login")
}
