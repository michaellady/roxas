package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mikelady/roxas/internal/auth"
)

// --- mock implementations ---

type mockAppClient struct {
	getInstallation func(ctx context.Context, installationID int64) (*GitHubAppInstallationInfo, error)
	listRepos       func(ctx context.Context, installationID int64) ([]GitHubAppRepo, error)
}

func (m *mockAppClient) GetInstallation(ctx context.Context, installationID int64) (*GitHubAppInstallationInfo, error) {
	return m.getInstallation(ctx, installationID)
}

func (m *mockAppClient) ListInstallationRepos(ctx context.Context, installationID int64) ([]GitHubAppRepo, error) {
	return m.listRepos(ctx, installationID)
}

type mockSetupUserStore struct {
	getOrCreate       func(ctx context.Context, githubID int64, githubLogin, email string) (*User, bool, error)
	getUserByID       func(ctx context.Context, userID string) (*User, error)
	linkGitHubIdentity func(ctx context.Context, userID string, githubID int64, githubLogin string) error
}

func (m *mockSetupUserStore) GetOrCreateByGitHub(ctx context.Context, githubID int64, githubLogin, email string) (*User, bool, error) {
	return m.getOrCreate(ctx, githubID, githubLogin, email)
}

func (m *mockSetupUserStore) GetUserByID(ctx context.Context, userID string) (*User, error) {
	if m.getUserByID != nil {
		return m.getUserByID(ctx, userID)
	}
	return nil, fmt.Errorf("not found")
}

func (m *mockSetupUserStore) LinkGitHubIdentity(ctx context.Context, userID string, githubID int64, githubLogin string) error {
	if m.linkGitHubIdentity != nil {
		return m.linkGitHubIdentity(ctx, userID, githubID, githubLogin)
	}
	return nil
}

type mockSetupInstallationStore struct {
	upsert func(ctx context.Context, inst *InstallationRecord) (*InstallationRecord, error)
}

func (m *mockSetupInstallationStore) UpsertInstallation(ctx context.Context, inst *InstallationRecord) (*InstallationRecord, error) {
	return m.upsert(ctx, inst)
}

type mockSetupAppRepoStore struct {
	upsert func(ctx context.Context, repo *AppRepositoryRecord) (*AppRepositoryRecord, error)
}

func (m *mockSetupAppRepoStore) UpsertAppRepository(ctx context.Context, repo *AppRepositoryRecord) (*AppRepositoryRecord, error) {
	return m.upsert(ctx, repo)
}

type mockSetupRepoStore struct {
	createFromApp  func(ctx context.Context, userID, githubURL, webhookSecret, appRepoID string) (*Repository, error)
	getByAppRepoID func(ctx context.Context, appRepoID string) (*Repository, error)
}

func (m *mockSetupRepoStore) CreateRepositoryFromApp(ctx context.Context, userID, githubURL, webhookSecret, appRepoID string) (*Repository, error) {
	return m.createFromApp(ctx, userID, githubURL, webhookSecret, appRepoID)
}

func (m *mockSetupRepoStore) GetRepositoryByAppRepoID(ctx context.Context, appRepoID string) (*Repository, error) {
	return m.getByAppRepoID(ctx, appRepoID)
}

type mockSetupSecretGen struct {
	generate func() (string, error)
}

func (m *mockSetupSecretGen) Generate() (string, error) {
	return m.generate()
}

// --- helper to build a fully-wired handler with sensible defaults ---

func newTestSetupHandler() (*GitHubAppSetupHandler, *mockAppClient, *mockSetupUserStore, *mockSetupInstallationStore, *mockSetupAppRepoStore, *mockSetupRepoStore, *mockSetupSecretGen) {
	appClient := &mockAppClient{
		getInstallation: func(ctx context.Context, installationID int64) (*GitHubAppInstallationInfo, error) {
			info := &GitHubAppInstallationInfo{ID: installationID}
			info.Account.Login = "testuser"
			info.Account.ID = 12345
			info.Account.Type = "User"
			return info, nil
		},
		listRepos: func(ctx context.Context, installationID int64) ([]GitHubAppRepo, error) {
			return []GitHubAppRepo{
				{ID: 100, FullName: "testuser/repo1", HTMLURL: "https://github.com/testuser/repo1", Private: false, DefaultBranch: "main"},
			}, nil
		},
	}

	userStore := &mockSetupUserStore{
		getOrCreate: func(ctx context.Context, githubID int64, githubLogin, email string) (*User, bool, error) {
			return &User{ID: "user-1", Email: email}, true, nil
		},
	}

	installStore := &mockSetupInstallationStore{
		upsert: func(ctx context.Context, inst *InstallationRecord) (*InstallationRecord, error) {
			return &InstallationRecord{ID: "inst-1", InstallationID: inst.InstallationID}, nil
		},
	}

	appRepoStore := &mockSetupAppRepoStore{
		upsert: func(ctx context.Context, repo *AppRepositoryRecord) (*AppRepositoryRecord, error) {
			return &AppRepositoryRecord{ID: "app-repo-1", InstallationID: repo.InstallationID, GitHubRepoID: repo.GitHubRepoID, FullName: repo.FullName}, nil
		},
	}

	repoStore := &mockSetupRepoStore{
		createFromApp: func(ctx context.Context, userID, githubURL, webhookSecret, appRepoID string) (*Repository, error) {
			return &Repository{ID: "repo-1", UserID: userID, GitHubURL: githubURL}, nil
		},
		getByAppRepoID: func(ctx context.Context, appRepoID string) (*Repository, error) {
			return nil, nil // no existing row
		},
	}

	secretGen := &mockSetupSecretGen{
		generate: func() (string, error) {
			return "whsec_test_secret", nil
		},
	}

	h := NewGitHubAppSetupHandler(appClient, userStore, installStore, appRepoStore, repoStore, secretGen)
	return h, appClient, userStore, installStore, appRepoStore, repoStore, secretGen
}

func TestGitHubAppSetup_Success(t *testing.T) {
	h, _, _, _, _, repoStore, _ := newTestSetupHandler()

	var createdAppRepoID string
	repoStore.createFromApp = func(ctx context.Context, userID, githubURL, webhookSecret, appRepoID string) (*Repository, error) {
		createdAppRepoID = appRepoID
		if userID != "user-1" {
			t.Errorf("expected userID user-1, got %s", userID)
		}
		if githubURL != "https://github.com/testuser/repo1" {
			t.Errorf("expected github URL https://github.com/testuser/repo1, got %s", githubURL)
		}
		if webhookSecret != "whsec_test_secret" {
			t.Errorf("expected webhook secret whsec_test_secret, got %s", webhookSecret)
		}
		return &Repository{ID: "repo-1", UserID: userID, GitHubURL: githubURL}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/github-app/setup?installation_id=42&setup_action=install", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location != "/repositories?installed=true" {
		t.Errorf("expected redirect to /repositories?installed=true, got %s", location)
	}

	if createdAppRepoID != "app-repo-1" {
		t.Errorf("expected CreateRepositoryFromApp called with app-repo-1, got %s", createdAppRepoID)
	}
}

func TestGitHubAppSetup_MissingInstallationID(t *testing.T) {
	h, _, _, _, _, _, _ := newTestSetupHandler()

	req := httptest.NewRequest(http.MethodGet, "/github-app/setup", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location != "/repositories?error=missing_installation_id" {
		t.Errorf("expected redirect with missing_installation_id error, got %s", location)
	}
}

func TestGitHubAppSetup_InvalidInstallationID(t *testing.T) {
	h, _, _, _, _, _, _ := newTestSetupHandler()

	req := httptest.NewRequest(http.MethodGet, "/github-app/setup?installation_id=notanumber", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location != "/repositories?error=invalid_installation_id" {
		t.Errorf("expected redirect with invalid_installation_id error, got %s", location)
	}
}

func TestGitHubAppSetup_GetInstallationError(t *testing.T) {
	h, appClient, _, _, _, _, _ := newTestSetupHandler()

	appClient.getInstallation = func(ctx context.Context, installationID int64) (*GitHubAppInstallationInfo, error) {
		return nil, fmt.Errorf("GitHub API unavailable")
	}

	req := httptest.NewRequest(http.MethodGet, "/github-app/setup?installation_id=42&setup_action=install", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location != "/repositories?error=github_api_error" {
		t.Errorf("expected redirect with github_api_error, got %s", location)
	}
}

func TestGitHubAppSetup_LoggedInUserReusesExistingAccount(t *testing.T) {
	h, _, userStore, _, _, repoStore, _ := newTestSetupHandler()

	// The logged-in user (email/password signup) has ID "existing-user"
	existingUser := &User{ID: "existing-user", Email: "alice@example.com"}

	userStore.getUserByID = func(ctx context.Context, userID string) (*User, error) {
		if userID == "existing-user" {
			return existingUser, nil
		}
		return nil, fmt.Errorf("not found")
	}

	var linkedUserID string
	var linkedGitHubID int64
	userStore.linkGitHubIdentity = func(ctx context.Context, userID string, githubID int64, githubLogin string) error {
		linkedUserID = userID
		linkedGitHubID = githubID
		return nil
	}

	// GetOrCreateByGitHub should NOT be called when user is logged in
	getOrCreateCalled := false
	userStore.getOrCreate = func(ctx context.Context, githubID int64, githubLogin, email string) (*User, bool, error) {
		getOrCreateCalled = true
		return &User{ID: "github-user", Email: email}, true, nil
	}

	// Track which user ID repos are created under
	var repoCreatedForUserID string
	repoStore.createFromApp = func(ctx context.Context, userID, githubURL, webhookSecret, appRepoID string) (*Repository, error) {
		repoCreatedForUserID = userID
		return &Repository{ID: "repo-1", UserID: userID, GitHubURL: githubURL}, nil
	}

	// Generate a valid auth token for the existing user
	token, err := auth.GenerateToken("existing-user", "alice@example.com")
	if err != nil {
		t.Fatalf("failed to generate test token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/github-app/setup?installation_id=42&setup_action=install", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location != "/repositories?installed=true" {
		t.Errorf("expected redirect to /repositories?installed=true, got %s", location)
	}

	// Verify repos were created under the existing user, not a new GitHub user
	if repoCreatedForUserID != "existing-user" {
		t.Errorf("expected repos created for existing-user, got %s", repoCreatedForUserID)
	}

	// Verify GetOrCreateByGitHub was NOT called
	if getOrCreateCalled {
		t.Error("expected GetOrCreateByGitHub to NOT be called when user is logged in")
	}

	// Verify GitHub identity was linked to existing user
	if linkedUserID != "existing-user" {
		t.Errorf("expected LinkGitHubIdentity called for existing-user, got %s", linkedUserID)
	}
	if linkedGitHubID != 12345 {
		t.Errorf("expected LinkGitHubIdentity called with GitHub ID 12345, got %d", linkedGitHubID)
	}

	// Verify no new auth cookie was set (user already had one)
	for _, cookie := range resp.Cookies() {
		if cookie.Name == auth.CookieName {
			t.Error("expected no new auth cookie to be set when user is already logged in")
		}
	}
}
