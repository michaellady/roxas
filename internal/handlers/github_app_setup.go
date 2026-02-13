package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/mikelady/roxas/internal/auth"
)

// GitHubAppClientInterface defines the GitHub App API operations needed by the setup handler.
type GitHubAppClientInterface interface {
	GetInstallation(ctx context.Context, installationID int64) (*GitHubAppInstallationInfo, error)
	ListInstallationRepos(ctx context.Context, installationID int64) ([]GitHubAppRepo, error)
}

// SetupUserStore defines user operations needed by the setup handler.
type SetupUserStore interface {
	GetOrCreateByGitHub(ctx context.Context, githubID int64, githubLogin, email string) (*User, bool, error)
	GetUserByID(ctx context.Context, userID string) (*User, error)
	LinkGitHubIdentity(ctx context.Context, userID string, githubID int64, githubLogin string) error
}

// SetupInstallationStore defines installation operations needed by the setup handler.
type SetupInstallationStore interface {
	UpsertInstallation(ctx context.Context, inst *InstallationRecord) (*InstallationRecord, error)
}

// SetupAppRepoStore defines app repository operations needed by the setup handler.
type SetupAppRepoStore interface {
	UpsertAppRepository(ctx context.Context, repo *AppRepositoryRecord) (*AppRepositoryRecord, error)
}

// SetupRepositoryStore defines repository operations needed by the setup handler.
type SetupRepositoryStore interface {
	CreateRepositoryFromApp(ctx context.Context, userID, githubURL, webhookSecret, appRepoID string) (*Repository, error)
	GetRepositoryByAppRepoID(ctx context.Context, appRepoID string) (*Repository, error)
	UpdateRepositoryUserID(ctx context.Context, repoID, userID string) error
}

// SetupSecretGenerator generates webhook secrets for new repositories.
type SetupSecretGenerator interface {
	Generate() (string, error)
}

// GitHubAppInstallationInfo represents installation details returned by the GitHub API.
type GitHubAppInstallationInfo struct {
	ID      int64
	Account struct {
		Login string
		ID    int64
		Type  string
	}
}

// GitHubAppRepo represents a repository accessible to a GitHub App installation.
type GitHubAppRepo struct {
	ID            int64
	FullName      string
	HTMLURL       string
	Private       bool
	DefaultBranch string
}

// InstallationRecord is a handler-local representation of a GitHub App installation
// used to avoid import cycles with the database package.
type InstallationRecord struct {
	ID             string
	InstallationID int64
	UserID         string
	AccountLogin   string
	AccountID      int64
	AccountType    string
}

// AppRepositoryRecord is a handler-local representation of a GitHub App repository
// used to avoid import cycles with the database package.
type AppRepositoryRecord struct {
	ID             string
	InstallationID int64
	GitHubRepoID   int64
	FullName       string
	HTMLURL        string
	Private        bool
	DefaultBranch  string
	IsActive       bool
}

// GitHubAppSetupHandler handles the post-installation redirect from GitHub.
// Route: GET /github-app/setup?installation_id=123&setup_action=install
type GitHubAppSetupHandler struct {
	appClient         GitHubAppClientInterface
	userStore         SetupUserStore
	installationStore SetupInstallationStore
	appRepoStore      SetupAppRepoStore
	repoStore         SetupRepositoryStore
	secretGen         SetupSecretGenerator
}

// NewGitHubAppSetupHandler creates a new setup handler.
func NewGitHubAppSetupHandler(
	appClient GitHubAppClientInterface,
	userStore SetupUserStore,
	installationStore SetupInstallationStore,
	appRepoStore SetupAppRepoStore,
	repoStore SetupRepositoryStore,
	secretGen SetupSecretGenerator,
) *GitHubAppSetupHandler {
	return &GitHubAppSetupHandler{
		appClient:         appClient,
		userStore:         userStore,
		installationStore: installationStore,
		appRepoStore:      appRepoStore,
		repoStore:         repoStore,
		secretGen:         secretGen,
	}
}

// ServeHTTP handles the GitHub App setup callback.
func (h *GitHubAppSetupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Extract and validate installation_id
	installationIDStr := r.URL.Query().Get("installation_id")
	if installationIDStr == "" {
		http.Redirect(w, r, "/repositories?error=missing_installation_id", http.StatusSeeOther)
		return
	}

	installationID, err := strconv.ParseInt(installationIDStr, 10, 64)
	if err != nil {
		http.Redirect(w, r, "/repositories?error=invalid_installation_id", http.StatusSeeOther)
		return
	}

	// 2. Get installation details from GitHub
	installation, err := h.appClient.GetInstallation(ctx, installationID)
	if err != nil {
		log.Printf("ERROR: failed to get installation %d: %v", installationID, err)
		http.Redirect(w, r, "/repositories?error=github_api_error", http.StatusSeeOther)
		return
	}

	// 3. Resolve user: prefer existing session, fall back to GitHub identity
	var user *User

	// Check if user is already logged in
	if cookie, cookieErr := r.Cookie(auth.CookieName); cookieErr == nil && cookie.Value != "" {
		if claims, validateErr := auth.ValidateToken(cookie.Value); validateErr == nil {
			existingUser, lookupErr := h.userStore.GetUserByID(ctx, claims.UserID)
			if lookupErr == nil && existingUser != nil {
				user = existingUser
				// Link GitHub identity to existing user so future lookups find them
				if linkErr := h.userStore.LinkGitHubIdentity(ctx, user.ID, installation.Account.ID, installation.Account.Login); linkErr != nil {
					log.Printf("WARNING: failed to link GitHub identity to user %s: %v", user.ID, linkErr)
				}
			}
		}
	}

	// Fall back to GetOrCreateByGitHub if not logged in
	if user == nil {
		email := installation.Account.Login + "@users.noreply.github.com"
		var err error
		user, _, err = h.userStore.GetOrCreateByGitHub(ctx, installation.Account.ID, installation.Account.Login, email)
		if err != nil {
			log.Printf("ERROR: failed to get/create user for GitHub account %s: %v", installation.Account.Login, err)
			http.Redirect(w, r, "/repositories?error=user_creation_failed", http.StatusSeeOther)
			return
		}

		// Generate JWT and set auth cookie only for new/unauthenticated users
		token, err := auth.GenerateToken(user.ID, user.Email)
		if err != nil {
			log.Printf("ERROR: failed to generate token for user %s: %v", user.ID, err)
			http.Redirect(w, r, "/repositories?error=auth_failed", http.StatusSeeOther)
			return
		}

		auth.SetAuthCookie(w, token, 86400)
	}

	// 5. Upsert installation record
	_, err = h.installationStore.UpsertInstallation(ctx, &InstallationRecord{
		InstallationID: installationID,
		UserID:         user.ID,
		AccountLogin:   installation.Account.Login,
		AccountID:      installation.Account.ID,
		AccountType:    installation.Account.Type,
	})
	if err != nil {
		log.Printf("ERROR: failed to upsert installation %d: %v", installationID, err)
		http.Redirect(w, r, "/repositories?error=installation_save_failed", http.StatusSeeOther)
		return
	}

	// 6. List installation repos
	repos, err := h.appClient.ListInstallationRepos(ctx, installationID)
	if err != nil {
		log.Printf("ERROR: failed to list repos for installation %d: %v", installationID, err)
		http.Redirect(w, r, "/repositories?error=repo_list_failed", http.StatusSeeOther)
		return
	}

	// 7. Sync each repo
	for _, repo := range repos {
		appRepo, err := h.appRepoStore.UpsertAppRepository(ctx, &AppRepositoryRecord{
			InstallationID: installationID,
			GitHubRepoID:   repo.ID,
			FullName:       repo.FullName,
			HTMLURL:        repo.HTMLURL,
			Private:        repo.Private,
			DefaultBranch:  repo.DefaultBranch,
		})
		if err != nil {
			log.Printf("ERROR: failed to upsert app repo %s: %v", repo.FullName, err)
			continue
		}

		// Check if a linked repositories row already exists
		existing, err := h.repoStore.GetRepositoryByAppRepoID(ctx, appRepo.ID)
		if err != nil {
			log.Printf("ERROR: failed to check existing repo for app_repo %s: %v", appRepo.ID, err)
			continue
		}

		if existing != nil {
			// Reassign repo to current user if it belongs to a different user
			// (e.g. a duplicate user created before the session-aware fix)
			if existing.UserID != user.ID {
				if err := h.repoStore.UpdateRepositoryUserID(ctx, existing.ID, user.ID); err != nil {
					log.Printf("ERROR: failed to reassign repo %s to user %s: %v", existing.ID, user.ID, err)
				}
			}
			continue
		}

		// Generate webhook secret and create linked repository
		secret, err := h.secretGen.Generate()
		if err != nil {
			log.Printf("ERROR: failed to generate webhook secret for %s: %v", repo.FullName, err)
			continue
		}

		githubURL := fmt.Sprintf("https://github.com/%s", repo.FullName)
		_, err = h.repoStore.CreateRepositoryFromApp(ctx, user.ID, githubURL, secret, appRepo.ID)
		if err != nil {
			log.Printf("ERROR: failed to create repository for %s: %v", repo.FullName, err)
			continue
		}
	}

	// 8. Redirect to repositories page
	http.Redirect(w, r, "/repositories?installed=true", http.StatusSeeOther)
}
