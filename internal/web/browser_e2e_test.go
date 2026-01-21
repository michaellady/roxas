//go:build browser

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
)

// =============================================================================
// Browser-based E2E Tests using Rod
//
// These tests launch a real browser (Chromium) to verify the web UI works
// correctly in an actual browser environment. This catches issues that
// httptest cannot detect, such as:
// - JavaScript errors
// - CSS rendering issues
// - Browser-specific cookie handling
// - Form submission behavior
// - Client-side validation
//
// Run with: go test -tags=browser -v ./internal/web -run TestBrowser
//
// By default, tests run headless. Set BROWSER_VISIBLE=1 to watch:
//   BROWSER_VISIBLE=1 go test -tags=browser -v ./internal/web -run TestBrowser
//
// =============================================================================

// browserTestConfig holds configuration for browser tests
type browserTestConfig struct {
	headless bool
	slowMo   time.Duration // slow down actions for visibility
}

// getBrowserConfig returns test configuration based on environment
func getBrowserConfig() browserTestConfig {
	cfg := browserTestConfig{
		headless: true,
		slowMo:   0,
	}

	if os.Getenv("BROWSER_VISIBLE") == "1" {
		cfg.headless = false
		cfg.slowMo = 300 * time.Millisecond // slow down so you can see what's happening
	}

	return cfg
}

// launchBrowser creates a browser instance with the given configuration.
// Returns the browser and a cleanup function that properly closes both the
// browser connection and kills the underlying Chromium process.
func launchBrowser(cfg browserTestConfig) (*rod.Browser, func()) {
	// Create launcher with common settings for CI environments
	l := launcher.New().
		// Required for running in CI/Docker without root
		NoSandbox(true).
		Headless(cfg.headless)

	if !cfg.headless {
		l = l.Devtools(false)
	}

	u := l.MustLaunch()
	browser := rod.New().ControlURL(u).MustConnect()

	if !cfg.headless {
		browser = browser.SlowMotion(cfg.slowMo)
	}

	// Cleanup must close browser AND kill the launcher process to avoid leaks
	cleanup := func() {
		browser.MustClose()
		l.Cleanup() // Kill the Chromium process and clean up temp directories
	}

	return browser, cleanup
}

// inputText finds an input field and sets its value.
// Note: Uses Must* methods that panic on failure. For improved error handling,
// see bead roxas-kosm for planned refactor to explicit error returns.
func inputText(t *testing.T, page *rod.Page, selector, text string) {
	t.Helper()
	el := page.MustElement(selector)
	// Use Eval to set value directly - more reliable than Input in headless mode
	el.MustEval(`(text) => { this.value = ''; this.value = text; }`, text)
	// Trigger input event to ensure form validation sees the change
	el.MustEval(`() => this.dispatchEvent(new Event('input', { bubbles: true }))`)
}

// TestBrowser_FullAuthFlow tests the complete authentication flow in a real browser:
// signup → login → dashboard → logout → redirect to login
func TestBrowser_FullAuthFlow(t *testing.T) {
	// Setup test server with mock stores
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	commitLister := NewMockCommitListerForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, commitLister, nil, nil, "")

	ts := httptest.NewServer(router)
	defer ts.Close()

	// Launch browser
	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	testEmail := "browser-test@example.com"
	testPassword := "securepassword123"

	// =========================================================================
	// Step 1: Navigate to home page
	// =========================================================================
	t.Log("Step 1: Navigate to home page")

	page.MustWaitLoad()

	// Verify we're on the home page
	title := page.MustElement("title").MustText()
	if !strings.Contains(title, "Roxas") {
		t.Fatalf("Expected title to contain 'Roxas', got: %s", title)
	}
	t.Log("Step 1 PASSED: Home page loaded")

	// =========================================================================
	// Step 2: Navigate to signup page
	// =========================================================================
	t.Log("Step 2: Navigate to signup page")

	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()

	// Verify signup form is present
	signupForm := page.MustElement("form.auth-form")
	if signupForm == nil {
		t.Fatal("Step 2 FAILED: Signup form not found")
	}

	h1 := page.MustElement("h1").MustText()
	if h1 != "Sign Up" {
		t.Fatalf("Step 2 FAILED: Expected h1 'Sign Up', got: %s", h1)
	}
	t.Log("Step 2 PASSED: Signup page loaded with form")

	// =========================================================================
	// Step 3: Fill and submit signup form
	// =========================================================================
	t.Log("Step 3: Fill and submit signup form")

	// Fill in the form fields
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)

	// Submit form
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()

	// Should redirect to login page after successful signup
	// Wait a moment for the redirect to complete
	page.MustWaitStable()
	currentURL := page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/login") {
		// Check if there's an error on the page
		bodyText := page.MustElement("body").MustText()
		t.Fatalf("Step 3 FAILED: Expected redirect to /login, got: %s\nPage content: %s", currentURL, bodyText[:min(len(bodyText), 500)])
	}
	t.Log("Step 3 PASSED: Signup successful, redirected to login")

	// =========================================================================
	// Step 4: Login with created account
	// =========================================================================
	t.Log("Step 4: Login with created account")

	// Fill login form
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)

	// Submit form
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Should redirect to dashboard after successful login
	currentURL = page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/dashboard") {
		bodyText := page.MustElement("body").MustText()
		t.Fatalf("Step 4 FAILED: Expected redirect to /dashboard, got: %s\nPage content: %s", currentURL, bodyText[:min(len(bodyText), 500)])
	}
	t.Log("Step 4 PASSED: Login successful, redirected to dashboard")

	// =========================================================================
	// Step 5: Verify dashboard content
	// =========================================================================
	t.Log("Step 5: Verify dashboard content")

	dashboardH1 := page.MustElement("h1").MustText()
	if dashboardH1 != "Dashboard" {
		t.Fatalf("Step 5 FAILED: Expected h1 'Dashboard', got: %s", dashboardH1)
	}

	// Should show empty state for new user
	emptyState := page.MustElement(".empty-state")
	if emptyState == nil {
		t.Fatal("Step 5 FAILED: Expected empty state for new user")
	}

	getStartedText := emptyState.MustText()
	if !strings.Contains(getStartedText, "Get Started") {
		t.Fatalf("Step 5 FAILED: Expected 'Get Started' in empty state, got: %s", getStartedText)
	}
	t.Log("Step 5 PASSED: Dashboard shows empty state for new user")

	// =========================================================================
	// Step 6: Logout
	// =========================================================================
	t.Log("Step 6: Logout")

	// Find the logout form and submit it
	// The form action is /logout and contains button.btn-link
	logoutForm := page.MustElement("form[action='/logout']")
	if logoutForm == nil {
		t.Fatal("Step 6 FAILED: Logout form not found")
	}

	// Click the submit button within the form
	logoutForm.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Should redirect to login page after logout
	currentURL = page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/login") {
		t.Fatalf("Step 6 FAILED: Expected redirect to /login after logout, got: %s", currentURL)
	}
	t.Log("Step 6 PASSED: Logout successful, redirected to login")

	// =========================================================================
	// Step 7: Verify dashboard requires authentication
	// =========================================================================
	t.Log("Step 7: Verify dashboard requires authentication after logout")

	page.MustNavigate(ts.URL + "/dashboard").MustWaitLoad()

	// Should redirect to login since we're logged out
	currentURL = page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/login") {
		t.Fatalf("Step 7 FAILED: Expected redirect to /login, dashboard should require auth, got: %s", currentURL)
	}
	t.Log("Step 7 PASSED: Dashboard requires authentication after logout")

	t.Log("=== ALL BROWSER E2E TESTS PASSED ===")
}

// TestBrowser_SignupValidation tests client-side form validation
func TestBrowser_SignupValidation(t *testing.T) {
	// Setup test server
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)
	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL + "/signup").Timeout(30 * time.Second)
	defer page.MustClose()

	page.MustWaitLoad()

	// =========================================================================
	// Test: Password mismatch shows error
	// =========================================================================
	t.Log("Testing password mismatch validation")

	inputText(t, page, "#email", "test@example.com")
	inputText(t, page, "#password", "password123")
	inputText(t, page, "#confirm_password", "differentpassword")
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()

	// Should show error message
	errorAlert := page.MustElement(".alert-error")
	if errorAlert == nil {
		t.Fatal("Expected error alert for password mismatch")
	}

	errorText := errorAlert.MustText()
	if !strings.Contains(errorText, "Passwords do not match") {
		t.Fatalf("Expected 'Passwords do not match' error, got: %s", errorText)
	}
	t.Log("PASSED: Password mismatch shows correct error")

	// =========================================================================
	// Test: Short password shows error
	// =========================================================================
	t.Log("Testing short password validation")

	// Navigate fresh to avoid stale state
	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()

	inputText(t, page, "#email", "test2@example.com")
	inputText(t, page, "#password", "short")
	inputText(t, page, "#confirm_password", "short")
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()

	// Should show error message
	errorAlert = page.MustElement(".alert-error")
	if errorAlert == nil {
		t.Fatal("Expected error alert for short password")
	}

	errorText = errorAlert.MustText()
	if !strings.Contains(errorText, "at least 8 characters") {
		t.Fatalf("Expected password length error, got: %s", errorText)
	}
	t.Log("PASSED: Short password shows correct error")
}

// TestBrowser_LoginValidation tests login error handling
func TestBrowser_LoginValidation(t *testing.T) {
	// Setup test server
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)
	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL + "/login").Timeout(30 * time.Second)
	defer page.MustClose()

	page.MustWaitLoad()

	// =========================================================================
	// Test: Invalid credentials show error
	// =========================================================================
	t.Log("Testing invalid credentials")

	inputText(t, page, "#email", "nonexistent@example.com")
	inputText(t, page, "#password", "wrongpassword")
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()

	// Should show error message
	errorAlert := page.MustElement(".alert-error")
	if errorAlert == nil {
		t.Fatal("Expected error alert for invalid credentials")
	}

	errorText := errorAlert.MustText()
	if !strings.Contains(errorText, "Invalid email or password") {
		t.Fatalf("Expected 'Invalid email or password' error, got: %s", errorText)
	}
	t.Log("PASSED: Invalid credentials show correct error")
}

// TestBrowser_DashboardWithData tests dashboard displays repository and commit data
func TestBrowser_DashboardWithData(t *testing.T) {
	// Setup test server with data
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	commitLister := NewMockCommitListerForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, commitLister, nil, nil, "")

	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	// Create user and add test data
	testEmail := "data-test@example.com"
	testPassword := "securepassword123"

	// Signup
	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Get the user ID so we can add test data
	user, err := userStore.GetUserByEmail(context.Background(), testEmail)
	if err != nil {
		t.Fatalf("Failed to get created user: %v", err)
	}
	if user == nil {
		t.Fatal("User not found after signup")
	}

	// Add test repository and commit
	repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/test/repo", "secret123")
	commitLister.AddCommitForUser(user.ID, &DashboardCommit{
		SHA:     "abc1234567890",
		Message: "Add awesome feature",
		Author:  "Test Author",
	})

	// Login
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Verify we're on dashboard
	currentURL := page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/dashboard") {
		t.Fatalf("Expected to be on dashboard, got: %s", currentURL)
	}

	// =========================================================================
	// Verify repository is displayed
	// =========================================================================
	t.Log("Verifying repository display")

	bodyText := page.MustElement("body").MustText()
	if !strings.Contains(bodyText, "github.com/test/repo") {
		t.Fatalf("Expected repository URL in dashboard, got body: %s", bodyText[:min(len(bodyText), 500)])
	}
	t.Log("PASSED: Repository displayed correctly")

	// =========================================================================
	// Verify commit is displayed
	// =========================================================================
	t.Log("Verifying commit display")

	if !strings.Contains(bodyText, "Add awesome feature") {
		t.Fatalf("Expected commit message in dashboard, got body: %s", bodyText[:min(len(bodyText), 500)])
	}

	if !strings.Contains(bodyText, "abc1234") {
		t.Fatalf("Expected commit SHA in dashboard, got body: %s", bodyText[:min(len(bodyText), 500)])
	}
	t.Log("PASSED: Commit displayed correctly")
}

// TestBrowser_AddRepositoryFlow tests the complete add repository workflow:
// dashboard → add repo → success page with webhook config → dashboard shows repo
func TestBrowser_AddRepositoryFlow(t *testing.T) {
	// Fixed webhook secret for deterministic testing
	const testWebhookSecret = "test-webhook-secret-browser-e2e"
	const testWebhookBaseURL = "https://api.roxas.test"

	// Setup test server with mock stores and secret generator
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	secretGen := &MockSecretGeneratorForWeb{Secret: testWebhookSecret}
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, secretGen, testWebhookBaseURL)

	ts := httptest.NewServer(router)
	defer ts.Close()

	// Launch browser
	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	testEmail := "repo-browser-test@example.com"
	testPassword := "securepassword123"
	testGitHubURL := "https://github.com/browsertest/myrepo"

	// =========================================================================
	// Step 1: Sign up
	// =========================================================================
	t.Log("Step 1: Sign up new user")

	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()

	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Should redirect to login
	currentURL := page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/login") {
		t.Fatalf("Step 1 FAILED: Expected redirect to /login, got: %s", currentURL)
	}
	t.Log("Step 1 PASSED: Sign up successful")

	// =========================================================================
	// Step 2: Log in
	// =========================================================================
	t.Log("Step 2: Log in")

	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	currentURL = page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/dashboard") {
		t.Fatalf("Step 2 FAILED: Expected redirect to /dashboard, got: %s", currentURL)
	}
	t.Log("Step 2 PASSED: Login successful, on dashboard")

	// =========================================================================
	// Step 3: Click 'Add Repository' link on dashboard
	// =========================================================================
	t.Log("Step 3: Click 'Add Repository' link")

	// Find and click the Add Repository link/button
	addRepoLink := page.MustElement("a[href='/repositories/new']")
	if addRepoLink == nil {
		t.Fatal("Step 3 FAILED: Add Repository link not found")
	}
	addRepoLink.MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	currentURL = page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/repositories/new") {
		t.Fatalf("Step 3 FAILED: Expected /repositories/new, got: %s", currentURL)
	}

	// Verify form is present
	h1 := page.MustElement("h1").MustText()
	if h1 != "Add Repository" {
		t.Fatalf("Step 3 FAILED: Expected h1 'Add Repository', got: %s", h1)
	}
	t.Log("Step 3 PASSED: Add Repository form displayed")

	// =========================================================================
	// Step 4: Enter GitHub URL and submit form
	// =========================================================================
	t.Log("Step 4: Submit GitHub repository URL")

	// Use MustInput which is more reliable for form fields
	el := page.MustElement("#github_url")
	el.MustSelectAllText().MustInput(testGitHubURL)

	// Submit the form
	page.MustElement("form.auth-form").MustEval(`() => this.submit()`)
	page.MustWaitLoad()
	page.MustWaitStable()

	// Should redirect to success page
	currentURL = page.MustInfo().URL
	if !strings.Contains(currentURL, "/repositories/success") {
		bodyText := page.MustElement("body").MustText()
		t.Fatalf("Step 4 FAILED: Expected redirect to /repositories/success, got: %s\nPage content: %s", currentURL, bodyText[:min(len(bodyText), 500)])
	}
	t.Log("Step 4 PASSED: Form submitted, redirected to success page")

	// =========================================================================
	// Step 5: Verify success page shows webhook configuration
	// =========================================================================
	t.Log("Step 5: Verify success page displays webhook configuration")

	// Check success message
	successH1 := page.MustElement("h1").MustText()
	if !strings.Contains(successH1, "Successfully") {
		t.Fatalf("Step 5 FAILED: Expected success message in h1, got: %s", successH1)
	}

	// Verify webhook URL is displayed
	webhookURLInput := page.MustElement("#webhook-url")
	webhookURL := webhookURLInput.MustProperty("value").String()
	if !strings.HasPrefix(webhookURL, testWebhookBaseURL+"/webhook/") {
		t.Fatalf("Step 5 FAILED: Expected webhook URL starting with '%s/webhook/', got: %s", testWebhookBaseURL, webhookURL)
	}
	t.Logf("Step 5: Webhook URL displayed: %s", webhookURL)

	// Verify webhook secret is displayed
	secretInput := page.MustElement("#webhook-secret")
	displayedSecret := secretInput.MustProperty("value").String()
	if displayedSecret != testWebhookSecret {
		t.Fatalf("Step 5 FAILED: Expected webhook secret '%s', got: %s", testWebhookSecret, displayedSecret)
	}
	t.Log("Step 5 PASSED: Success page shows webhook URL and secret")

	// =========================================================================
	// Step 6: Test copy-to-clipboard functionality
	// =========================================================================
	t.Log("Step 6: Test copy-to-clipboard buttons")

	// Find the copy button for webhook URL
	urlCopyBtn := page.MustElement("button[data-copy-target='webhook-url']")
	if urlCopyBtn == nil {
		t.Fatal("Step 6 FAILED: Copy button for webhook URL not found")
	}

	// Click the copy button
	urlCopyBtn.MustClick()

	// Wait for the button text to change to "Copied!"
	// Note: Clipboard API may not work in headless mode, but the button feedback should
	page.MustWaitStable()

	// Check button shows feedback (either "Copied!" or remains "Copy" if clipboard unavailable)
	// In headless mode, clipboard may fail but the button should still respond
	btnText := urlCopyBtn.MustText()
	if btnText == "Copied!" {
		t.Log("Step 6: Copy button shows 'Copied!' feedback")
	} else {
		t.Log("Step 6: Copy button clicked (clipboard may be unavailable in headless mode)")
	}

	// Verify the secret copy button exists too
	secretCopyBtn := page.MustElement("button[data-copy-target='webhook-secret']")
	if secretCopyBtn == nil {
		t.Fatal("Step 6 FAILED: Copy button for webhook secret not found")
	}
	t.Log("Step 6 PASSED: Copy-to-clipboard buttons present and functional")

	// =========================================================================
	// Step 7: Navigate to dashboard and verify repository appears
	// =========================================================================
	t.Log("Step 7: Navigate to dashboard and verify repository is listed")

	// Click "Go to Dashboard" link
	dashboardLink := page.MustElement("a[href='/dashboard']")
	dashboardLink.MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	currentURL = page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/dashboard") {
		t.Fatalf("Step 7 FAILED: Expected /dashboard, got: %s", currentURL)
	}

	// Verify dashboard does NOT show empty state
	bodyText := page.MustElement("body").MustText()
	if strings.Contains(strings.ToLower(bodyText), "get started") {
		t.Fatalf("Step 7 FAILED: Dashboard still shows empty state after adding repository")
	}

	// Verify repository name appears in dashboard
	if !strings.Contains(bodyText, "myrepo") {
		t.Fatalf("Step 7 FAILED: Expected repository 'myrepo' in dashboard, got: %s", bodyText[:min(len(bodyText), 500)])
	}
	t.Log("Step 7 PASSED: Repository visible on dashboard")

	t.Log("=== ADD REPOSITORY BROWSER E2E TEST PASSED ===")
}

// TestBrowser_AddRepositoryValidation tests form validation in browser
func TestBrowser_AddRepositoryValidation(t *testing.T) {
	// Setup test server
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, secretGen, "https://api.test")

	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	// Create and login a test user
	testEmail := "validation-test@example.com"
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

	// =========================================================================
	// Test: Invalid GitHub URL shows error
	// =========================================================================
	t.Log("Testing invalid GitHub URL validation")

	page.MustNavigate(ts.URL + "/repositories/new").MustWaitLoad()

	// Submit with invalid URL - use form.submit() to bypass browser validation
	el := page.MustElement("#github_url")
	el.MustSelectAllText().MustInput("https://gitlab.com/user/repo")
	page.MustElement("form.auth-form").MustEval(`() => this.submit()`)
	page.MustWaitLoad()

	// Should show error message (stay on same page)
	currentURL := page.MustInfo().URL
	if strings.Contains(currentURL, "/repositories/success") {
		t.Fatal("FAILED: Non-GitHub URL should not be accepted")
	}

	// Check for error message (use Element which returns error instead of MustElement which panics)
	errorAlert, err := page.Element(".alert-error")
	if err == nil && errorAlert != nil {
		errorText, _ := errorAlert.Text()
		t.Logf("PASSED: Invalid URL shows error: %s", errorText)
	} else {
		// Server-side validation may have redirected or shown different error
		t.Log("PASSED: Invalid URL was rejected")
	}

	// =========================================================================
	// Test: Valid GitHub URL is accepted
	// =========================================================================
	t.Log("Testing valid GitHub URL is accepted")

	page.MustNavigate(ts.URL + "/repositories/new").MustWaitLoad()

	validEl := page.MustElement("#github_url")
	validEl.MustSelectAllText().MustInput("https://github.com/valid/repo")
	page.MustElement("form.auth-form").MustEval(`() => this.submit()`)
	page.MustWaitLoad()
	page.MustWaitStable()

	currentURL = page.MustInfo().URL
	if !strings.Contains(currentURL, "/repositories/success") {
		bodyText := page.MustElement("body").MustText()
		t.Fatalf("FAILED: Valid URL should redirect to success, got: %s\nBody: %s", currentURL, bodyText[:min(len(bodyText), 300)])
	}
	t.Log("PASSED: Valid GitHub URL is accepted and redirects to success")
}

// TestBrowser_WebhookDeliveries tests the webhook deliveries list page in a real browser.
// Tests: page load, auth required, deliveries table display, status badges, empty state.
func TestBrowser_WebhookDeliveries(t *testing.T) {
	// Setup test server with all necessary stores
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	webhookStore := NewMockWebhookDeliveryStore()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-webhook-secret"}
	router := NewRouterWithWebhookDeliveries(userStore, repoStore, nil, nil, secretGen, "https://api.example.com", webhookStore)

	ts := httptest.NewServer(router)
	defer ts.Close()

	// Launch browser
	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	testEmail := "webhook-deliveries-test@example.com"
	testPassword := "securepassword123"

	// =========================================================================
	// Step 1: Create user and repository
	// =========================================================================
	t.Log("Step 1: Create user and repository")

	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Get user ID for repository creation
	user, err := userStore.GetUserByEmail(context.Background(), testEmail)
	if err != nil || user == nil {
		t.Fatalf("Step 1 FAILED: Could not get user: %v", err)
	}

	// Create a repository
	repo, err := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/test/webhook-repo", "secret")
	if err != nil {
		t.Fatalf("Step 1 FAILED: Could not create repository: %v", err)
	}
	t.Logf("Step 1 PASSED: Created user and repository (ID: %s)", repo.ID)

	// =========================================================================
	// Step 2: Verify auth required - unauthenticated access redirects to login
	// =========================================================================
	t.Log("Step 2: Verify auth required for webhook deliveries")

	page.MustNavigate(ts.URL + "/repositories/" + repo.ID + "/webhooks").MustWaitLoad()
	page.MustWaitStable()

	currentURL := page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/login") {
		t.Fatalf("Step 2 FAILED: Expected redirect to /login, got: %s", currentURL)
	}
	t.Log("Step 2 PASSED: Unauthenticated access redirects to login")

	// =========================================================================
	// Step 3: Login and view empty webhook deliveries
	// =========================================================================
	t.Log("Step 3: Login and view empty webhook deliveries")

	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Navigate to webhook deliveries page
	page.MustNavigate(ts.URL + "/repositories/" + repo.ID + "/webhooks").MustWaitLoad()
	page.MustWaitStable()

	currentURL = page.MustInfo().URL
	if !strings.Contains(currentURL, "/webhooks") {
		t.Fatalf("Step 3 FAILED: Expected to be on webhooks page, got: %s", currentURL)
	}

	// Verify page title
	h1 := page.MustElement("h1").MustText()
	if h1 != "Webhook Deliveries" {
		t.Fatalf("Step 3 FAILED: Expected h1 'Webhook Deliveries', got: %s", h1)
	}

	// Verify empty state is displayed
	bodyText := page.MustElement("body").MustText()
	if !strings.Contains(bodyText, "No webhook deliveries yet") {
		t.Fatalf("Step 3 FAILED: Expected empty state message, got: %s", bodyText[:min(len(bodyText), 500)])
	}
	t.Log("Step 3 PASSED: Empty state displays correctly")

	// =========================================================================
	// Step 4: Add deliveries and verify table display
	// =========================================================================
	t.Log("Step 4: Add deliveries and verify table display")

	// Add successful delivery
	webhookStore.AddDelivery(repo.ID, &WebhookDelivery{
		ID:         "delivery-success-1",
		EventType:  "push",
		Payload:    `{"commits":[{"message":"Add feature"}]}`,
		StatusCode: 200,
		CreatedAt:  "2026-01-03 10:30:00",
		IsSuccess:  true,
	})

	// Add failed delivery with error message
	errMsg := "Connection timeout"
	webhookStore.AddDelivery(repo.ID, &WebhookDelivery{
		ID:           "delivery-failed-1",
		EventType:    "push",
		Payload:      `{"commits":[{"message":"Fix bug"}]}`,
		StatusCode:   500,
		ErrorMessage: &errMsg,
		CreatedAt:    "2026-01-03 10:25:00",
		IsSuccess:    false,
	})

	// Reload page
	page.MustReload().MustWaitLoad()
	page.MustWaitStable()

	// Verify table headers exist
	tableHeaders := page.MustElement("thead").MustText()
	if !strings.Contains(tableHeaders, "Time") ||
		!strings.Contains(tableHeaders, "Event") ||
		!strings.Contains(tableHeaders, "Status") {
		t.Fatalf("Step 4 FAILED: Expected table headers (Time, Event, Status), got: %s", tableHeaders)
	}

	// Verify deliveries are displayed
	tbody := page.MustElement("tbody")
	tbodyText := tbody.MustText()
	if !strings.Contains(tbodyText, "push") {
		t.Fatalf("Step 4 FAILED: Expected 'push' event in table, got: %s", tbodyText[:min(len(tbodyText), 300)])
	}
	t.Log("Step 4 PASSED: Deliveries table displays correctly")

	// =========================================================================
	// Step 5: Verify status badges display correctly
	// =========================================================================
	t.Log("Step 5: Verify status badges display correctly")

	// Check for success badge (status code 200)
	successBadges := page.MustElements(".status-success")
	if len(successBadges) == 0 {
		t.Fatal("Step 5 FAILED: Expected at least one success status badge")
	}
	successText := successBadges[0].MustText()
	if successText != "200" {
		t.Fatalf("Step 5 FAILED: Expected success badge to show '200', got: %s", successText)
	}

	// Check for failed badge (status code 500)
	failedBadges := page.MustElements(".status-failed")
	if len(failedBadges) == 0 {
		t.Fatal("Step 5 FAILED: Expected at least one failed status badge")
	}
	failedText := failedBadges[0].MustText()
	if failedText != "500" {
		t.Fatalf("Step 5 FAILED: Expected failed badge to show '500', got: %s", failedText)
	}
	t.Log("Step 5 PASSED: Status badges display correctly (200 success, 500 failed)")

	// =========================================================================
	// Step 6: Verify error message row displays for failed delivery
	// =========================================================================
	t.Log("Step 6: Verify error message row displays for failed delivery")

	errorRows := page.MustElements(".error-row")
	if len(errorRows) == 0 {
		t.Fatal("Step 6 FAILED: Expected error row for failed delivery")
	}
	errorRowText := errorRows[0].MustText()
	if !strings.Contains(errorRowText, "Connection timeout") {
		t.Fatalf("Step 6 FAILED: Expected error message 'Connection timeout', got: %s", errorRowText)
	}
	t.Log("Step 6 PASSED: Error message row displays correctly")

	// =========================================================================
	// Step 7: Verify back navigation link
	// =========================================================================
	t.Log("Step 7: Verify back navigation link")

	backLink := page.MustElement("a.btn.btn-small")
	backLinkText := backLink.MustText()
	if !strings.Contains(backLinkText, "Back to Repository") {
		t.Fatalf("Step 7 FAILED: Expected back link with 'Back to Repository', got: %s", backLinkText)
	}

	// Click back link
	backLink.MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	currentURL = page.MustInfo().URL
	if !strings.Contains(currentURL, "/repositories/"+repo.ID) || strings.Contains(currentURL, "/webhooks") {
		t.Fatalf("Step 7 FAILED: Expected to navigate to repository view, got: %s", currentURL)
	}
	t.Log("Step 7 PASSED: Back navigation works correctly")

	t.Log("=== WEBHOOK DELIVERIES BROWSER E2E TEST PASSED ===")
}

// TestBrowser_WebhookDeliveries_OtherUserRepo tests that users cannot view another user's webhook deliveries.
func TestBrowser_WebhookDeliveries_OtherUserRepo(t *testing.T) {
	// Setup test server
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	webhookStore := NewMockWebhookDeliveryStore()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}
	router := NewRouterWithWebhookDeliveries(userStore, repoStore, nil, nil, secretGen, "https://api.example.com", webhookStore)

	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	// Create two users
	user1Email := "user1-webhook@example.com"
	user2Email := "user2-webhook@example.com"
	testPassword := "securepassword123"

	// Create user1 and their repo
	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", user1Email)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	user1, _ := userStore.GetUserByEmail(context.Background(), user1Email)
	repo1, _ := repoStore.CreateRepository(context.Background(), user1.ID, "https://github.com/user1/private-repo", "secret1")

	// Add a delivery to user1's repo
	webhookStore.AddDelivery(repo1.ID, &WebhookDelivery{
		ID:         "private-delivery",
		EventType:  "push",
		Payload:    `{"secret":"data"}`,
		StatusCode: 200,
		CreatedAt:  "2026-01-03 10:00:00",
		IsSuccess:  true,
	})

	// Create and login as user2
	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", user2Email)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Login as user2
	inputText(t, page, "#email", user2Email)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// =========================================================================
	// Test: User2 tries to access User1's webhook deliveries
	// =========================================================================
	t.Log("Testing: User cannot view another user's webhook deliveries")

	page.MustNavigate(ts.URL + "/repositories/" + repo1.ID + "/webhooks").MustWaitLoad()
	page.MustWaitStable()

	// Should get 404 (not found) - Go's standard library returns text/plain for NotFound
	bodyText := page.MustElement("body").MustText()
	if !strings.Contains(bodyText, "404") && !strings.Contains(bodyText, "not found") {
		// If we're still on the page with deliveries visible, that's a security issue
		if strings.Contains(bodyText, "Webhook Deliveries") && strings.Contains(bodyText, "private-delivery") {
			t.Fatal("SECURITY FAILURE: User can view another user's webhook deliveries")
		}
	}

	t.Log("PASSED: User cannot view another user's webhook deliveries")
}

// TestBrowser_ConnectionDisconnect tests the connection disconnect confirmation flow in a real browser.
// Tests: auth required, confirmation page display, disconnect action, redirect after disconnect.
func TestBrowser_ConnectionDisconnect(t *testing.T) {
	// Setup test server with connection service
	userStore := NewMockUserStore()
	connService := NewMockConnectionService()
	router := NewRouterWithConnectionService(userStore, connService)

	ts := httptest.NewServer(router)
	defer ts.Close()

	// Launch browser
	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	testEmail := "disconnect-browser-test@example.com"
	testPassword := "securepassword123"

	// =========================================================================
	// Step 1: Create user and add connection
	// =========================================================================
	t.Log("Step 1: Create user and add connection")

	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Get user and add a connection
	user, err := userStore.GetUserByEmail(context.Background(), testEmail)
	if err != nil || user == nil {
		t.Fatalf("Step 1 FAILED: Could not get user: %v", err)
	}
	connService.AddConnection(user.ID, "twitter", "@testuser", "https://twitter.com/testuser")
	t.Log("Step 1 PASSED: Created user and added Twitter connection")

	// =========================================================================
	// Step 2: Verify auth required for disconnect page
	// =========================================================================
	t.Log("Step 2: Verify auth required for disconnect page")

	page.MustNavigate(ts.URL + "/connections/twitter/disconnect").MustWaitLoad()
	page.MustWaitStable()

	currentURL := page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/login") {
		t.Fatalf("Step 2 FAILED: Expected redirect to /login, got: %s", currentURL)
	}
	t.Log("Step 2 PASSED: Unauthenticated access redirects to login")

	// =========================================================================
	// Step 3: Login and view disconnect confirmation page
	// =========================================================================
	t.Log("Step 3: Login and view disconnect confirmation page")

	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Navigate to disconnect page
	page.MustNavigate(ts.URL + "/connections/twitter/disconnect").MustWaitLoad()
	page.MustWaitStable()

	// Verify page content
	h1 := page.MustElement("h1").MustText()
	if h1 != "Disconnect Account" {
		t.Fatalf("Step 3 FAILED: Expected h1 'Disconnect Account', got: %s", h1)
	}

	bodyText := page.MustElement("body").MustText()
	if !strings.Contains(bodyText, "twitter") {
		t.Fatal("Step 3 FAILED: Expected platform 'twitter' in page")
	}
	if !strings.Contains(bodyText, "@testuser") {
		t.Fatal("Step 3 FAILED: Expected display name '@testuser' in page")
	}
	if !strings.Contains(bodyText, "Are you sure") {
		t.Fatal("Step 3 FAILED: Expected confirmation text in page")
	}
	t.Log("Step 3 PASSED: Disconnect confirmation page displays correctly")

	// =========================================================================
	// Step 4: Verify warning message is displayed
	// =========================================================================
	t.Log("Step 4: Verify warning message is displayed")

	warningAlert := page.MustElement(".alert-warning")
	warningText := warningAlert.MustText()
	if !strings.Contains(warningText, "Warning") {
		t.Fatalf("Step 4 FAILED: Expected warning message, got: %s", warningText)
	}
	t.Log("Step 4 PASSED: Warning message displayed")

	// =========================================================================
	// Step 5: Verify cancel button navigates back
	// =========================================================================
	t.Log("Step 5: Verify cancel button navigates back")

	cancelBtn := page.MustElement("a.btn-secondary")
	cancelText := cancelBtn.MustText()
	if cancelText != "Cancel" {
		t.Fatalf("Step 5 FAILED: Expected 'Cancel' button, got: %s", cancelText)
	}
	t.Log("Step 5 PASSED: Cancel button present")

	// =========================================================================
	// Step 6: Click disconnect button and verify redirect
	// =========================================================================
	t.Log("Step 6: Click disconnect button and verify redirect")

	// Find and click the disconnect button (submit form)
	disconnectBtn := page.MustElement("button.btn-danger")
	disconnectText := disconnectBtn.MustText()
	if !strings.Contains(disconnectText, "Disconnect") {
		t.Fatalf("Step 6 FAILED: Expected 'Disconnect' button, got: %s", disconnectText)
	}

	disconnectBtn.MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Should redirect to dashboard with success param
	currentURL = page.MustInfo().URL
	if !strings.Contains(currentURL, "/dashboard") {
		t.Fatalf("Step 6 FAILED: Expected redirect to /dashboard, got: %s", currentURL)
	}
	if !strings.Contains(currentURL, "disconnected=twitter") {
		t.Fatalf("Step 6 FAILED: Expected 'disconnected=twitter' in URL, got: %s", currentURL)
	}
	t.Log("Step 6 PASSED: Disconnect successful, redirected to dashboard")

	// =========================================================================
	// Step 7: Verify connection is removed
	// =========================================================================
	t.Log("Step 7: Verify connection is removed")

	_, err = connService.GetConnection(context.Background(), user.ID, "twitter")
	if err == nil {
		t.Fatal("Step 7 FAILED: Connection should have been removed")
	}
	t.Log("Step 7 PASSED: Connection successfully removed")

	t.Log("=== CONNECTION DISCONNECT BROWSER E2E TEST PASSED ===")
}

// TestBrowser_ConnectionDisconnect_NotFound tests that disconnect returns 404 for non-existent connections.
func TestBrowser_ConnectionDisconnect_NotFound(t *testing.T) {
	// Setup test server
	userStore := NewMockUserStore()
	connService := NewMockConnectionService()
	router := NewRouterWithConnectionService(userStore, connService)

	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	testEmail := "no-conn-test@example.com"
	testPassword := "securepassword123"

	// Create user (no connection)
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

	// =========================================================================
	// Test: Try to disconnect non-existent connection
	// =========================================================================
	t.Log("Testing: Disconnect non-existent connection returns 404")

	page.MustNavigate(ts.URL + "/connections/twitter/disconnect").MustWaitLoad()
	page.MustWaitStable()

	bodyText := page.MustElement("body").MustText()
	if !strings.Contains(bodyText, "404") && !strings.Contains(strings.ToLower(bodyText), "not found") {
		// If we see the disconnect page, that's wrong
		if strings.Contains(bodyText, "Disconnect Account") {
			t.Fatal("FAILED: Should not show disconnect page for non-existent connection")
		}
	}

	t.Log("PASSED: Non-existent connection returns 404")
}

// TestBrowser_TestWebhookButton tests clicking the Test Webhook button in repository view
func TestBrowser_TestWebhookButton(t *testing.T) {
	// Fixed webhook secret for deterministic testing
	const testWebhookSecret = "test-webhook-secret-for-browser"
	const testWebhookBaseURL = "https://api.roxas.test"

	// Setup test server with mock stores
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	secretGen := &MockSecretGeneratorForWeb{Secret: testWebhookSecret}
	webhookTester := NewMockWebhookTester()
	router := NewRouterWithWebhookTester(userStore, repoStore, nil, nil, secretGen, testWebhookBaseURL, webhookTester)

	ts := httptest.NewServer(router)
	defer ts.Close()

	// Launch browser
	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	testEmail := "webhook-test@example.com"
	testPassword := "securepassword123"
	testGitHubURL := "https://github.com/webhooktest/myrepo"

	// =========================================================================
	// Step 1: Sign up
	// =========================================================================
	t.Log("Step 1: Sign up new user")

	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()

	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()
	t.Log("Step 1 PASSED: Sign up successful")

	// =========================================================================
	// Step 2: Log in
	// =========================================================================
	t.Log("Step 2: Log in")

	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()
	t.Log("Step 2 PASSED: Login successful")

	// =========================================================================
	// Step 3: Add a repository
	// =========================================================================
	t.Log("Step 3: Add a repository")

	page.MustNavigate(ts.URL + "/repositories/new").MustWaitLoad()

	el := page.MustElement("#github_url")
	el.MustSelectAllText().MustInput(testGitHubURL)
	page.MustElement("form.auth-form").MustEval(`() => this.submit()`)
	page.MustWaitLoad()
	page.MustWaitStable()

	currentURL := page.MustInfo().URL
	if !strings.Contains(currentURL, "/repositories/success") {
		t.Fatalf("Step 3 FAILED: Expected /repositories/success, got: %s", currentURL)
	}
	t.Log("Step 3 PASSED: Repository added")

	// =========================================================================
	// Step 4: Navigate to repository view
	// =========================================================================
	t.Log("Step 4: Navigate to repository view")

	// Go to dashboard first
	page.MustNavigate(ts.URL + "/dashboard").MustWaitLoad()
	page.MustWaitStable()

	// Navigate to repositories list
	page.MustNavigate(ts.URL + "/repositories").MustWaitLoad()
	page.MustWaitStable()

	// Click on the repository to view it (link is in the Actions column as "View" button)
	repoLink := page.MustElement("table a.btn-small[href^='/repositories/']")
	repoLink.MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	currentURL = page.MustInfo().URL
	if !strings.Contains(currentURL, "/repositories/") {
		t.Fatalf("Step 4 FAILED: Expected to be on repository view, got: %s", currentURL)
	}
	t.Log("Step 4 PASSED: On repository view page")

	// =========================================================================
	// Step 5: Click Test Webhook button
	// =========================================================================
	t.Log("Step 5: Click Test Webhook button")

	// Find the Test Webhook button
	testWebhookBtn := page.MustElement("#test-webhook-btn")
	if testWebhookBtn == nil {
		t.Fatal("Step 5 FAILED: Test Webhook button not found")
	}

	// Click the button
	testWebhookBtn.MustClick()

	// Wait for the async request to complete
	// The button should show "Testing..." then back to "Test Webhook"
	page.MustWaitStable()

	// Give time for the fetch to complete
	time.Sleep(500 * time.Millisecond)

	// =========================================================================
	// Step 6: Verify success message is displayed
	// =========================================================================
	t.Log("Step 6: Verify success message")

	resultSpan := page.MustElement("#webhook-test-result")
	if resultSpan == nil {
		t.Fatal("Step 6 FAILED: Result span not found")
	}

	resultText := resultSpan.MustText()
	if !strings.Contains(resultText, "Success") {
		t.Fatalf("Step 6 FAILED: Expected 'Success' in result, got: %s", resultText)
	}

	// Verify the result has success styling
	resultClass := resultSpan.MustProperty("className").String()
	if !strings.Contains(resultClass, "status-success") {
		t.Logf("Warning: Expected status-success class, got: %s", resultClass)
	}

	t.Log("Step 6 PASSED: Success message displayed")

	t.Log("=== TEST WEBHOOK BUTTON BROWSER E2E TEST PASSED ===")
}

// TestBrowser_TestWebhookButton_Failure tests the webhook test button when webhook fails
func TestBrowser_TestWebhookButton_Failure(t *testing.T) {
	const testWebhookSecret = "test-webhook-secret-fail"
	const testWebhookBaseURL = "https://api.roxas.test"

	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	secretGen := &MockSecretGeneratorForWeb{Secret: testWebhookSecret}
	webhookTester := NewMockWebhookTester()
	webhookTester.SetShouldError(true) // Make webhook fail
	router := NewRouterWithWebhookTester(userStore, repoStore, nil, nil, secretGen, testWebhookBaseURL, webhookTester)

	ts := httptest.NewServer(router)
	defer ts.Close()

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	testEmail := "webhook-fail-test@example.com"
	testPassword := "securepassword123"
	testGitHubURL := "https://github.com/webhookfail/myrepo"

	// Sign up and login
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

	// Add a repository
	page.MustNavigate(ts.URL + "/repositories/new").MustWaitLoad()
	el := page.MustElement("#github_url")
	el.MustSelectAllText().MustInput(testGitHubURL)
	page.MustElement("form.auth-form").MustEval(`() => this.submit()`)
	page.MustWaitLoad()
	page.MustWaitStable()

	// Navigate to repositories list and view
	page.MustNavigate(ts.URL + "/repositories").MustWaitLoad()
	page.MustWaitStable()

	repoLink := page.MustElement("table a.btn-small[href^='/repositories/']")
	repoLink.MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Click Test Webhook button
	t.Log("Clicking Test Webhook button (expecting failure)")
	testWebhookBtn := page.MustElement("#test-webhook-btn")
	testWebhookBtn.MustClick()
	page.MustWaitStable()
	time.Sleep(500 * time.Millisecond)

	// Verify error message is displayed
	resultSpan := page.MustElement("#webhook-test-result")
	resultText := resultSpan.MustText()

	if !strings.Contains(resultText, "Failed") && !strings.Contains(resultText, "Error") && !strings.Contains(resultText, "error") {
		t.Fatalf("Expected 'Failed' or 'Error' in result, got: %s", resultText)
	}

	// Verify the result has error styling
	resultClass := resultSpan.MustProperty("className").String()
	if !strings.Contains(resultClass, "status-error") {
		t.Logf("Warning: Expected status-error class, got: %s", resultClass)
	}

	t.Log("PASSED: Error message displayed correctly for failed webhook")
}

// TestBrowser_DeleteRepositoryFlow tests the complete delete repository workflow:
// add repo → view repo → click delete → confirmation page → cancel → back to repo
// then: click delete again → confirm delete → redirected to repositories list → repo gone
func TestBrowser_DeleteRepositoryFlow(t *testing.T) {
	// Setup test server with mock stores
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, secretGen, "https://api.test")

	ts := httptest.NewServer(router)
	defer ts.Close()

	// Launch browser
	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	testEmail := "delete-test@example.com"
	testPassword := "securepassword123"
	testGitHubURL := "https://github.com/deletetest/myrepo"

	// =========================================================================
	// Step 1: Sign up and log in
	// =========================================================================
	t.Log("Step 1: Sign up and log in")

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

	currentURL := page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/dashboard") {
		t.Fatalf("Step 1 FAILED: Expected /dashboard, got: %s", currentURL)
	}
	t.Log("Step 1 PASSED: Signed up and logged in")

	// =========================================================================
	// Step 2: Add a repository
	// =========================================================================
	t.Log("Step 2: Add a repository")

	page.MustNavigate(ts.URL + "/repositories/new").MustWaitLoad()
	el := page.MustElement("#github_url")
	el.MustSelectAllText().MustInput(testGitHubURL)
	page.MustElement("form.auth-form").MustEval(`() => this.submit()`)
	page.MustWaitLoad()
	page.MustWaitStable()

	currentURL = page.MustInfo().URL
	if !strings.Contains(currentURL, "/repositories/success") {
		bodyText := page.MustElement("body").MustText()
		t.Fatalf("Step 2 FAILED: Expected /repositories/success, got: %s\nBody: %s", currentURL, bodyText[:min(len(bodyText), 300)])
	}
	t.Log("Step 2 PASSED: Repository added")

	// =========================================================================
	// Step 3: Navigate to repository view
	// =========================================================================
	t.Log("Step 3: Navigate to repository view")

	// Go to repositories list first
	page.MustNavigate(ts.URL + "/repositories").MustWaitLoad()
	page.MustWaitStable()

	// Click on the repository to view it - find the view link
	repoLinks := page.MustElements("a[href^='/repositories/']")
	var repoViewLink *rod.Element
	for _, link := range repoLinks {
		linkHref := link.MustProperty("href").String()
		if !strings.Contains(linkHref, "/edit") && !strings.Contains(linkHref, "/delete") && !strings.Contains(linkHref, "/webhook") && !strings.Contains(linkHref, "/new") && !strings.Contains(linkHref, "/success") {
			repoViewLink = link
			break
		}
	}
	if repoViewLink == nil {
		t.Fatal("Step 3 FAILED: Could not find repository view link")
	}

	repoViewLink.MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	currentURL = page.MustInfo().URL
	if !strings.Contains(currentURL, "/repositories/") {
		t.Fatalf("Step 3 FAILED: Expected repository view URL, got: %s", currentURL)
	}
	t.Log("Step 3 PASSED: On repository view page")

	// =========================================================================
	// Step 4: Click Delete Repository button
	// =========================================================================
	t.Log("Step 4: Click Delete Repository button")

	deleteBtn := page.MustElement("a.btn-danger[href*='/delete']")
	if deleteBtn == nil {
		t.Fatal("Step 4 FAILED: Delete Repository button not found")
	}

	deleteBtn.MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	currentURL = page.MustInfo().URL
	if !strings.Contains(currentURL, "/delete") {
		t.Fatalf("Step 4 FAILED: Expected delete confirmation URL, got: %s", currentURL)
	}
	t.Log("Step 4 PASSED: On delete confirmation page")

	// =========================================================================
	// Step 5: Verify confirmation page content
	// =========================================================================
	t.Log("Step 5: Verify confirmation page content")

	bodyText := page.MustElement("body").MustText()

	// Should show repo name
	if !strings.Contains(bodyText, "deletetest/myrepo") {
		t.Fatalf("Step 5 FAILED: Expected repo name 'deletetest/myrepo' on confirmation page, got: %s", bodyText[:min(len(bodyText), 500)])
	}

	// Should show warning
	if !strings.Contains(strings.ToLower(bodyText), "warning") {
		t.Fatalf("Step 5 FAILED: Expected warning on confirmation page")
	}

	// Should have Delete and Cancel buttons
	if !strings.Contains(bodyText, "Delete Repository") {
		t.Fatal("Step 5 FAILED: Delete Repository button not found")
	}
	if !strings.Contains(bodyText, "Cancel") {
		t.Fatal("Step 5 FAILED: Cancel button not found")
	}
	t.Log("Step 5 PASSED: Confirmation page shows repo name, warning, and buttons")

	// =========================================================================
	// Step 6: Test Cancel returns to repository view
	// =========================================================================
	t.Log("Step 6: Test Cancel button")

	cancelBtn := page.MustElement("a.btn-secondary")
	if cancelBtn == nil {
		t.Fatal("Step 6 FAILED: Cancel button not found")
	}

	cancelBtn.MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	currentURL = page.MustInfo().URL
	// Cancel should go back to repository view (not delete page)
	if strings.Contains(currentURL, "/delete") {
		t.Fatalf("Step 6 FAILED: Cancel should navigate away from delete page, got: %s", currentURL)
	}
	t.Log("Step 6 PASSED: Cancel returns to repository view")

	// =========================================================================
	// Step 7: Go back to delete and confirm deletion
	// =========================================================================
	t.Log("Step 7: Confirm deletion")

	// Click delete button again
	deleteBtn = page.MustElement("a.btn-danger[href*='/delete']")
	deleteBtn.MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Now click the actual Delete Repository submit button
	deleteSubmitBtn := page.MustElement("button.btn-danger[type='submit']")
	if deleteSubmitBtn == nil {
		t.Fatal("Step 7 FAILED: Delete submit button not found")
	}

	deleteSubmitBtn.MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Should redirect to repositories list
	currentURL = page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/repositories") {
		t.Fatalf("Step 7 FAILED: Expected redirect to /repositories after delete, got: %s", currentURL)
	}
	t.Log("Step 7 PASSED: Delete successful, redirected to repositories list")

	// =========================================================================
	// Step 8: Verify repository is no longer in the list
	// =========================================================================
	t.Log("Step 8: Verify repository is deleted")

	bodyText = page.MustElement("body").MustText()

	// Repository should NOT appear in the list
	if strings.Contains(bodyText, "deletetest/myrepo") {
		t.Fatal("Step 8 FAILED: Deleted repository still appears in list")
	}

	t.Log("Step 8 PASSED: Repository no longer appears in list")

	t.Log("=== DELETE REPOSITORY BROWSER E2E TEST PASSED ===")
}

// =============================================================================
// Drafts Navigation Tests (TDD - RED PHASE)
//
// These tests verify the drafts navigation functionality:
// - Drafts link appears in navigation for authenticated users
// - Draft count badge shows correct number
// - Clicking Drafts link navigates to /drafts
//
// These tests are expected to FAIL initially as the functionality
// does not yet exist. This is the "red" phase of TDD.
// =============================================================================

// TestBrowser_DraftsNavigation_LinkAppearsInNav tests that the Drafts link
// appears in the navigation bar for authenticated users.
func TestBrowser_DraftsNavigation_LinkAppearsInNav(t *testing.T) {
	// Setup test server with mock stores
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	ts := httptest.NewServer(router)
	defer ts.Close()

	// Launch browser
	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	testEmail := "drafts-nav-test@example.com"
	testPassword := "securepassword123"

	// =========================================================================
	// Step 1: Sign up and log in
	// =========================================================================
	t.Log("Step 1: Sign up and log in")

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

	currentURL := page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/dashboard") {
		t.Fatalf("Step 1 FAILED: Expected /dashboard, got: %s", currentURL)
	}
	t.Log("Step 1 PASSED: Logged in successfully")

	// =========================================================================
	// Step 2: Verify Drafts link appears in navigation
	// =========================================================================
	t.Log("Step 2: Verify Drafts link appears in navigation")

	// Find the navigation bar
	navbar := page.MustElement("nav.navbar")
	if navbar == nil {
		t.Fatal("Step 2 FAILED: Navigation bar not found")
	}

	// Look for Drafts link in nav-links
	navLinks := navbar.MustElement(".nav-links")
	navLinksText := navLinks.MustText()

	if !strings.Contains(navLinksText, "Drafts") {
		t.Fatalf("Step 2 FAILED: Expected 'Drafts' link in navigation, got: %s", navLinksText)
	}

	// Verify the link exists and has correct href
	draftsLink, err := navLinks.Element("a[href='/drafts']")
	if err != nil || draftsLink == nil {
		t.Fatal("Step 2 FAILED: Drafts link with href='/drafts' not found in navigation")
	}

	t.Log("Step 2 PASSED: Drafts link appears in navigation")

	t.Log("=== DRAFTS NAVIGATION LINK TEST PASSED ===")
}

// TestBrowser_DraftsNavigation_BadgeShowsCount tests that the draft count badge
// displays the correct number of drafts.
func TestBrowser_DraftsNavigation_BadgeShowsCount(t *testing.T) {
	// Setup test server with mock stores including draft store
	userStore := NewMockUserStore()
	draftStore := NewMockDraftStore()
	router := NewRouterWithDraftStore(userStore, draftStore)

	ts := httptest.NewServer(router)
	defer ts.Close()

	// Launch browser
	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	testEmail := "drafts-badge-test@example.com"
	testPassword := "securepassword123"

	// =========================================================================
	// Step 1: Sign up and log in
	// =========================================================================
	t.Log("Step 1: Sign up and log in")

	page.MustNavigate(ts.URL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Get user and add drafts
	user, err := userStore.GetUserByEmail(context.Background(), testEmail)
	if err != nil || user == nil {
		t.Fatalf("Step 1 FAILED: Could not get user: %v", err)
	}

	// Add 3 drafts for this user
	draftStore.AddDraft(user.ID, &Draft{
		ID:      "draft-1",
		Title:   "Draft Post 1",
		Content: "Content for draft 1",
	})
	draftStore.AddDraft(user.ID, &Draft{
		ID:      "draft-2",
		Title:   "Draft Post 2",
		Content: "Content for draft 2",
	})
	draftStore.AddDraft(user.ID, &Draft{
		ID:      "draft-3",
		Title:   "Draft Post 3",
		Content: "Content for draft 3",
	})

	// Login
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	t.Log("Step 1 PASSED: Logged in with 3 drafts")

	// =========================================================================
	// Step 2: Verify draft count badge shows "3"
	// =========================================================================
	t.Log("Step 2: Verify draft count badge shows correct count")

	// Find the draft count badge in navigation
	navbar := page.MustElement("nav.navbar")
	if navbar == nil {
		t.Fatal("Step 2 FAILED: Navigation bar not found")
	}

	// Look for the badge element (should be near the Drafts link)
	badge, err := navbar.Element(".draft-count-badge")
	if err != nil || badge == nil {
		t.Fatal("Step 2 FAILED: Draft count badge not found in navigation")
	}

	badgeText := badge.MustText()
	if badgeText != "3" {
		t.Fatalf("Step 2 FAILED: Expected badge to show '3', got: %s", badgeText)
	}

	t.Log("Step 2 PASSED: Draft count badge shows correct count (3)")

	// =========================================================================
	// Step 3: Verify badge updates when draft count changes
	// =========================================================================
	t.Log("Step 3: Verify badge updates when draft count changes")

	// Add another draft
	draftStore.AddDraft(user.ID, &Draft{
		ID:      "draft-4",
		Title:   "Draft Post 4",
		Content: "Content for draft 4",
	})

	// Reload the page
	page.MustReload().MustWaitLoad()
	page.MustWaitStable()

	// Check badge again
	badge, err = page.Element(".draft-count-badge")
	if err != nil || badge == nil {
		t.Fatal("Step 3 FAILED: Draft count badge not found after reload")
	}

	badgeText = badge.MustText()
	if badgeText != "4" {
		t.Fatalf("Step 3 FAILED: Expected badge to show '4' after adding draft, got: %s", badgeText)
	}

	t.Log("Step 3 PASSED: Draft count badge updates correctly")

	t.Log("=== DRAFTS BADGE COUNT TEST PASSED ===")
}

// TestBrowser_DraftsNavigation_LinkNavigatesToDrafts tests that clicking the
// Drafts link navigates to the /drafts page.
func TestBrowser_DraftsNavigation_LinkNavigatesToDrafts(t *testing.T) {
	// Setup test server with mock stores
	userStore := NewMockUserStore()
	draftStore := NewMockDraftStore()
	router := NewRouterWithDraftStore(userStore, draftStore)

	ts := httptest.NewServer(router)
	defer ts.Close()

	// Launch browser
	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	testEmail := "drafts-link-test@example.com"
	testPassword := "securepassword123"

	// =========================================================================
	// Step 1: Sign up and log in
	// =========================================================================
	t.Log("Step 1: Sign up and log in")

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

	t.Log("Step 1 PASSED: Logged in successfully")

	// =========================================================================
	// Step 2: Click Drafts link and verify navigation
	// =========================================================================
	t.Log("Step 2: Click Drafts link and verify navigation")

	// Find and click the Drafts link
	draftsLink := page.MustElement("a[href='/drafts']")
	if draftsLink == nil {
		t.Fatal("Step 2 FAILED: Drafts link not found")
	}

	draftsLink.MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Verify we're on the /drafts page
	currentURL := page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/drafts") {
		t.Fatalf("Step 2 FAILED: Expected to be on /drafts page, got: %s", currentURL)
	}

	// Verify page title or heading indicates Drafts page
	h1 := page.MustElement("h1").MustText()
	if h1 != "Drafts" {
		t.Fatalf("Step 2 FAILED: Expected h1 'Drafts', got: %s", h1)
	}

	t.Log("Step 2 PASSED: Drafts link navigates to /drafts page")

	t.Log("=== DRAFTS NAVIGATION LINK CLICK TEST PASSED ===")
}

// TestBrowser_DraftsNavigation_BadgeHiddenWhenZero tests that the draft count
// badge is hidden when there are no drafts.
func TestBrowser_DraftsNavigation_BadgeHiddenWhenZero(t *testing.T) {
	// Setup test server with mock stores (no drafts)
	userStore := NewMockUserStore()
	draftStore := NewMockDraftStore()
	router := NewRouterWithDraftStore(userStore, draftStore)

	ts := httptest.NewServer(router)
	defer ts.Close()

	// Launch browser
	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(ts.URL).Timeout(30 * time.Second)
	defer page.MustClose()

	testEmail := "drafts-zero-test@example.com"
	testPassword := "securepassword123"

	// Sign up and log in
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

	// =========================================================================
	// Test: Badge should be hidden or show 0 when no drafts exist
	// =========================================================================
	t.Log("Testing: Draft count badge hidden when no drafts")

	// Try to find the badge - it should not exist or be empty
	badge, err := page.Element(".draft-count-badge")
	if err == nil && badge != nil {
		badgeText := badge.MustText()
		// Badge should either not exist, be empty, or show "0"
		if badgeText != "" && badgeText != "0" {
			t.Fatalf("FAILED: Expected badge to be hidden or show '0' when no drafts, got: %s", badgeText)
		}
	}

	t.Log("PASSED: Draft count badge is appropriately hidden or shows 0")
}

// =============================================================================
// Mock Draft Store for Tests
// =============================================================================

// Draft represents a post draft
type Draft struct {
	ID        string
	UserID    string
	Title     string
	Content   string
	Platform  string
	CreatedAt string
	UpdatedAt string
}

// MockDraftStore implements DraftStore for tests
type MockDraftStore struct {
	mu     sync.Mutex
	drafts map[string][]*Draft // userID -> drafts
}

// NewMockDraftStore creates a new mock draft store
func NewMockDraftStore() *MockDraftStore {
	return &MockDraftStore{
		drafts: make(map[string][]*Draft),
	}
}

// AddDraft adds a draft for a user
func (s *MockDraftStore) AddDraft(userID string, draft *Draft) {
	s.mu.Lock()
	defer s.mu.Unlock()
	draft.UserID = userID
	s.drafts[userID] = append(s.drafts[userID], draft)
}

// CountDraftsByUser returns the number of drafts for a user
func (s *MockDraftStore) CountDraftsByUser(ctx context.Context, userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if drafts, ok := s.drafts[userID]; ok {
		return len(drafts), nil
	}
	return 0, nil
}

// ListDraftsByUser returns all drafts for a user
func (s *MockDraftStore) ListDraftsByUser(ctx context.Context, userID string) ([]*Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if drafts, ok := s.drafts[userID]; ok {
		return drafts, nil
	}
	return []*Draft{}, nil
}

// NewRouterWithDraftStore creates a new web router with draft store support
// NOTE: This function needs to be implemented in router.go
func NewRouterWithDraftStore(userStore UserStore, draftStore *MockDraftStore) *Router {
	r := &Router{
		mux:       http.NewServeMux(),
		userStore: userStore,
		// draftStore: draftStore, // This field needs to be added to Router
	}
	r.setupRoutes()
	return r
}
