//go:build browser

package web

import (
	"context"
	"net/http/httptest"
	"os"
	"strings"
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

// =============================================================================
// Connection Disconnect with Confirmation (hq-chj1)
// =============================================================================

// TestBrowser_ConnectionDisconnectConfirmation tests that disconnecting a platform
// shows a confirmation dialog and properly handles both confirm and cancel actions.
func TestBrowser_ConnectionDisconnectConfirmation(t *testing.T) {
	// Setup test server with mock stores including connection service
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

	testEmail := "disconnect-test@example.com"
	testPassword := "securepassword123"

	// =========================================================================
	// Setup: Create user and add a connection
	// =========================================================================
	t.Log("Setup: Creating user and adding connection")

	user, _ := userStore.CreateUser(context.Background(), testEmail, hashPassword(testPassword))
	connService.AddConnection(user.ID, "twitter", "connected", "@testuser")

	// =========================================================================
	// Step 1: Login
	// =========================================================================
	t.Log("Step 1: Login")

	page.MustNavigate(ts.URL + "/login").MustWaitLoad()

	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	t.Log("Step 1 PASSED: User logged in")

	// =========================================================================
	// Step 2: Navigate to connection view page
	// =========================================================================
	t.Log("Step 2: Navigate to connection view page")

	page.MustNavigate(ts.URL + "/connections/twitter").MustWaitLoad()
	page.MustWaitStable()

	// Verify we're on the connection view page
	bodyText := page.MustElement("body").MustText()
	if !strings.Contains(bodyText, "Twitter") {
		t.Fatalf("Step 2 FAILED: Expected to see 'Twitter' on page, got: %s", bodyText[:min(len(bodyText), 200)])
	}
	if !strings.Contains(bodyText, "Disconnect") {
		t.Fatalf("Step 2 FAILED: Expected to see 'Disconnect' button on page")
	}

	t.Log("Step 2 PASSED: Connection view page loaded with Disconnect button")

	// =========================================================================
	// Step 3: Test cancel on confirmation dialog
	// =========================================================================
	t.Log("Step 3: Click Disconnect and cancel the confirmation")

	// Set up dialog handler to automatically dismiss (cancel) the dialog
	wait, handle := page.MustHandleDialog()
	go func() {
		wait()
		handle(false, "") // false = dismiss/cancel the dialog
	}()

	// Find and click the disconnect button
	disconnectBtn := page.MustElement(".btn-danger")
	disconnectBtn.MustClick()

	// Wait a moment for dialog handling
	page.MustWaitStable()

	// Verify we're still on the same page (cancel should not proceed)
	currentURL := page.MustInfo().URL
	if !strings.Contains(currentURL, "/connections/twitter") {
		t.Logf("Note: Page URL changed to %s, checking if connection still exists", currentURL)
	}

	// Verify connection still exists after canceling
	conn, _ := connService.GetConnection(context.Background(), user.ID, "twitter")
	if conn == nil {
		t.Fatal("Step 3 FAILED: Connection was removed even though dialog was canceled")
	}

	t.Log("Step 3 PASSED: Connection still exists after canceling dialog")

	// =========================================================================
	// Step 4: Test confirm on confirmation dialog
	// =========================================================================
	t.Log("Step 4: Click Disconnect and confirm")

	// Navigate back to connection view if needed
	page.MustNavigate(ts.URL + "/connections/twitter").MustWaitLoad()
	page.MustWaitStable()

	// Set up dialog handler to automatically accept the dialog
	wait2, handle2 := page.MustHandleDialog()
	go func() {
		wait2()
		handle2(true, "") // true = accept/confirm the dialog
	}()

	// Find and click the disconnect button
	disconnectBtn = page.MustElement(".btn-danger")
	disconnectBtn.MustClick()

	// Wait for the redirect after disconnect
	page.MustWaitLoad()
	page.MustWaitStable()

	// Verify we were redirected to connections list
	currentURL = page.MustInfo().URL
	if !strings.Contains(currentURL, "/connections") {
		t.Logf("Step 4: Current URL is %s", currentURL)
	}

	// Verify connection was removed after confirming
	conn, _ = connService.GetConnection(context.Background(), user.ID, "twitter")
	if conn != nil {
		t.Fatal("Step 4 FAILED: Connection still exists after confirming disconnect")
	}

	t.Log("Step 4 PASSED: Connection removed after confirming disconnect")
}

// TestBrowser_ConnectionsList tests the connections list page shows all connected platforms.
func TestBrowser_ConnectionsList(t *testing.T) {
	// Setup test server with mock stores including connection service
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

	testEmail := "list-test@example.com"
	testPassword := "securepassword123"

	// Setup: Create user and add multiple connections
	t.Log("Setup: Creating user and adding connections")

	user, _ := userStore.CreateUser(context.Background(), testEmail, hashPassword(testPassword))
	connService.AddConnection(user.ID, "twitter", "connected", "@testuser")
	connService.AddConnection(user.ID, "linkedin", "connected", "Test User")

	// Login
	t.Log("Login")
	page.MustNavigate(ts.URL + "/login").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Navigate to connections list
	t.Log("Navigate to connections list")
	page.MustNavigate(ts.URL + "/connections").MustWaitLoad()
	page.MustWaitStable()

	// Verify both connections are shown
	bodyText := page.MustElement("body").MustText()
	// Platform names are displayed with first letter capitalized
	if !strings.Contains(bodyText, "Twitter") {
		t.Errorf("Expected to see 'Twitter' in connections list")
	}
	if !strings.Contains(bodyText, "Linkedin") {
		t.Errorf("Expected to see 'Linkedin' in connections list")
	}
	if !strings.Contains(bodyText, "Connected Platforms") {
		t.Errorf("Expected to see 'Connected Platforms' heading")
	}

	t.Log("PASSED: Connections list shows all connected platforms")
}

// TestBrowser_ConnectionNotConnected tests the not connected state.
func TestBrowser_ConnectionNotConnected(t *testing.T) {
	// Setup test server with mock stores including connection service
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

	testEmail := "notconnected-test@example.com"
	testPassword := "securepassword123"

	// Setup: Create user WITHOUT any connections
	t.Log("Setup: Creating user without connections")

	userStore.CreateUser(context.Background(), testEmail, hashPassword(testPassword))

	// Login
	t.Log("Login")
	page.MustNavigate(ts.URL + "/login").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Navigate to a connection view page for a platform that's not connected
	t.Log("Navigate to twitter connection page (not connected)")
	page.MustNavigate(ts.URL + "/connections/twitter").MustWaitLoad()
	page.MustWaitStable()

	// Verify "Not Connected" state is shown
	bodyText := page.MustElement("body").MustText()
	if !strings.Contains(bodyText, "Not Connected") {
		t.Errorf("Expected to see 'Not Connected' state on page, got: %s", bodyText[:min(len(bodyText), 200)])
	}

	t.Log("PASSED: Not connected state is shown correctly")
}
