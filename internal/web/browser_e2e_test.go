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

// launchBrowser creates a browser instance with the given configuration
func launchBrowser(cfg browserTestConfig) (*rod.Browser, func()) {
	var browser *rod.Browser

	// Create launcher with common settings for CI environments
	l := launcher.New().
		// Required for running in CI/Docker without root
		NoSandbox(true).
		Headless(cfg.headless)

	if !cfg.headless {
		l = l.Devtools(false)
	}

	u := l.MustLaunch()
	browser = rod.New().ControlURL(u).MustConnect()

	if !cfg.headless {
		browser = browser.SlowMotion(cfg.slowMo)
	}

	cleanup := func() {
		browser.MustClose()
	}

	return browser, cleanup
}

// inputText finds an input field and sets its value
func inputText(page *rod.Page, selector, text string) {
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
	router := NewRouterWithAllStores(userStore, repoStore, commitLister, nil)

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
	inputText(page, "#email", testEmail)
	inputText(page, "#password", testPassword)
	inputText(page, "#confirm_password", testPassword)

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
	inputText(page, "#email", testEmail)
	inputText(page, "#password", testPassword)

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

	inputText(page, "#email", "test@example.com")
	inputText(page, "#password", "password123")
	inputText(page, "#confirm_password", "differentpassword")
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

	inputText(page, "#email", "test2@example.com")
	inputText(page, "#password", "short")
	inputText(page, "#confirm_password", "short")
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

	inputText(page, "#email", "nonexistent@example.com")
	inputText(page, "#password", "wrongpassword")
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
	router := NewRouterWithAllStores(userStore, repoStore, commitLister, nil)

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
	inputText(page, "#email", testEmail)
	inputText(page, "#password", testPassword)
	inputText(page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	// Get the user ID so we can add test data
	user, _ := userStore.GetUserByEmail(context.Background(), testEmail)
	if user == nil {
		t.Fatal("Failed to get created user")
	}

	// Add test repository and commit
	repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/test/repo", "secret123")
	commitLister.AddCommitForUser(user.ID, &DashboardCommit{
		SHA:     "abc1234567890",
		Message: "Add awesome feature",
		Author:  "Test Author",
	})

	// Login
	inputText(page, "#email", testEmail)
	inputText(page, "#password", testPassword)
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
