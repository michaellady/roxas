//go:build browser

package web

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Browser-based E2E Tests against Deployed Environment
//
// These tests run the same browser E2E tests but against a live deployed
// environment (e.g., PR preview deployments) instead of a local httptest server.
//
// Set the DEPLOY_URL environment variable to run these tests:
//   DEPLOY_URL=https://pr-63.roxasapp.com go test -tags=browser -v ./internal/web -run TestDeployed
//
// By default, tests run headless. Set BROWSER_VISIBLE=1 to watch:
//   BROWSER_VISIBLE=1 DEPLOY_URL=https://pr-63.roxasapp.com go test -tags=browser -v ./internal/web -run TestDeployed
//
// =============================================================================

// getDeployURL returns the deployment URL from environment or skips the test
func getDeployURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("DEPLOY_URL")
	if url == "" {
		t.Skip("DEPLOY_URL not set - skipping deployed environment test")
	}
	return strings.TrimSuffix(url, "/")
}

// TestDeployed_FullAuthFlow tests the complete authentication flow against a deployed environment:
// signup → login → dashboard → logout → redirect to login
func TestDeployed_FullAuthFlow(t *testing.T) {
	baseURL := getDeployURL(t)

	// Launch browser
	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(baseURL).Timeout(30 * time.Second)
	defer page.MustClose()

	// Use unique email to avoid conflicts with existing users
	testEmail := fmt.Sprintf("deployed-test-%d@example.com", time.Now().UnixNano())
	testPassword := "securepassword123"

	// =========================================================================
	// Step 1: Navigate to home page and verify it loads
	// =========================================================================
	t.Log("Step 1: Navigate to home page")

	page.MustWaitLoad()

	// First check if the server is responding with HTML (not JSON error)
	bodyText := page.MustElement("body").MustText()
	if strings.Contains(bodyText, "Internal Server Error") {
		t.Fatalf("Step 1 FAILED: Server returned Internal Server Error. The Lambda may be failing to start. Body: %s", bodyText)
	}

	// Verify we're on the home page
	title := page.MustElement("title").MustText()
	if !strings.Contains(title, "Roxas") {
		t.Fatalf("Expected title to contain 'Roxas', got: %s", title)
	}

	// Verify CSS is loaded (check that body has styles applied)
	bodyStyles := page.MustElement("body").MustEval(`() => window.getComputedStyle(this).fontFamily`).String()
	if bodyStyles == "" {
		t.Log("Warning: Could not verify CSS loading")
	}
	t.Log("Step 1 PASSED: Home page loaded")

	// =========================================================================
	// Step 2: Navigate to signup page
	// =========================================================================
	t.Log("Step 2: Navigate to signup page")

	page.MustNavigate(baseURL + "/signup").MustWaitLoad()

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
	page.MustWaitStable()
	currentURL := page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/login") {
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

	page.MustNavigate(baseURL + "/dashboard").MustWaitLoad()

	// Should redirect to login since we're logged out
	currentURL = page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/login") {
		t.Fatalf("Step 7 FAILED: Expected redirect to /login, dashboard should require auth, got: %s", currentURL)
	}
	t.Log("Step 7 PASSED: Dashboard requires authentication after logout")

	t.Log("=== ALL DEPLOYED E2E TESTS PASSED ===")
}

// TestDeployed_StaticAssets verifies that static assets are served correctly
func TestDeployed_StaticAssets(t *testing.T) {
	baseURL := getDeployURL(t)

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(baseURL).Timeout(30 * time.Second)
	defer page.MustClose()

	page.MustWaitLoad()

	// Check that CSS is actually loaded and applied
	t.Log("Checking CSS is loaded...")

	// The navbar should have specific styling from our CSS
	navbar := page.MustElement(".navbar")
	if navbar == nil {
		t.Fatal("Navbar element not found")
	}

	// Check computed styles to verify CSS loaded
	bgColor := navbar.MustEval(`() => window.getComputedStyle(this).backgroundColor`).String()
	if bgColor == "" || bgColor == "rgba(0, 0, 0, 0)" {
		t.Errorf("Navbar background color not set (got %q) - CSS is likely not loading correctly", bgColor)
	}

	// Navigate directly to CSS and check it returns CSS content
	page.MustNavigate(baseURL + "/static/css/style.css").MustWaitLoad()

	// The page should contain CSS content, not HTML
	bodyText := page.MustElement("body").MustText()
	if strings.Contains(bodyText, "<!DOCTYPE html>") {
		t.Fatal("CSS endpoint returned HTML instead of CSS")
	}
	if !strings.Contains(bodyText, ":root") && !strings.Contains(bodyText, "--primary") {
		t.Fatalf("CSS content doesn't look like our stylesheet: %s", bodyText[:min(len(bodyText), 200)])
	}

	t.Log("PASSED: Static assets are served correctly")
}

// TestDeployed_SignupValidation tests form validation on the deployed environment
func TestDeployed_SignupValidation(t *testing.T) {
	baseURL := getDeployURL(t)

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(baseURL + "/signup").Timeout(30 * time.Second)
	defer page.MustClose()

	page.MustWaitLoad()

	// =========================================================================
	// Test: Password mismatch shows error
	// =========================================================================
	t.Log("Testing password mismatch validation")

	inputText(t, page, "#email", "validation-test@example.com")
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
	page.MustNavigate(baseURL + "/signup").MustWaitLoad()

	inputText(t, page, "#email", "validation-test2@example.com")
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

// TestDeployed_GitHubAppInstallLink verifies the GitHub App install button renders
// correctly on deployed environments and points to the correct URL.
func TestDeployed_GitHubAppInstallLink(t *testing.T) {
	baseURL := getDeployURL(t)

	// Launch browser
	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(baseURL).Timeout(30 * time.Second)
	defer page.MustClose()

	// Use unique email to avoid conflicts with existing users
	testEmail := fmt.Sprintf("deployed-ghapp-test-%d@example.com", time.Now().UnixNano())
	testPassword := "securepassword123"

	// =========================================================================
	// Step 1: Sign up and log in
	// =========================================================================
	t.Log("Step 1: Sign up")
	page.MustNavigate(baseURL + "/signup").MustWaitLoad()
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	inputText(t, page, "#confirm_password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	t.Log("Step 1b: Log in")
	inputText(t, page, "#email", testEmail)
	inputText(t, page, "#password", testPassword)
	page.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	currentURL := page.MustInfo().URL
	if !strings.HasSuffix(currentURL, "/dashboard") {
		t.Fatalf("Expected redirect to /dashboard after login, got: %s", currentURL)
	}

	// =========================================================================
	// Step 2: Verify GitHub App install link on dashboard empty state
	// =========================================================================
	t.Log("Step 2: Check GitHub App install link on dashboard")

	dashboardLink := page.MustElement(".empty-state a.btn-primary")
	dashboardLinkText := dashboardLink.MustText()
	if !strings.Contains(dashboardLinkText, "Install Roxas GitHub App") {
		t.Fatalf("Expected link text to contain 'Install Roxas GitHub App', got: %s", dashboardLinkText)
	}

	dashboardHref := dashboardLink.MustProperty("href").String()
	if !strings.Contains(dashboardHref, "github.com/apps/") || !strings.HasSuffix(dashboardHref, "/installations/new") {
		t.Fatalf("Dashboard install link has unexpected href: %s (expected github.com/apps/.../installations/new)", dashboardHref)
	}
	t.Logf("Step 2 PASSED: Dashboard link href = %s", dashboardHref)

	// =========================================================================
	// Step 3: Verify GitHub App install link on /repositories/new
	// =========================================================================
	t.Log("Step 3: Check GitHub App install link on /repositories/new")

	page.MustNavigate(baseURL + "/repositories/new").MustWaitLoad()
	page.MustWaitStable()

	repoLink := page.MustElement(".github-app-install a.btn-primary")
	repoLinkText := repoLink.MustText()
	if !strings.Contains(repoLinkText, "Install Roxas GitHub App") {
		t.Fatalf("Expected link text to contain 'Install Roxas GitHub App', got: %s", repoLinkText)
	}

	repoHref := repoLink.MustProperty("href").String()
	if !strings.Contains(repoHref, "github.com/apps/") || !strings.HasSuffix(repoHref, "/installations/new") {
		t.Fatalf("Repo page install link has unexpected href: %s (expected github.com/apps/.../installations/new)", repoHref)
	}
	t.Logf("Step 3 PASSED: Repo page link href = %s", repoHref)

	// =========================================================================
	// Step 4: Verify both links point to the same URL
	// =========================================================================
	t.Log("Step 4: Verify href consistency")

	if dashboardHref != repoHref {
		t.Fatalf("Dashboard href (%s) does not match repo page href (%s)", dashboardHref, repoHref)
	}
	t.Log("Step 4 PASSED: Both links point to the same URL")

	// =========================================================================
	// Step 5: Optionally validate exact URL via EXPECTED_GH_APP_URL
	// =========================================================================
	if expectedURL := os.Getenv("EXPECTED_GH_APP_URL"); expectedURL != "" {
		t.Logf("Step 5: Validating exact URL against EXPECTED_GH_APP_URL=%s", expectedURL)
		if dashboardHref != expectedURL {
			t.Fatalf("Install link href %q does not match EXPECTED_GH_APP_URL %q", dashboardHref, expectedURL)
		}
		t.Log("Step 5 PASSED: Href matches EXPECTED_GH_APP_URL exactly")
	} else {
		t.Log("Step 5 SKIPPED: EXPECTED_GH_APP_URL not set, URL shape already validated")
	}

	// =========================================================================
	// Step 6: Logout
	// =========================================================================
	t.Log("Step 6: Logout")

	page.MustNavigate(baseURL + "/dashboard").MustWaitLoad()
	logoutForm := page.MustElement("form[action='/logout']")
	logoutForm.MustElement("button[type=submit]").MustClick()
	page.MustWaitLoad()
	page.MustWaitStable()

	t.Log("=== TestDeployed_GitHubAppInstallLink PASSED ===")
}

// TestDeployed_LoginValidation tests login error handling on deployed environment
func TestDeployed_LoginValidation(t *testing.T) {
	baseURL := getDeployURL(t)

	cfg := getBrowserConfig()
	browser, cleanup := launchBrowser(cfg)
	defer cleanup()

	page := browser.MustPage(baseURL + "/login").Timeout(30 * time.Second)
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
