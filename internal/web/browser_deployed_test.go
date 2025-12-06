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
//
// Note: This test requires the deployed environment to have a working database connection.
// If authentication shows "not configured", the test will be skipped.
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
		// Check if there's an error on the page
		bodyText := page.MustElement("body").MustText()
		// Skip if database is not configured (infrastructure issue, not code issue)
		if strings.Contains(bodyText, "Registration not configured") ||
			strings.Contains(bodyText, "not configured") {
			t.Skip("Skipping: Database not available in deployed environment (infrastructure issue)")
		}
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
		t.Log("Warning: Navbar background color not set - CSS may not be loading correctly")
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
