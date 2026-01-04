// Package jobs provides background job implementations for the application.
package jobs

import (
	"context"
	"time"

	"github.com/mikelady/roxas/internal/services"
)

// ConnectionTester tests if a platform connection is working
type ConnectionTester interface {
	TestConnection(ctx context.Context, creds *services.PlatformCredentials) error
}

// HealthCheckConfig configures the health check job
type HealthCheckConfig struct {
	// CheckInterval is how often connections should be checked
	CheckInterval time.Duration

	// ExpiryWarningDays is how many days before expiry to flag tokens
	ExpiryWarningDays int
}

// DefaultConfig returns default health check configuration
func DefaultConfig() HealthCheckConfig {
	return HealthCheckConfig{
		CheckInterval:     24 * time.Hour,
		ExpiryWarningDays: 7,
	}
}

// HealthCheckResult contains the results of a health check run
type HealthCheckResult struct {
	Checked       int   // Total connections checked
	Healthy       int   // Connections that are healthy
	Unhealthy     int   // Connections that are unhealthy
	ExpiringTokens int  // Tokens expiring within warning period
	UpdateErrors  int   // Errors updating health status
	Err           error // Fatal error that stopped the job (nil if completed)
}

// HealthCheckJob checks the health of platform connections
type HealthCheckJob struct {
	credentialStore services.CredentialStore
	tester          ConnectionTester
	config          HealthCheckConfig
}

// NewHealthCheckJob creates a new health check job
func NewHealthCheckJob(store services.CredentialStore, tester ConnectionTester, config HealthCheckConfig) *HealthCheckJob {
	return &HealthCheckJob{
		credentialStore: store,
		tester:          tester,
		config:          config,
	}
}

// Run executes the health check job
func (j *HealthCheckJob) Run(ctx context.Context) HealthCheckResult {
	result := HealthCheckResult{}

	// Get credentials needing a health check
	credentials, err := j.credentialStore.GetCredentialsNeedingCheck(ctx, j.config.CheckInterval)
	if err != nil {
		result.Err = err
		return result
	}

	// Check each credential
	for _, creds := range credentials {
		result.Checked++

		// Test the connection
		testErr := j.tester.TestConnection(ctx, creds)

		var isHealthy bool
		var healthError *string

		if testErr != nil {
			isHealthy = false
			errMsg := testErr.Error()
			healthError = &errMsg
			result.Unhealthy++
		} else {
			isHealthy = true
			result.Healthy++
		}

		// Update health status in database
		if updateErr := j.credentialStore.UpdateHealthStatus(ctx, creds.UserID, creds.Platform, isHealthy, healthError); updateErr != nil {
			result.UpdateErrors++
			// Don't stop processing other credentials
		}
	}

	// Check for expiring tokens
	expiryDuration := time.Duration(j.config.ExpiryWarningDays) * 24 * time.Hour
	expiringCreds, err := j.credentialStore.GetExpiringCredentials(ctx, expiryDuration)
	if err == nil {
		result.ExpiringTokens = len(expiringCreds)
	}

	return result
}
