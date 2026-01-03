// Package jobs provides background job implementations for Roxas.
package jobs

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/mikelady/roxas/internal/services"
)

// =============================================================================
// Connection Health Check Job (hq-lq9)
// Periodic health monitoring for connected social platforms
// =============================================================================

// HealthCheckStore defines the credential store operations needed for health checks
type HealthCheckStore interface {
	// GetAllCredentials retrieves all active credentials
	GetAllCredentials(ctx context.Context) ([]*services.PlatformCredentials, error)

	// GetExpiringCredentials retrieves credentials expiring within the given duration
	GetExpiringCredentials(ctx context.Context, within time.Duration) ([]*services.PlatformCredentials, error)

	// GetCredentialsNeedingCheck retrieves credentials that haven't been checked recently
	GetCredentialsNeedingCheck(ctx context.Context, since time.Duration) ([]*services.PlatformCredentials, error)

	// UpdateHealthStatus updates the health status of a credential
	UpdateHealthStatus(ctx context.Context, userID, platform string, isHealthy bool, healthError string) error
}

// ConnectionTester defines the interface for testing platform connections
type ConnectionTester interface {
	// TestConnection verifies a connection is still valid
	// Returns nil if healthy, error describing the issue otherwise
	TestConnection(ctx context.Context, creds *services.PlatformCredentials) error
}

// HealthCheckConfig configures the health check job
type HealthCheckConfig struct {
	// ExpiryWarningWindow is how far in advance to warn about expiring tokens
	// Default: 7 days
	ExpiryWarningWindow time.Duration

	// CheckInterval is how long since last check before re-checking a connection
	// Default: 24 hours
	CheckInterval time.Duration

	// Logger for job output (optional, defaults to standard logger)
	Logger *log.Logger
}

// DefaultHealthCheckConfig returns sensible defaults
func DefaultHealthCheckConfig() HealthCheckConfig {
	return HealthCheckConfig{
		ExpiryWarningWindow: 7 * 24 * time.Hour,
		CheckInterval:       24 * time.Hour,
	}
}

// HealthCheckResult contains the results of a health check run
type HealthCheckResult struct {
	// TokensExpiringSoon is the count of tokens expiring within the warning window
	TokensExpiringSoon int

	// HealthyConnections is the count of connections that passed health check
	HealthyConnections int

	// UnhealthyConnections is the count of connections that failed health check
	UnhealthyConnections int

	// Errors is a list of errors encountered during the run
	Errors []error

	// Duration is how long the health check took
	Duration time.Duration
}

// HealthCheckJob runs periodic health checks on platform connections
type HealthCheckJob struct {
	store  HealthCheckStore
	tester ConnectionTester
	config HealthCheckConfig
}

// NewHealthCheckJob creates a new health check job
func NewHealthCheckJob(store HealthCheckStore, tester ConnectionTester, config HealthCheckConfig) *HealthCheckJob {
	// Apply defaults for zero values
	if config.ExpiryWarningWindow == 0 {
		config.ExpiryWarningWindow = 7 * 24 * time.Hour
	}
	if config.CheckInterval == 0 {
		config.CheckInterval = 24 * time.Hour
	}

	return &HealthCheckJob{
		store:  store,
		tester: tester,
		config: config,
	}
}

// Run executes the complete health check job
func (j *HealthCheckJob) Run(ctx context.Context) (*HealthCheckResult, error) {
	start := time.Now()
	result := &HealthCheckResult{}

	// Check for expiring tokens
	expiryResult := j.CheckExpiringTokens(ctx)
	result.TokensExpiringSoon = expiryResult.TokensExpiringSoon
	result.Errors = append(result.Errors, expiryResult.Errors...)

	// Test connections that need checking
	connResult := j.TestConnections(ctx)
	result.HealthyConnections = connResult.HealthyConnections
	result.UnhealthyConnections = connResult.UnhealthyConnections
	result.Errors = append(result.Errors, connResult.Errors...)

	result.Duration = time.Since(start)

	j.log("Health check completed: %d expiring, %d healthy, %d unhealthy, %d errors, took %v",
		result.TokensExpiringSoon,
		result.HealthyConnections,
		result.UnhealthyConnections,
		len(result.Errors),
		result.Duration,
	)

	return result, nil
}

// CheckExpiringTokens finds tokens that will expire soon
func (j *HealthCheckJob) CheckExpiringTokens(ctx context.Context) *HealthCheckResult {
	result := &HealthCheckResult{}

	expiring, err := j.store.GetExpiringCredentials(ctx, j.config.ExpiryWarningWindow)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("fetching expiring credentials: %w", err))
		return result
	}

	result.TokensExpiringSoon = len(expiring)

	// Log warnings for expiring tokens
	for _, creds := range expiring {
		var expiresIn time.Duration
		if creds.TokenExpiresAt != nil {
			expiresIn = time.Until(*creds.TokenExpiresAt)
		}
		j.log("Token expiring soon: user=%s platform=%s expires_in=%v",
			creds.UserID, creds.Platform, expiresIn)
	}

	return result
}

// TestConnections tests all connections that need checking
func (j *HealthCheckJob) TestConnections(ctx context.Context) *HealthCheckResult {
	result := &HealthCheckResult{}

	// Get credentials that need a health check
	creds, err := j.store.GetCredentialsNeedingCheck(ctx, j.config.CheckInterval)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("fetching credentials needing check: %w", err))
		return result
	}

	// Test each connection
	for _, c := range creds {
		testErr := j.tester.TestConnection(ctx, c)

		isHealthy := testErr == nil
		healthError := ""
		if testErr != nil {
			healthError = testErr.Error()
		}

		// Update health status in database
		if updateErr := j.store.UpdateHealthStatus(ctx, c.UserID, c.Platform, isHealthy, healthError); updateErr != nil {
			// Wrap error with credential context for debugging (hq-1aig)
			result.Errors = append(result.Errors, fmt.Errorf("updating health status for user=%s platform=%s: %w", c.UserID, c.Platform, updateErr))
			// Continue processing other credentials
		}

		if isHealthy {
			result.HealthyConnections++
		} else {
			result.UnhealthyConnections++
			j.log("Unhealthy connection: user=%s platform=%s error=%s",
				c.UserID, c.Platform, healthError)
		}
	}

	return result
}

// log writes a message using the configured logger or standard log
func (j *HealthCheckJob) log(format string, args ...interface{}) {
	if j.config.Logger != nil {
		j.config.Logger.Printf(format, args...)
	} else {
		log.Printf("[HealthCheck] "+format, args...)
	}
}
