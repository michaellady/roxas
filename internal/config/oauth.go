package config

import (
	"fmt"
	"os"
)

// OAuthConfig holds OAuth credentials for all supported platforms
type OAuthConfig struct {
	Threads         PlatformOAuthConfig
	Twitter         PlatformOAuthConfig
	LinkedIn        PlatformOAuthConfig
	RedirectBaseURL string
}

// PlatformOAuthConfig holds OAuth credentials for a single platform
type PlatformOAuthConfig struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
	Enabled      bool
}

// Validate checks if an enabled platform has all required fields
func (c *PlatformOAuthConfig) Validate() error {
	if !c.Enabled {
		return nil // Disabled platforms don't need validation
	}

	if c.ClientID == "" {
		return fmt.Errorf("client ID is required for enabled platform")
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("client secret is required for enabled platform")
	}
	return nil
}

// LoadOAuthConfig loads OAuth configuration from environment variables
func LoadOAuthConfig() (*OAuthConfig, error) {
	cfg := &OAuthConfig{
		RedirectBaseURL: getEnvOrDefault("OAUTH_REDIRECT_BASE_URL", "http://localhost:8080"),
	}

	// Load Threads config
	cfg.Threads = loadPlatformConfig("THREADS", []string{
		"threads_basic",
		"threads_content_publish",
		"threads_manage_insights",
	})

	// Load Twitter config
	cfg.Twitter = loadPlatformConfig("TWITTER", []string{
		"tweet.read",
		"tweet.write",
		"users.read",
	})

	// Load LinkedIn config
	cfg.LinkedIn = loadPlatformConfig("LINKEDIN", []string{
		"r_liteprofile",
		"w_member_social",
	})

	return cfg, nil
}

// loadPlatformConfig loads OAuth config for a single platform from environment
func loadPlatformConfig(prefix string, defaultScopes []string) PlatformOAuthConfig {
	clientID := os.Getenv(prefix + "_CLIENT_ID")
	clientSecret := os.Getenv(prefix + "_CLIENT_SECRET")

	// Platform is enabled only if both client ID and secret are present
	enabled := clientID != "" && clientSecret != ""

	return PlatformOAuthConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       defaultScopes,
		Enabled:      enabled,
	}
}

// getEnvOrDefault returns the environment variable value or a default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// EnabledPlatforms returns a list of platform names that are enabled
func (c *OAuthConfig) EnabledPlatforms() []string {
	var platforms []string
	if c.Threads.Enabled {
		platforms = append(platforms, "threads")
	}
	if c.Twitter.Enabled {
		platforms = append(platforms, "twitter")
	}
	if c.LinkedIn.Enabled {
		platforms = append(platforms, "linkedin")
	}
	return platforms
}

// GetPlatformConfig returns the OAuth config for a specific platform
func (c *OAuthConfig) GetPlatformConfig(platform string) (PlatformOAuthConfig, bool) {
	switch platform {
	case "threads":
		return c.Threads, true
	case "twitter":
		return c.Twitter, true
	case "linkedin":
		return c.LinkedIn, true
	default:
		return PlatformOAuthConfig{}, false
	}
}

// Validate checks all enabled platforms have valid configuration
func (c *OAuthConfig) Validate() error {
	if err := c.Threads.Validate(); err != nil {
		return fmt.Errorf("threads: %w", err)
	}
	if err := c.Twitter.Validate(); err != nil {
		return fmt.Errorf("twitter: %w", err)
	}
	if err := c.LinkedIn.Validate(); err != nil {
		return fmt.Errorf("linkedin: %w", err)
	}
	return nil
}
