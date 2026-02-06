package config

import (
	"os"
	"testing"
)

func TestLoadOAuthConfig_AllPlatformsEnabled(t *testing.T) {
	// Set all environment variables
	setEnv := map[string]string{
		"THREADS_CLIENT_ID":     "threads-id",
		"THREADS_CLIENT_SECRET": "threads-secret",
		"TWITTER_CLIENT_ID":     "twitter-id",
		"TWITTER_CLIENT_SECRET": "twitter-secret",
		"LINKEDIN_CLIENT_ID":    "linkedin-id",
		"LINKEDIN_CLIENT_SECRET": "linkedin-secret",
		"OAUTH_REDIRECT_BASE_URL": "https://roxas.example.com",
	}

	for k, v := range setEnv {
		os.Setenv(k, v)
		defer os.Unsetenv(k)
	}

	cfg, err := LoadOAuthConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify Threads
	if !cfg.Threads.Enabled {
		t.Error("expected Threads to be enabled")
	}
	if cfg.Threads.ClientID != "threads-id" {
		t.Errorf("expected Threads ClientID 'threads-id', got %q", cfg.Threads.ClientID)
	}
	if cfg.Threads.ClientSecret != "threads-secret" {
		t.Errorf("expected Threads ClientSecret 'threads-secret', got %q", cfg.Threads.ClientSecret)
	}

	// Verify Twitter
	if !cfg.Twitter.Enabled {
		t.Error("expected Twitter to be enabled")
	}
	if cfg.Twitter.ClientID != "twitter-id" {
		t.Errorf("expected Twitter ClientID 'twitter-id', got %q", cfg.Twitter.ClientID)
	}

	// Verify LinkedIn
	if !cfg.LinkedIn.Enabled {
		t.Error("expected LinkedIn to be enabled")
	}
	if cfg.LinkedIn.ClientID != "linkedin-id" {
		t.Errorf("expected LinkedIn ClientID 'linkedin-id', got %q", cfg.LinkedIn.ClientID)
	}

	// Verify redirect URL
	if cfg.RedirectBaseURL != "https://roxas.example.com" {
		t.Errorf("expected RedirectBaseURL 'https://roxas.example.com', got %q", cfg.RedirectBaseURL)
	}
}

func TestLoadOAuthConfig_PartialConfig_DisablesPlatform(t *testing.T) {
	// Only set Threads config, leave others empty
	os.Setenv("THREADS_CLIENT_ID", "threads-id")
	os.Setenv("THREADS_CLIENT_SECRET", "threads-secret")
	os.Setenv("OAUTH_REDIRECT_BASE_URL", "https://example.com")
	defer os.Unsetenv("THREADS_CLIENT_ID")
	defer os.Unsetenv("THREADS_CLIENT_SECRET")
	defer os.Unsetenv("OAUTH_REDIRECT_BASE_URL")

	// Ensure others are unset
	os.Unsetenv("TWITTER_CLIENT_ID")
	os.Unsetenv("TWITTER_CLIENT_SECRET")
	os.Unsetenv("LINKEDIN_CLIENT_ID")
	os.Unsetenv("LINKEDIN_CLIENT_SECRET")

	cfg, err := LoadOAuthConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Threads should be enabled
	if !cfg.Threads.Enabled {
		t.Error("expected Threads to be enabled")
	}

	// Twitter should be disabled (no credentials)
	if cfg.Twitter.Enabled {
		t.Error("expected Twitter to be disabled when credentials missing")
	}

	// LinkedIn should be disabled (no credentials)
	if cfg.LinkedIn.Enabled {
		t.Error("expected LinkedIn to be disabled when credentials missing")
	}
}

func TestLoadOAuthConfig_MissingRedirectURL_UsesDefault(t *testing.T) {
	os.Setenv("THREADS_CLIENT_ID", "id")
	os.Setenv("THREADS_CLIENT_SECRET", "secret")
	os.Unsetenv("OAUTH_REDIRECT_BASE_URL")
	defer os.Unsetenv("THREADS_CLIENT_ID")
	defer os.Unsetenv("THREADS_CLIENT_SECRET")

	cfg, err := LoadOAuthConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should use localhost default for development
	if cfg.RedirectBaseURL != "http://localhost:8080" {
		t.Errorf("expected default RedirectBaseURL 'http://localhost:8080', got %q", cfg.RedirectBaseURL)
	}
}

func TestLoadOAuthConfig_NoPlatformsConfigured_ReturnsEmpty(t *testing.T) {
	// Clear all OAuth env vars
	os.Unsetenv("THREADS_CLIENT_ID")
	os.Unsetenv("THREADS_CLIENT_SECRET")
	os.Unsetenv("TWITTER_CLIENT_ID")
	os.Unsetenv("TWITTER_CLIENT_SECRET")
	os.Unsetenv("LINKEDIN_CLIENT_ID")
	os.Unsetenv("LINKEDIN_CLIENT_SECRET")
	os.Unsetenv("OAUTH_REDIRECT_BASE_URL")

	cfg, err := LoadOAuthConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All platforms should be disabled
	if cfg.Threads.Enabled {
		t.Error("expected Threads to be disabled")
	}
	if cfg.Twitter.Enabled {
		t.Error("expected Twitter to be disabled")
	}
	if cfg.LinkedIn.Enabled {
		t.Error("expected LinkedIn to be disabled")
	}

	// EnabledPlatforms should be empty
	if len(cfg.EnabledPlatforms()) != 0 {
		t.Errorf("expected no enabled platforms, got %v", cfg.EnabledPlatforms())
	}
}

func TestLoadOAuthConfig_OnlyClientID_PlatformDisabled(t *testing.T) {
	// Set only client ID, no secret
	os.Setenv("THREADS_CLIENT_ID", "threads-id")
	os.Unsetenv("THREADS_CLIENT_SECRET")
	defer os.Unsetenv("THREADS_CLIENT_ID")

	cfg, err := LoadOAuthConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Platform should be disabled without both ID and secret
	if cfg.Threads.Enabled {
		t.Error("expected Threads to be disabled when only client ID is set")
	}
}

func TestPlatformOAuthConfig_Validate(t *testing.T) {
	tests := []struct {
		name     string
		config   PlatformOAuthConfig
		wantErr  bool
	}{
		{
			name: "valid config",
			config: PlatformOAuthConfig{
				ClientID:     "id",
				ClientSecret: "secret",
				Enabled:      true,
			},
			wantErr: false,
		},
		{
			name: "disabled config with missing fields is valid",
			config: PlatformOAuthConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "enabled config with missing client ID",
			config: PlatformOAuthConfig{
				ClientSecret: "secret",
				Enabled:      true,
			},
			wantErr: true,
		},
		{
			name: "enabled config with missing client secret",
			config: PlatformOAuthConfig{
				ClientID: "id",
				Enabled:  true,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOAuthConfig_EnabledPlatforms(t *testing.T) {
	cfg := &OAuthConfig{
		Threads:  PlatformOAuthConfig{Enabled: true},
		Twitter:  PlatformOAuthConfig{Enabled: false},
		LinkedIn: PlatformOAuthConfig{Enabled: true},
	}

	platforms := cfg.EnabledPlatforms()
	if len(platforms) != 2 {
		t.Errorf("expected 2 enabled platforms, got %d", len(platforms))
	}

	// Check that enabled platforms are in the list
	hasThreads, hasLinkedIn := false, false
	for _, p := range platforms {
		if p == "threads" {
			hasThreads = true
		}
		if p == "linkedin" {
			hasLinkedIn = true
		}
	}

	if !hasThreads {
		t.Error("expected threads in enabled platforms")
	}
	if !hasLinkedIn {
		t.Error("expected linkedin in enabled platforms")
	}
}

func TestOAuthConfig_GetPlatformConfig(t *testing.T) {
	cfg := &OAuthConfig{
		Threads: PlatformOAuthConfig{
			ClientID:     "threads-id",
			ClientSecret: "threads-secret",
			Enabled:      true,
		},
	}

	// Get existing platform
	pc, ok := cfg.GetPlatformConfig("threads")
	if !ok {
		t.Error("expected to find threads config")
	}
	if pc.ClientID != "threads-id" {
		t.Errorf("expected ClientID 'threads-id', got %q", pc.ClientID)
	}

	// Get non-existent platform
	_, ok = cfg.GetPlatformConfig("unknown")
	if ok {
		t.Error("expected not to find unknown platform config")
	}
}

func TestOAuthConfig_Validate_AllValid(t *testing.T) {
	cfg := &OAuthConfig{
		Threads: PlatformOAuthConfig{
			ClientID:     "id",
			ClientSecret: "secret",
			Enabled:      true,
		},
		Twitter: PlatformOAuthConfig{
			ClientID:     "id",
			ClientSecret: "secret",
			Enabled:      true,
		},
		LinkedIn: PlatformOAuthConfig{
			ClientID:     "id",
			ClientSecret: "secret",
			Enabled:      true,
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestOAuthConfig_Validate_ThreadsInvalid(t *testing.T) {
	cfg := &OAuthConfig{
		Threads: PlatformOAuthConfig{
			ClientID: "",
			Enabled:  true,
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() expected error for invalid Threads config")
	}
}

func TestOAuthConfig_Validate_TwitterInvalid(t *testing.T) {
	cfg := &OAuthConfig{
		Threads: PlatformOAuthConfig{
			ClientID:     "id",
			ClientSecret: "secret",
			Enabled:      true,
		},
		Twitter: PlatformOAuthConfig{
			ClientID: "",
			Enabled:  true,
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() expected error for invalid Twitter config")
	}
}

func TestOAuthConfig_Validate_LinkedInInvalid(t *testing.T) {
	cfg := &OAuthConfig{
		Threads: PlatformOAuthConfig{
			ClientID:     "id",
			ClientSecret: "secret",
			Enabled:      true,
		},
		Twitter: PlatformOAuthConfig{
			ClientID:     "id",
			ClientSecret: "secret",
			Enabled:      true,
		},
		LinkedIn: PlatformOAuthConfig{
			ClientID: "",
			Enabled:  true,
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() expected error for invalid LinkedIn config")
	}
}

func TestOAuthConfig_Validate_AllDisabled(t *testing.T) {
	cfg := &OAuthConfig{
		Threads:  PlatformOAuthConfig{Enabled: false},
		Twitter:  PlatformOAuthConfig{Enabled: false},
		LinkedIn: PlatformOAuthConfig{Enabled: false},
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() unexpected error for disabled platforms: %v", err)
	}
}

func TestOAuthConfig_GetPlatformConfig_AllPlatforms(t *testing.T) {
	cfg := &OAuthConfig{
		Threads: PlatformOAuthConfig{
			ClientID: "threads-id",
			Enabled:  true,
		},
		Twitter: PlatformOAuthConfig{
			ClientID: "twitter-id",
			Enabled:  true,
		},
		LinkedIn: PlatformOAuthConfig{
			ClientID: "linkedin-id",
			Enabled:  true,
		},
	}

	tests := []struct {
		platform   string
		wantOK     bool
		wantID     string
	}{
		{"threads", true, "threads-id"},
		{"twitter", true, "twitter-id"},
		{"linkedin", true, "linkedin-id"},
		{"unknown", false, ""},
		{"", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.platform, func(t *testing.T) {
			pc, ok := cfg.GetPlatformConfig(tt.platform)
			if ok != tt.wantOK {
				t.Errorf("GetPlatformConfig(%q) ok = %v, want %v", tt.platform, ok, tt.wantOK)
			}
			if ok && pc.ClientID != tt.wantID {
				t.Errorf("GetPlatformConfig(%q) ClientID = %q, want %q", tt.platform, pc.ClientID, tt.wantID)
			}
		})
	}
}

func TestOAuthConfig_EnabledPlatforms_AllEnabled(t *testing.T) {
	cfg := &OAuthConfig{
		Threads:  PlatformOAuthConfig{Enabled: true},
		Twitter:  PlatformOAuthConfig{Enabled: true},
		LinkedIn: PlatformOAuthConfig{Enabled: true},
	}

	platforms := cfg.EnabledPlatforms()
	if len(platforms) != 3 {
		t.Errorf("expected 3 enabled platforms, got %d: %v", len(platforms), platforms)
	}

	has := map[string]bool{}
	for _, p := range platforms {
		has[p] = true
	}
	for _, want := range []string{"threads", "twitter", "linkedin"} {
		if !has[want] {
			t.Errorf("expected %q in enabled platforms", want)
		}
	}
}

func TestOAuthConfig_EnabledPlatforms_OnlyTwitter(t *testing.T) {
	cfg := &OAuthConfig{
		Threads:  PlatformOAuthConfig{Enabled: false},
		Twitter:  PlatformOAuthConfig{Enabled: true},
		LinkedIn: PlatformOAuthConfig{Enabled: false},
	}

	platforms := cfg.EnabledPlatforms()
	if len(platforms) != 1 {
		t.Errorf("expected 1 enabled platform, got %d: %v", len(platforms), platforms)
	}
	if len(platforms) > 0 && platforms[0] != "twitter" {
		t.Errorf("expected twitter, got %q", platforms[0])
	}
}

func TestOAuthConfig_ThreadsScopes(t *testing.T) {
	os.Setenv("THREADS_CLIENT_ID", "id")
	os.Setenv("THREADS_CLIENT_SECRET", "secret")
	defer os.Unsetenv("THREADS_CLIENT_ID")
	defer os.Unsetenv("THREADS_CLIENT_SECRET")

	cfg, _ := LoadOAuthConfig()

	// Threads should have default scopes
	if len(cfg.Threads.Scopes) == 0 {
		t.Error("expected Threads to have default scopes")
	}

	// Should include required scopes for posting
	hasBasic, hasPublish := false, false
	for _, s := range cfg.Threads.Scopes {
		if s == "threads_basic" {
			hasBasic = true
		}
		if s == "threads_content_publish" {
			hasPublish = true
		}
	}

	if !hasBasic {
		t.Error("expected threads_basic scope")
	}
	if !hasPublish {
		t.Error("expected threads_content_publish scope")
	}
}
