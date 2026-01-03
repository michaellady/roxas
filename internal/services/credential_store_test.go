package services

import (
	"testing"
	"time"
)

func TestPlatformCredentials_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt *time.Time
		want      bool
	}{
		{
			name:      "nil expiry - never expires",
			expiresAt: nil,
			want:      false,
		},
		{
			name:      "future expiry - not expired",
			expiresAt: timePtr(time.Now().Add(time.Hour)),
			want:      false,
		},
		{
			name:      "past expiry - expired",
			expiresAt: timePtr(time.Now().Add(-time.Hour)),
			want:      true,
		},
		{
			name:      "just now - expired",
			expiresAt: timePtr(time.Now().Add(-time.Second)),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &PlatformCredentials{
				TokenExpiresAt: tt.expiresAt,
			}
			if got := c.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPlatformCredentials_ExpiresWithin(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt *time.Time
		window    time.Duration
		want      bool
	}{
		{
			name:      "nil expiry - never expires",
			expiresAt: nil,
			window:    time.Hour,
			want:      false,
		},
		{
			name:      "expires in 30 min, checking 1 hour window - true",
			expiresAt: timePtr(time.Now().Add(30 * time.Minute)),
			window:    time.Hour,
			want:      true,
		},
		{
			name:      "expires in 2 hours, checking 1 hour window - false",
			expiresAt: timePtr(time.Now().Add(2 * time.Hour)),
			window:    time.Hour,
			want:      false,
		},
		{
			name:      "already expired, checking 1 hour window - true",
			expiresAt: timePtr(time.Now().Add(-30 * time.Minute)),
			window:    time.Hour,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &PlatformCredentials{
				TokenExpiresAt: tt.expiresAt,
			}
			if got := c.ExpiresWithin(tt.window); got != tt.want {
				t.Errorf("ExpiresWithin(%v) = %v, want %v", tt.window, got, tt.want)
			}
		})
	}
}

func TestPlatformCredentials_HasRefreshToken(t *testing.T) {
	tests := []struct {
		name         string
		refreshToken string
		want         bool
	}{
		{
			name:         "empty refresh token",
			refreshToken: "",
			want:         false,
		},
		{
			name:         "has refresh token",
			refreshToken: "some-refresh-token",
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &PlatformCredentials{
				RefreshToken: tt.refreshToken,
			}
			if got := c.HasRefreshToken(); got != tt.want {
				t.Errorf("HasRefreshToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidatePlatform(t *testing.T) {
	tests := []struct {
		name     string
		platform string
		wantErr  bool
	}{
		{name: "linkedin is valid", platform: PlatformLinkedIn, wantErr: false},
		{name: "twitter is valid", platform: PlatformTwitter, wantErr: false},
		{name: "instagram is valid", platform: PlatformInstagram, wantErr: false},
		{name: "youtube is valid", platform: PlatformYouTube, wantErr: false},
		{name: "bluesky is valid", platform: PlatformBluesky, wantErr: false},
		{name: "threads is valid", platform: PlatformThreads, wantErr: false},
		{name: "tiktok is valid", platform: PlatformTikTok, wantErr: false},
		{name: "unknown platform is invalid", platform: "fakebook", wantErr: true},
		{name: "empty platform is invalid", platform: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePlatform(tt.platform)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePlatform(%q) error = %v, wantErr %v", tt.platform, err, tt.wantErr)
			}
		})
	}
}

func TestSupportedPlatforms(t *testing.T) {
	// Verify all expected platforms are supported
	expectedPlatforms := []string{
		"linkedin", "twitter", "instagram", "youtube",
		"bluesky", "threads", "tiktok",
	}

	for _, platform := range expectedPlatforms {
		if !SupportedPlatforms[platform] {
			t.Errorf("Expected platform %q to be supported", platform)
		}
	}

	// Verify platform constants match the map keys
	if !SupportedPlatforms[PlatformLinkedIn] {
		t.Error("PlatformLinkedIn constant doesn't match supported platforms")
	}
	if !SupportedPlatforms[PlatformTwitter] {
		t.Error("PlatformTwitter constant doesn't match supported platforms")
	}
	if !SupportedPlatforms[PlatformBluesky] {
		t.Error("PlatformBluesky constant doesn't match supported platforms")
	}
}

// timePtr is a helper to create a pointer to a time.Time
func timePtr(t time.Time) *time.Time {
	return &t
}
