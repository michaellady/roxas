package database

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func TestDBSecret_ToConfig(t *testing.T) {
	secret := DBSecret{
		Host:     "localhost",
		Port:     5432,
		Username: "testuser",
		Password: "testpass",
		Database: "testdb",
	}

	cfg := &Config{
		Host:     secret.Host,
		Port:     fmt.Sprintf("%d", secret.Port),
		User:     secret.Username,
		Password: secret.Password,
		Database: secret.Database,
		SSLMode:  "require",
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Config validation failed: %v", err)
	}

	if cfg.Host != secret.Host {
		t.Errorf("Host = %v, want %v", cfg.Host, secret.Host)
	}
	expectedPort := fmt.Sprintf("%d", secret.Port)
	if cfg.Port != expectedPort {
		t.Errorf("Port = %v, want %v", cfg.Port, expectedPort)
	}
	if cfg.User != secret.Username {
		t.Errorf("User = %v, want %v", cfg.User, secret.Username)
	}
	if cfg.Password != secret.Password {
		t.Errorf("Password = %v, want %v", cfg.Password, secret.Password)
	}
	if cfg.Database != secret.Database {
		t.Errorf("Database = %v, want %v", cfg.Database, secret.Database)
	}
}

func TestLoadConfigFromSecretsManager_MissingSecret(t *testing.T) {
	// Skip if not running integration tests with AWS
	if testing.Short() {
		t.Skip("Skipping AWS Secrets Manager integration test in short mode")
	}

	ctx := context.Background()
	_, err := LoadConfigFromSecretsManager(ctx, "non-existent-secret-12345")

	if err == nil {
		t.Error("Expected error for non-existent secret, got nil")
	}
}

func TestPortType_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{
			name:    "integer port",
			input:   `{"port": 5432}`,
			want:    5432,
			wantErr: false,
		},
		{
			name:    "string port",
			input:   `{"port": "5432"}`,
			want:    5432,
			wantErr: false,
		},
		{
			name:    "invalid string port",
			input:   `{"port": "not-a-number"}`,
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result struct {
				Port PortType `json:"port"`
			}
			err := json.Unmarshal([]byte(tt.input), &result)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if int(result.Port) != tt.want {
				t.Errorf("Port = %d, want %d", result.Port, tt.want)
			}
		})
	}
}
