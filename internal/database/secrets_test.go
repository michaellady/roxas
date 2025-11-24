package database

import (
	"context"
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
