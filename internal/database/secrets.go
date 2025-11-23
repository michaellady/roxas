package database

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// DBSecret represents the structure of database credentials in Secrets Manager
type DBSecret struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Database string `json:"database"`
}

// LoadConfigFromSecretsManager fetches database credentials from AWS Secrets Manager
func LoadConfigFromSecretsManager(ctx context.Context, secretName string) (*Config, error) {
	// Load AWS SDK configuration
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create Secrets Manager client
	client := secretsmanager.NewFromConfig(cfg)

	// Retrieve the secret
	result, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve secret %s: %w", secretName, err)
	}

	// Parse the secret JSON
	var secret DBSecret
	if err := json.Unmarshal([]byte(*result.SecretString), &secret); err != nil {
		return nil, fmt.Errorf("failed to parse secret JSON: %w", err)
	}

	// Convert to Config
	dbConfig := &Config{
		Host:     secret.Host,
		Port:     secret.Port,
		User:     secret.Username,
		Password: secret.Password,
		Database: secret.Database,
		SSLMode:  "require",
	}

	// Validate the configuration
	if err := dbConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}

	return dbConfig, nil
}
