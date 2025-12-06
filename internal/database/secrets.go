package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// DBSecret represents the structure of database credentials in Secrets Manager
type DBSecret struct {
	Host     string   `json:"host"`
	Port     PortType `json:"port"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	Database string   `json:"dbname"`
}

// PortType handles JSON port values that can be either string or int
type PortType int

// UnmarshalJSON handles both string and int port values from JSON
func (p *PortType) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as int first
	var intVal int
	if err := json.Unmarshal(data, &intVal); err == nil {
		*p = PortType(intVal)
		return nil
	}

	// Try to unmarshal as string
	var strVal string
	if err := json.Unmarshal(data, &strVal); err == nil {
		intVal, err := strconv.Atoi(strVal)
		if err != nil {
			return fmt.Errorf("port string %q is not a valid integer: %w", strVal, err)
		}
		*p = PortType(intVal)
		return nil
	}

	return fmt.Errorf("port must be a string or integer, got: %s", string(data))
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
		Port:     fmt.Sprintf("%d", secret.Port),
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
