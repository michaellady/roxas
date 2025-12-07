package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// MockSecretsManagerClient implements SecretsManagerClient for testing
type MockSecretsManagerClient struct {
	GetSecretValueFunc func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

func (m *MockSecretsManagerClient) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return m.GetSecretValueFunc(ctx, params, optFns...)
}

// MockDBConnector implements DBConnector for testing
type MockDBConnector struct {
	ConnectFunc func(ctx context.Context, connString string) (DBConn, error)
}

func (m *MockDBConnector) Connect(ctx context.Context, connString string) (DBConn, error) {
	return m.ConnectFunc(ctx, connString)
}

// MockDBConn implements DBConn for testing
type MockDBConn struct {
	QueryFunc func(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	ExecFunc  func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	CloseFunc func(ctx context.Context) error
}

func (m *MockDBConn) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return m.QueryFunc(ctx, sql, args...)
}

func (m *MockDBConn) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return m.ExecFunc(ctx, sql, args...)
}

func (m *MockDBConn) Close(ctx context.Context) error {
	if m.CloseFunc != nil {
		return m.CloseFunc(ctx)
	}
	return nil
}

// MockRows implements pgx.Rows for testing
type MockRows struct {
	hasNext bool
	closed  bool
}

func (m *MockRows) Next() bool {
	if m.hasNext && !m.closed {
		m.hasNext = false
		return true
	}
	return false
}

func (m *MockRows) Close()                                       { m.closed = true }
func (m *MockRows) Err() error                                   { return nil }
func (m *MockRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (m *MockRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (m *MockRows) Scan(dest ...any) error                       { return nil }
func (m *MockRows) Values() ([]any, error)                       { return nil, nil }
func (m *MockRows) RawValues() [][]byte                          { return nil }
func (m *MockRows) Conn() *pgx.Conn                              { return nil }

func TestHandler_MissingPRNumber(t *testing.T) {
	ctx := context.Background()

	resp, err := handler(ctx, Request{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 400 {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}
	if resp.Body.Action != "error" {
		t.Errorf("expected action 'error', got %q", resp.Body.Action)
	}
	if resp.Body.Message != "pr_number is required" {
		t.Errorf("unexpected message: %s", resp.Body.Message)
	}
}

func TestHandler_InvalidAction(t *testing.T) {
	ctx := context.Background()
	t.Setenv("DB_SECRET_NAME", "test-secret")

	creds := DBCredentials{Host: "localhost", Port: 5432, Username: "user", Password: "pass"}
	credsJSON, _ := json.Marshal(creds)
	secretStr := string(credsJSON)

	smClient = &MockSecretsManagerClient{
		GetSecretValueFunc: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{SecretString: &secretStr}, nil
		},
	}
	defer func() { smClient = nil }()

	resp, err := handler(ctx, Request{PRNumber: 123, Action: "invalid"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 400 {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}
	if resp.Body.Action != "error" {
		t.Errorf("expected action 'error', got %q", resp.Body.Action)
	}
}

func TestHandler_DatabaseDoesNotExist(t *testing.T) {
	ctx := context.Background()
	t.Setenv("DB_SECRET_NAME", "test-secret")

	creds := DBCredentials{Host: "localhost", Port: 5432, Username: "user", Password: "pass"}
	credsJSON, _ := json.Marshal(creds)
	secretStr := string(credsJSON)

	smClient = &MockSecretsManagerClient{
		GetSecretValueFunc: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{SecretString: &secretStr}, nil
		},
	}
	defer func() { smClient = nil }()

	mockConn := &MockDBConn{
		QueryFunc: func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
			return &MockRows{hasNext: false}, nil // Database doesn't exist
		},
		ExecFunc: func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
	}

	dbConnector = &MockDBConnector{
		ConnectFunc: func(ctx context.Context, connString string) (DBConn, error) {
			return mockConn, nil
		},
	}
	defer func() { dbConnector = &PgxConnector{} }()

	resp, err := handler(ctx, Request{PRNumber: 999, Action: "drop"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if resp.Body.Action != "skipped" {
		t.Errorf("expected action 'skipped', got %q", resp.Body.Action)
	}
	if resp.Body.Database != "pr_999" {
		t.Errorf("expected database 'pr_999', got %q", resp.Body.Database)
	}
}

func TestHandler_SuccessfulDrop(t *testing.T) {
	ctx := context.Background()
	t.Setenv("DB_SECRET_NAME", "test-secret")

	creds := DBCredentials{Host: "localhost", Port: 5432, Username: "user", Password: "pass"}
	credsJSON, _ := json.Marshal(creds)
	secretStr := string(credsJSON)

	smClient = &MockSecretsManagerClient{
		GetSecretValueFunc: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{SecretString: &secretStr}, nil
		},
	}
	defer func() { smClient = nil }()

	execCalls := 0
	mockConn := &MockDBConn{
		QueryFunc: func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
			return &MockRows{hasNext: true}, nil // Database exists
		},
		ExecFunc: func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			execCalls++
			return pgconn.CommandTag{}, nil
		},
	}

	dbConnector = &MockDBConnector{
		ConnectFunc: func(ctx context.Context, connString string) (DBConn, error) {
			return mockConn, nil
		},
	}
	defer func() { dbConnector = &PgxConnector{} }()

	resp, err := handler(ctx, Request{PRNumber: 42, Action: "drop"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if resp.Body.Action != "dropped" {
		t.Errorf("expected action 'dropped', got %q", resp.Body.Action)
	}
	if resp.Body.Database != "pr_42" {
		t.Errorf("expected database 'pr_42', got %q", resp.Body.Database)
	}
	if execCalls != 2 {
		t.Errorf("expected 2 exec calls (terminate + drop), got %d", execCalls)
	}
}

func TestHandler_DefaultAction(t *testing.T) {
	ctx := context.Background()
	t.Setenv("DB_SECRET_NAME", "test-secret")

	creds := DBCredentials{Host: "localhost", Port: 5432, Username: "user", Password: "pass"}
	credsJSON, _ := json.Marshal(creds)
	secretStr := string(credsJSON)

	smClient = &MockSecretsManagerClient{
		GetSecretValueFunc: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{SecretString: &secretStr}, nil
		},
	}
	defer func() { smClient = nil }()

	mockConn := &MockDBConn{
		QueryFunc: func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
			return &MockRows{hasNext: false}, nil
		},
		ExecFunc: func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
	}

	dbConnector = &MockDBConnector{
		ConnectFunc: func(ctx context.Context, connString string) (DBConn, error) {
			return mockConn, nil
		},
	}
	defer func() { dbConnector = &PgxConnector{} }()

	// No action specified - should default to "drop"
	resp, err := handler(ctx, Request{PRNumber: 123})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestHandler_SecretsManagerError(t *testing.T) {
	ctx := context.Background()
	t.Setenv("DB_SECRET_NAME", "test-secret")

	smClient = &MockSecretsManagerClient{
		GetSecretValueFunc: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return nil, errors.New("access denied")
		},
	}
	defer func() { smClient = nil }()

	resp, err := handler(ctx, Request{PRNumber: 123, Action: "drop"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}
	if resp.Body.Action != "error" {
		t.Errorf("expected action 'error', got %q", resp.Body.Action)
	}
}

func TestHandler_DBConnectionError(t *testing.T) {
	ctx := context.Background()
	t.Setenv("DB_SECRET_NAME", "test-secret")

	creds := DBCredentials{Host: "localhost", Port: 5432, Username: "user", Password: "pass"}
	credsJSON, _ := json.Marshal(creds)
	secretStr := string(credsJSON)

	smClient = &MockSecretsManagerClient{
		GetSecretValueFunc: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{SecretString: &secretStr}, nil
		},
	}
	defer func() { smClient = nil }()

	dbConnector = &MockDBConnector{
		ConnectFunc: func(ctx context.Context, connString string) (DBConn, error) {
			return nil, errors.New("connection refused")
		},
	}
	defer func() { dbConnector = &PgxConnector{} }()

	resp, err := handler(ctx, Request{PRNumber: 123, Action: "drop"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}
	if resp.Body.Action != "error" {
		t.Errorf("expected action 'error', got %q", resp.Body.Action)
	}
}

func TestHandler_DropDatabaseError(t *testing.T) {
	ctx := context.Background()
	t.Setenv("DB_SECRET_NAME", "test-secret")

	creds := DBCredentials{Host: "localhost", Port: 5432, Username: "user", Password: "pass"}
	credsJSON, _ := json.Marshal(creds)
	secretStr := string(credsJSON)

	smClient = &MockSecretsManagerClient{
		GetSecretValueFunc: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{SecretString: &secretStr}, nil
		},
	}
	defer func() { smClient = nil }()

	execCalls := 0
	mockConn := &MockDBConn{
		QueryFunc: func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
			return &MockRows{hasNext: true}, nil // Database exists
		},
		ExecFunc: func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			execCalls++
			if execCalls == 2 { // DROP DATABASE call
				return pgconn.CommandTag{}, errors.New("database in use")
			}
			return pgconn.CommandTag{}, nil
		},
	}

	dbConnector = &MockDBConnector{
		ConnectFunc: func(ctx context.Context, connString string) (DBConn, error) {
			return mockConn, nil
		},
	}
	defer func() { dbConnector = &PgxConnector{} }()

	resp, err := handler(ctx, Request{PRNumber: 123, Action: "drop"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}
	if resp.Body.Action != "error" {
		t.Errorf("expected action 'error', got %q", resp.Body.Action)
	}
}

func TestHandler_MissingDBSecretEnvVar(t *testing.T) {
	ctx := context.Background()
	// Don't set DB_SECRET_NAME

	creds := DBCredentials{Host: "localhost", Port: 5432, Username: "user", Password: "pass"}
	credsJSON, _ := json.Marshal(creds)
	secretStr := string(credsJSON)

	smClient = &MockSecretsManagerClient{
		GetSecretValueFunc: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{SecretString: &secretStr}, nil
		},
	}
	defer func() { smClient = nil }()

	resp, err := handler(ctx, Request{PRNumber: 123, Action: "drop"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}
	if resp.Body.Action != "error" {
		t.Errorf("expected action 'error', got %q", resp.Body.Action)
	}
}
