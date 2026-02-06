package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
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

// =============================================================================
// EC2 Mock for ENI/Security Group cleanup tests
// =============================================================================

// MockEC2Client implements EC2Client for testing
type MockEC2Client struct {
	DescribeNetworkInterfacesFunc func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	DeleteNetworkInterfaceFunc    func(ctx context.Context, params *ec2.DeleteNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error)
	DescribeSecurityGroupsFunc    func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DeleteSecurityGroupFunc       func(ctx context.Context, params *ec2.DeleteSecurityGroupInput, optFns ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error)
}

func (m *MockEC2Client) DescribeNetworkInterfaces(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	if m.DescribeNetworkInterfacesFunc != nil {
		return m.DescribeNetworkInterfacesFunc(ctx, params, optFns...)
	}
	return &ec2.DescribeNetworkInterfacesOutput{}, nil
}

func (m *MockEC2Client) DeleteNetworkInterface(ctx context.Context, params *ec2.DeleteNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error) {
	if m.DeleteNetworkInterfaceFunc != nil {
		return m.DeleteNetworkInterfaceFunc(ctx, params, optFns...)
	}
	return &ec2.DeleteNetworkInterfaceOutput{}, nil
}

func (m *MockEC2Client) DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if m.DescribeSecurityGroupsFunc != nil {
		return m.DescribeSecurityGroupsFunc(ctx, params, optFns...)
	}
	return &ec2.DescribeSecurityGroupsOutput{}, nil
}

func (m *MockEC2Client) DeleteSecurityGroup(ctx context.Context, params *ec2.DeleteSecurityGroupInput, optFns ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error) {
	if m.DeleteSecurityGroupFunc != nil {
		return m.DeleteSecurityGroupFunc(ctx, params, optFns...)
	}
	return &ec2.DeleteSecurityGroupOutput{}, nil
}

// =============================================================================
// ENI Cleanup Tests (RED - these will fail until implemented)
// =============================================================================

func TestHandler_CleanupENIs_Success(t *testing.T) {
	ctx := context.Background()

	deletedENIs := []string{}
	ec2Client = &MockEC2Client{
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			// Return 2 available ENIs for PR 45
			return &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: []types.NetworkInterface{
					{
						NetworkInterfaceId: aws.String("eni-111111111"),
						Status:             types.NetworkInterfaceStatusAvailable,
						Description:        aws.String("AWS Lambda VPC ENI-roxas-webhook-handler-pr-45-dev"),
					},
					{
						NetworkInterfaceId: aws.String("eni-222222222"),
						Status:             types.NetworkInterfaceStatusAvailable,
						Description:        aws.String("AWS Lambda VPC ENI-roxas-webhook-handler-pr-45-dev"),
					},
				},
			}, nil
		},
		DeleteNetworkInterfaceFunc: func(ctx context.Context, params *ec2.DeleteNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error) {
			deletedENIs = append(deletedENIs, *params.NetworkInterfaceId)
			return &ec2.DeleteNetworkInterfaceOutput{}, nil
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 45, Action: "cleanup_enis"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d: %s", resp.StatusCode, resp.Body.Message)
	}
	if resp.Body.Action != "enis_cleaned" {
		t.Errorf("expected action 'enis_cleaned', got %q", resp.Body.Action)
	}
	if len(deletedENIs) != 2 {
		t.Errorf("expected 2 ENIs deleted, got %d", len(deletedENIs))
	}
}

func TestHandler_CleanupENIs_NoOrphanedENIs(t *testing.T) {
	ctx := context.Background()

	ec2Client = &MockEC2Client{
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			// Return empty - no ENIs found
			return &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: []types.NetworkInterface{},
			}, nil
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 99, Action: "cleanup_enis"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if resp.Body.Action != "enis_cleaned" {
		t.Errorf("expected action 'enis_cleaned', got %q", resp.Body.Action)
	}
}

func TestHandler_CleanupENIs_SkipsInUseENIs(t *testing.T) {
	ctx := context.Background()

	deletedENIs := []string{}
	ec2Client = &MockEC2Client{
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			// Return 1 available and 1 in-use ENI
			return &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: []types.NetworkInterface{
					{
						NetworkInterfaceId: aws.String("eni-available"),
						Status:             types.NetworkInterfaceStatusAvailable,
						Description:        aws.String("AWS Lambda VPC ENI-roxas-webhook-handler-pr-45-dev"),
					},
					{
						NetworkInterfaceId: aws.String("eni-inuse"),
						Status:             types.NetworkInterfaceStatusInUse,
						Description:        aws.String("AWS Lambda VPC ENI-roxas-webhook-handler-pr-45-dev"),
					},
				},
			}, nil
		},
		DeleteNetworkInterfaceFunc: func(ctx context.Context, params *ec2.DeleteNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error) {
			deletedENIs = append(deletedENIs, *params.NetworkInterfaceId)
			return &ec2.DeleteNetworkInterfaceOutput{}, nil
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 45, Action: "cleanup_enis"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	// Should only delete the available one
	if len(deletedENIs) != 1 {
		t.Errorf("expected 1 ENI deleted, got %d", len(deletedENIs))
	}
	if len(deletedENIs) > 0 && deletedENIs[0] != "eni-available" {
		t.Errorf("expected eni-available to be deleted, got %s", deletedENIs[0])
	}
}

// =============================================================================
// Security Group Cleanup Tests (RED - these will fail until implemented)
// =============================================================================

func TestHandler_CleanupSGs_Success(t *testing.T) {
	ctx := context.Background()

	deletedSGs := []string{}
	ec2Client = &MockEC2Client{
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			// No ENIs using this security group
			return &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: []types.NetworkInterface{},
			}, nil
		},
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []types.SecurityGroup{
					{
						GroupId:   aws.String("sg-orphaned"),
						GroupName: aws.String("roxas-webhook-handler-pr-45-dev-lambda"),
						VpcId:     aws.String("vpc-123"),
					},
				},
			}, nil
		},
		DeleteSecurityGroupFunc: func(ctx context.Context, params *ec2.DeleteSecurityGroupInput, optFns ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error) {
			deletedSGs = append(deletedSGs, *params.GroupId)
			return &ec2.DeleteSecurityGroupOutput{}, nil
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 45, Action: "cleanup_sgs"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d: %s", resp.StatusCode, resp.Body.Message)
	}
	if resp.Body.Action != "sgs_cleaned" {
		t.Errorf("expected action 'sgs_cleaned', got %q", resp.Body.Action)
	}
	if len(deletedSGs) != 1 {
		t.Errorf("expected 1 SG deleted, got %d", len(deletedSGs))
	}
}

func TestHandler_CleanupSGs_SkipsSGsWithENIs(t *testing.T) {
	ctx := context.Background()

	deletedSGs := []string{}
	ec2Client = &MockEC2Client{
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			// ENI still using this security group
			return &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: []types.NetworkInterface{
					{
						NetworkInterfaceId: aws.String("eni-still-attached"),
						Status:             types.NetworkInterfaceStatusInUse,
					},
				},
			}, nil
		},
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []types.SecurityGroup{
					{
						GroupId:   aws.String("sg-in-use"),
						GroupName: aws.String("roxas-webhook-handler-pr-45-dev-lambda"),
						VpcId:     aws.String("vpc-123"),
					},
				},
			}, nil
		},
		DeleteSecurityGroupFunc: func(ctx context.Context, params *ec2.DeleteSecurityGroupInput, optFns ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error) {
			deletedSGs = append(deletedSGs, *params.GroupId)
			return &ec2.DeleteSecurityGroupOutput{}, nil
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 45, Action: "cleanup_sgs"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	// Should NOT delete the SG because it has ENIs
	if len(deletedSGs) != 0 {
		t.Errorf("expected 0 SGs deleted (in use), got %d", len(deletedSGs))
	}
}

// =============================================================================
// Full Cleanup Test (cleanup_all = ENIs + SGs)
// =============================================================================

func TestHandler_CleanupAll_Success(t *testing.T) {
	ctx := context.Background()

	deletedENIs := []string{}
	deletedSGs := []string{}
	describeENIsCalls := 0

	ec2Client = &MockEC2Client{
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			describeENIsCalls++
			if describeENIsCalls == 1 {
				// First call: return ENIs for cleanup
				return &ec2.DescribeNetworkInterfacesOutput{
					NetworkInterfaces: []types.NetworkInterface{
						{
							NetworkInterfaceId: aws.String("eni-cleanup"),
							Status:             types.NetworkInterfaceStatusAvailable,
							Description:        aws.String("AWS Lambda VPC ENI-roxas-webhook-handler-pr-45-dev"),
						},
					},
				}, nil
			}
			// Subsequent calls: no ENIs (for SG dependency check)
			return &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: []types.NetworkInterface{},
			}, nil
		},
		DeleteNetworkInterfaceFunc: func(ctx context.Context, params *ec2.DeleteNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error) {
			deletedENIs = append(deletedENIs, *params.NetworkInterfaceId)
			return &ec2.DeleteNetworkInterfaceOutput{}, nil
		},
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []types.SecurityGroup{
					{
						GroupId:   aws.String("sg-cleanup"),
						GroupName: aws.String("roxas-webhook-handler-pr-45-dev-lambda"),
						VpcId:     aws.String("vpc-123"),
					},
				},
			}, nil
		},
		DeleteSecurityGroupFunc: func(ctx context.Context, params *ec2.DeleteSecurityGroupInput, optFns ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error) {
			deletedSGs = append(deletedSGs, *params.GroupId)
			return &ec2.DeleteSecurityGroupOutput{}, nil
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 45, Action: "cleanup_all"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d: %s", resp.StatusCode, resp.Body.Message)
	}
	if resp.Body.Action != "all_cleaned" {
		t.Errorf("expected action 'all_cleaned', got %q", resp.Body.Action)
	}
	if len(deletedENIs) != 1 {
		t.Errorf("expected 1 ENI deleted, got %d", len(deletedENIs))
	}
	if len(deletedSGs) != 1 {
		t.Errorf("expected 1 SG deleted, got %d", len(deletedSGs))
	}
}

// =============================================================================
// Orphaned ENI Cleanup Tests (cleanup_orphaned_enis - scheduled daily)
// =============================================================================

func TestHandler_CleanupOrphanedENIs_Success(t *testing.T) {
	ctx := context.Background()

	deletedENIs := []string{}
	ec2Client = &MockEC2Client{
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			// Return multiple orphaned ENIs from different PRs
			return &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: []types.NetworkInterface{
					{
						NetworkInterfaceId: aws.String("eni-pr-50-orphan"),
						Status:             types.NetworkInterfaceStatusAvailable,
						Description:        aws.String("AWS Lambda VPC ENI-roxas-webhook-handler-pr-50-dev"),
					},
					{
						NetworkInterfaceId: aws.String("eni-pr-51-orphan"),
						Status:             types.NetworkInterfaceStatusAvailable,
						Description:        aws.String("AWS Lambda VPC ENI-roxas-webhook-handler-pr-51-dev"),
					},
					{
						NetworkInterfaceId: aws.String("eni-pr-52-orphan"),
						Status:             types.NetworkInterfaceStatusAvailable,
						Description:        aws.String("AWS Lambda VPC ENI-roxas-webhook-handler-pr-52-dev"),
					},
				},
			}, nil
		},
		DeleteNetworkInterfaceFunc: func(ctx context.Context, params *ec2.DeleteNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error) {
			deletedENIs = append(deletedENIs, *params.NetworkInterfaceId)
			return &ec2.DeleteNetworkInterfaceOutput{}, nil
		},
	}
	defer func() { ec2Client = nil }()

	// Note: pr_number=0 is allowed for cleanup_orphaned_enis
	resp, err := handler(ctx, Request{PRNumber: 0, Action: "cleanup_orphaned_enis"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d: %s", resp.StatusCode, resp.Body.Message)
	}
	if resp.Body.Action != "orphaned_enis_cleaned" {
		t.Errorf("expected action 'orphaned_enis_cleaned', got %q", resp.Body.Action)
	}
	if len(deletedENIs) != 3 {
		t.Errorf("expected 3 ENIs deleted, got %d", len(deletedENIs))
	}
}

func TestHandler_CleanupOrphanedENIs_SkipsInUse(t *testing.T) {
	ctx := context.Background()

	deletedENIs := []string{}
	ec2Client = &MockEC2Client{
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			// Return mix of available and in-use ENIs
			return &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: []types.NetworkInterface{
					{
						NetworkInterfaceId: aws.String("eni-orphan"),
						Status:             types.NetworkInterfaceStatusAvailable,
						Description:        aws.String("AWS Lambda VPC ENI-roxas-webhook-handler-pr-50-dev"),
					},
					{
						NetworkInterfaceId: aws.String("eni-active"),
						Status:             types.NetworkInterfaceStatusInUse,
						Description:        aws.String("AWS Lambda VPC ENI-roxas-webhook-handler-pr-74-dev"),
					},
				},
			}, nil
		},
		DeleteNetworkInterfaceFunc: func(ctx context.Context, params *ec2.DeleteNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error) {
			deletedENIs = append(deletedENIs, *params.NetworkInterfaceId)
			return &ec2.DeleteNetworkInterfaceOutput{}, nil
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 0, Action: "cleanup_orphaned_enis"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	// Should only delete the available ENI, skip the in-use one
	if len(deletedENIs) != 1 {
		t.Errorf("expected 1 ENI deleted (skipping in-use), got %d", len(deletedENIs))
	}
	if len(deletedENIs) > 0 && deletedENIs[0] != "eni-orphan" {
		t.Errorf("expected eni-orphan to be deleted, got %s", deletedENIs[0])
	}
}

// =============================================================================
// Additional Coverage Tests
// =============================================================================

func TestHandler_CleanupENIs_DescribeError(t *testing.T) {
	ctx := context.Background()

	ec2Client = &MockEC2Client{
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			return nil, errors.New("ec2 describe error")
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 45, Action: "cleanup_enis"})
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

func TestHandler_CleanupENIs_DeleteError(t *testing.T) {
	ctx := context.Background()

	ec2Client = &MockEC2Client{
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			return &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: []types.NetworkInterface{
					{
						NetworkInterfaceId: aws.String("eni-fail"),
						Status:             types.NetworkInterfaceStatusAvailable,
						Description:        aws.String("AWS Lambda VPC ENI-roxas-webhook-handler-pr-45-dev"),
					},
				},
			}, nil
		},
		DeleteNetworkInterfaceFunc: func(ctx context.Context, params *ec2.DeleteNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error) {
			return nil, errors.New("delete failed")
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 45, Action: "cleanup_enis"})
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

func TestHandler_CleanupSGs_DescribeError(t *testing.T) {
	ctx := context.Background()

	ec2Client = &MockEC2Client{
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return nil, errors.New("sg describe error")
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 45, Action: "cleanup_sgs"})
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

func TestHandler_CleanupSGs_ENICheckError(t *testing.T) {
	ctx := context.Background()

	ec2Client = &MockEC2Client{
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []types.SecurityGroup{
					{
						GroupId:   aws.String("sg-test"),
						GroupName: aws.String("roxas-webhook-handler-pr-45-dev-lambda"),
						VpcId:     aws.String("vpc-123"),
					},
				},
			}, nil
		},
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			return nil, errors.New("eni check error")
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 45, Action: "cleanup_sgs"})
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

func TestHandler_CleanupSGs_DeleteError(t *testing.T) {
	ctx := context.Background()

	ec2Client = &MockEC2Client{
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []types.SecurityGroup{
					{
						GroupId:   aws.String("sg-del-err"),
						GroupName: aws.String("roxas-webhook-handler-pr-45-dev-lambda"),
						VpcId:     aws.String("vpc-123"),
					},
				},
			}, nil
		},
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			// No ENIs using this SG
			return &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: []types.NetworkInterface{},
			}, nil
		},
		DeleteSecurityGroupFunc: func(ctx context.Context, params *ec2.DeleteSecurityGroupInput, optFns ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error) {
			return nil, errors.New("delete sg failed")
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 45, Action: "cleanup_sgs"})
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

func TestHandler_CleanupAll_ENIFailure(t *testing.T) {
	ctx := context.Background()

	ec2Client = &MockEC2Client{
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			return nil, errors.New("eni describe error")
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 45, Action: "cleanup_all"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// cleanup_all should fail if ENI cleanup fails
	if resp.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}
	if resp.Body.Action != "error" {
		t.Errorf("expected action 'error', got %q", resp.Body.Action)
	}
}

func TestHandler_CleanupAll_SGFailure(t *testing.T) {
	ctx := context.Background()

	describeENIsCalls := 0
	ec2Client = &MockEC2Client{
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			describeENIsCalls++
			// First call for ENI cleanup succeeds with no ENIs
			return &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: []types.NetworkInterface{},
			}, nil
		},
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return nil, errors.New("sg describe error")
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 45, Action: "cleanup_all"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// cleanup_all should fail if SG cleanup fails
	if resp.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}
}

func TestHandler_CleanupOrphanedENIs_DescribeError(t *testing.T) {
	ctx := context.Background()

	ec2Client = &MockEC2Client{
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			return nil, errors.New("describe error")
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 0, Action: "cleanup_orphaned_enis"})
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

func TestHandler_CleanupOrphanedENIs_DeleteError(t *testing.T) {
	ctx := context.Background()

	ec2Client = &MockEC2Client{
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			return &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: []types.NetworkInterface{
					{
						NetworkInterfaceId: aws.String("eni-orphan-fail"),
						Status:             types.NetworkInterfaceStatusAvailable,
						Description:        aws.String("AWS Lambda VPC ENI-roxas-webhook-pr-50"),
					},
				},
			}, nil
		},
		DeleteNetworkInterfaceFunc: func(ctx context.Context, params *ec2.DeleteNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error) {
			return nil, errors.New("delete error")
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 0, Action: "cleanup_orphaned_enis"})
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

func TestHandler_CleanupOrphanedENIs_WithPagination(t *testing.T) {
	ctx := context.Background()

	deletedENIs := []string{}
	callCount := 0
	ec2Client = &MockEC2Client{
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			callCount++
			if callCount == 1 {
				nextToken := "page2"
				return &ec2.DescribeNetworkInterfacesOutput{
					NetworkInterfaces: []types.NetworkInterface{
						{
							NetworkInterfaceId: aws.String("eni-page1"),
							Status:             types.NetworkInterfaceStatusAvailable,
							Description:        aws.String("AWS Lambda VPC ENI-roxas-pr-1"),
						},
					},
					NextToken: &nextToken,
				}, nil
			}
			// Second page - no more pages
			return &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: []types.NetworkInterface{
					{
						NetworkInterfaceId: aws.String("eni-page2"),
						Status:             types.NetworkInterfaceStatusAvailable,
						Description:        aws.String("AWS Lambda VPC ENI-roxas-pr-2"),
					},
				},
			}, nil
		},
		DeleteNetworkInterfaceFunc: func(ctx context.Context, params *ec2.DeleteNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error) {
			deletedENIs = append(deletedENIs, *params.NetworkInterfaceId)
			return &ec2.DeleteNetworkInterfaceOutput{}, nil
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 0, Action: "cleanup_orphaned_enis"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d: %s", resp.StatusCode, resp.Body.Message)
	}
	if len(deletedENIs) != 2 {
		t.Errorf("expected 2 ENIs deleted across pages, got %d", len(deletedENIs))
	}
	if callCount != 2 {
		t.Errorf("expected 2 describe calls (pagination), got %d", callCount)
	}
}

func TestHandler_CleanupOrphanedENIs_NilDescription(t *testing.T) {
	ctx := context.Background()

	deletedENIs := []string{}
	ec2Client = &MockEC2Client{
		DescribeNetworkInterfacesFunc: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			return &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: []types.NetworkInterface{
					{
						NetworkInterfaceId: aws.String("eni-nil-desc"),
						Status:             types.NetworkInterfaceStatusAvailable,
						Description:        nil,
					},
				},
			}, nil
		},
		DeleteNetworkInterfaceFunc: func(ctx context.Context, params *ec2.DeleteNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error) {
			deletedENIs = append(deletedENIs, *params.NetworkInterfaceId)
			return &ec2.DeleteNetworkInterfaceOutput{}, nil
		},
	}
	defer func() { ec2Client = nil }()

	resp, err := handler(ctx, Request{PRNumber: 0, Action: "cleanup_orphaned_enis"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if len(deletedENIs) != 1 {
		t.Errorf("expected 1 ENI deleted, got %d", len(deletedENIs))
	}
}

func TestHandler_QueryError(t *testing.T) {
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
			return nil, errors.New("query error")
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

func TestHandler_InvalidCredentialsJSON(t *testing.T) {
	ctx := context.Background()
	t.Setenv("DB_SECRET_NAME", "test-secret")

	invalidJSON := "not-valid-json"
	smClient = &MockSecretsManagerClient{
		GetSecretValueFunc: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{SecretString: &invalidJSON}, nil
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
