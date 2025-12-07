package main

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// MockLambdaClient implements LambdaClient for testing
type MockLambdaClient struct {
	Functions           []lambdatypes.FunctionConfiguration
	PutConcurrencyErr   map[string]error
	PutConcurrencyCalls []string
}

func (m *MockLambdaClient) ListFunctions(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return &lambda.ListFunctionsOutput{
		Functions: m.Functions,
	}, nil
}

func (m *MockLambdaClient) PutFunctionConcurrency(ctx context.Context, params *lambda.PutFunctionConcurrencyInput, optFns ...func(*lambda.Options)) (*lambda.PutFunctionConcurrencyOutput, error) {
	name := *params.FunctionName
	m.PutConcurrencyCalls = append(m.PutConcurrencyCalls, name)

	if m.PutConcurrencyErr != nil {
		if err, ok := m.PutConcurrencyErr[name]; ok {
			return nil, err
		}
	}
	return &lambda.PutFunctionConcurrencyOutput{}, nil
}

// MockRDSClient implements RDSClient for testing
type MockRDSClient struct {
	Instances    []rdstypes.DBInstance
	StopErr      map[string]error
	StopCalls    []string
}

func (m *MockRDSClient) DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{
		DBInstances: m.Instances,
	}, nil
}

func (m *MockRDSClient) StopDBInstance(ctx context.Context, params *rds.StopDBInstanceInput, optFns ...func(*rds.Options)) (*rds.StopDBInstanceOutput, error) {
	id := *params.DBInstanceIdentifier
	m.StopCalls = append(m.StopCalls, id)

	if m.StopErr != nil {
		if err, ok := m.StopErr[id]; ok {
			return nil, err
		}
	}
	return &rds.StopDBInstanceOutput{}, nil
}

// MockEC2Client implements EC2Client for testing
type MockEC2Client struct {
	Instances []ec2types.Instance
	StopErr   map[string]error
	StopCalls []string
}

func (m *MockEC2Client) DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{
		Reservations: []ec2types.Reservation{
			{Instances: m.Instances},
		},
	}, nil
}

func (m *MockEC2Client) StopInstances(ctx context.Context, params *ec2.StopInstancesInput, optFns ...func(*ec2.Options)) (*ec2.StopInstancesOutput, error) {
	for _, id := range params.InstanceIds {
		m.StopCalls = append(m.StopCalls, id)
		if m.StopErr != nil {
			if err, ok := m.StopErr[id]; ok {
				return nil, err
			}
		}
	}
	return &ec2.StopInstancesOutput{}, nil
}

func TestHandler_DisablesMatchingFunctions(t *testing.T) {
	mockLambda := &MockLambdaClient{
		Functions: []lambdatypes.FunctionConfiguration{
			{FunctionName: aws.String("roxas-webhook-handler")},
			{FunctionName: aws.String("roxas-cleanup")},
			{FunctionName: aws.String("other-function")},
		},
	}
	mockRDS := &MockRDSClient{}
	mockEC2 := &MockEC2Client{}

	lambdaClient = mockLambda
	rdsClient = mockRDS
	ec2Client = mockEC2

	event := events.SNSEvent{
		Records: []events.SNSEventRecord{
			{SNS: events.SNSEntity{Message: `{"test": true}`}},
		},
	}

	result, err := handler(context.Background(), event)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if len(result.FunctionsDisabled) != 2 {
		t.Errorf("expected 2 functions disabled, got %d", len(result.FunctionsDisabled))
	}

	// Verify correct functions were disabled
	disabled := make(map[string]bool)
	for _, fn := range result.FunctionsDisabled {
		disabled[fn] = true
	}
	if !disabled["roxas-webhook-handler"] {
		t.Error("expected roxas-webhook-handler to be disabled")
	}
	if !disabled["roxas-cleanup"] {
		t.Error("expected roxas-cleanup to be disabled")
	}
}

func TestHandler_SkipsCircuitBreaker(t *testing.T) {
	mockLambda := &MockLambdaClient{
		Functions: []lambdatypes.FunctionConfiguration{
			{FunctionName: aws.String("roxas-dev-circuit-breaker")},
			{FunctionName: aws.String("roxas-prod-circuit-breaker")},
		},
	}
	mockRDS := &MockRDSClient{}
	mockEC2 := &MockEC2Client{}

	lambdaClient = mockLambda
	rdsClient = mockRDS
	ec2Client = mockEC2

	result, err := handler(context.Background(), events.SNSEvent{})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if len(result.FunctionsDisabled) != 0 {
		t.Errorf("expected 0 functions disabled, got %d", len(result.FunctionsDisabled))
	}
}

func TestHandler_StopsRDSInstances(t *testing.T) {
	mockLambda := &MockLambdaClient{}
	mockRDS := &MockRDSClient{
		Instances: []rdstypes.DBInstance{
			{DBInstanceIdentifier: aws.String("roxas-dev-db"), DBInstanceStatus: aws.String("available")},
			{DBInstanceIdentifier: aws.String("roxas-prod-db"), DBInstanceStatus: aws.String("available")},
			{DBInstanceIdentifier: aws.String("other-db"), DBInstanceStatus: aws.String("available")},
		},
	}
	mockEC2 := &MockEC2Client{}

	lambdaClient = mockLambda
	rdsClient = mockRDS
	ec2Client = mockEC2

	result, err := handler(context.Background(), events.SNSEvent{})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if len(result.RDSStopped) != 2 {
		t.Errorf("expected 2 RDS instances stopped, got %d: %v", len(result.RDSStopped), result.RDSStopped)
	}

	if len(mockRDS.StopCalls) != 2 {
		t.Errorf("expected 2 StopDBInstance calls, got %d", len(mockRDS.StopCalls))
	}
}

func TestHandler_SkipsAlreadyStoppedRDS(t *testing.T) {
	mockLambda := &MockLambdaClient{}
	mockRDS := &MockRDSClient{
		Instances: []rdstypes.DBInstance{
			{DBInstanceIdentifier: aws.String("roxas-dev-db"), DBInstanceStatus: aws.String("stopped")},
			{DBInstanceIdentifier: aws.String("roxas-prod-db"), DBInstanceStatus: aws.String("stopping")},
		},
	}
	mockEC2 := &MockEC2Client{}

	lambdaClient = mockLambda
	rdsClient = mockRDS
	ec2Client = mockEC2

	result, err := handler(context.Background(), events.SNSEvent{})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if len(result.RDSStopped) != 0 {
		t.Errorf("expected 0 RDS instances stopped, got %d", len(result.RDSStopped))
	}

	if len(mockRDS.StopCalls) != 0 {
		t.Errorf("expected 0 StopDBInstance calls, got %d", len(mockRDS.StopCalls))
	}
}

func TestHandler_StopsNATInstances(t *testing.T) {
	mockLambda := &MockLambdaClient{}
	mockRDS := &MockRDSClient{}
	mockEC2 := &MockEC2Client{
		Instances: []ec2types.Instance{
			{
				InstanceId: aws.String("i-nat123"),
				Tags: []ec2types.Tag{
					{Key: aws.String("Name"), Value: aws.String("roxas-dev-nat")},
				},
			},
			{
				InstanceId: aws.String("i-web456"),
				Tags: []ec2types.Tag{
					{Key: aws.String("Name"), Value: aws.String("roxas-dev-web")},
				},
			},
		},
	}

	lambdaClient = mockLambda
	rdsClient = mockRDS
	ec2Client = mockEC2

	result, err := handler(context.Background(), events.SNSEvent{})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	// Only NAT instance should be stopped
	if len(result.NATStopped) != 1 {
		t.Errorf("expected 1 NAT instance stopped, got %d: %v", len(result.NATStopped), result.NATStopped)
	}

	if len(mockEC2.StopCalls) != 1 {
		t.Errorf("expected 1 StopInstances call, got %d", len(mockEC2.StopCalls))
	}

	if mockEC2.StopCalls[0] != "i-nat123" {
		t.Errorf("expected i-nat123 to be stopped, got %s", mockEC2.StopCalls[0])
	}
}

func TestHandler_HandlesAPIErrors(t *testing.T) {
	mockLambda := &MockLambdaClient{
		Functions: []lambdatypes.FunctionConfiguration{
			{FunctionName: aws.String("roxas-function-1")},
			{FunctionName: aws.String("roxas-function-2")},
		},
		PutConcurrencyErr: map[string]error{
			"roxas-function-2": errors.New("access denied"),
		},
	}
	mockRDS := &MockRDSClient{
		Instances: []rdstypes.DBInstance{
			{DBInstanceIdentifier: aws.String("roxas-db-1"), DBInstanceStatus: aws.String("available")},
		},
		StopErr: map[string]error{
			"roxas-db-1": errors.New("insufficient permissions"),
		},
	}
	mockEC2 := &MockEC2Client{}

	lambdaClient = mockLambda
	rdsClient = mockRDS
	ec2Client = mockEC2

	result, err := handler(context.Background(), events.SNSEvent{})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if len(result.FunctionsDisabled) != 1 {
		t.Errorf("expected 1 function disabled, got %d", len(result.FunctionsDisabled))
	}

	if len(result.FunctionsFailed) != 1 {
		t.Errorf("expected 1 function failed, got %d", len(result.FunctionsFailed))
	}

	if len(result.RDSFailed) != 1 {
		t.Errorf("expected 1 RDS failed, got %d", len(result.RDSFailed))
	}
}

func TestHandler_CalculatesTotals(t *testing.T) {
	mockLambda := &MockLambdaClient{
		Functions: []lambdatypes.FunctionConfiguration{
			{FunctionName: aws.String("roxas-fn1")},
			{FunctionName: aws.String("roxas-fn2")},
		},
	}
	mockRDS := &MockRDSClient{
		Instances: []rdstypes.DBInstance{
			{DBInstanceIdentifier: aws.String("roxas-db"), DBInstanceStatus: aws.String("available")},
		},
	}
	mockEC2 := &MockEC2Client{
		Instances: []ec2types.Instance{
			{
				InstanceId: aws.String("i-nat"),
				Tags:       []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String("roxas-nat")}},
			},
		},
	}

	lambdaClient = mockLambda
	rdsClient = mockRDS
	ec2Client = mockEC2

	result, err := handler(context.Background(), events.SNSEvent{})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	// 2 lambdas + 1 RDS + 1 NAT = 4 total
	if result.TotalDisabled != 4 {
		t.Errorf("expected TotalDisabled=4, got %d", result.TotalDisabled)
	}

	if result.TotalFailed != 0 {
		t.Errorf("expected TotalFailed=0, got %d", result.TotalFailed)
	}
}
