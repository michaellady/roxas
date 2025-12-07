package main

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// MockLambdaClient implements LambdaClient for testing
type MockLambdaClient struct {
	Functions         []types.FunctionConfiguration
	PutConcurrencyErr map[string]error // function name -> error
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

func strPtr(s string) *string {
	return &s
}

func TestHandler_DisablesMatchingFunctions(t *testing.T) {
	mock := &MockLambdaClient{
		Functions: []types.FunctionConfiguration{
			{FunctionName: strPtr("roxas-webhook-handler")},
			{FunctionName: strPtr("roxas-cleanup")},
			{FunctionName: strPtr("other-function")},
		},
	}
	lambdaClient = mock

	event := events.SNSEvent{
		Records: []events.SNSEventRecord{
			{SNS: events.SNSEntity{Message: `{"test": true}`}},
		},
	}

	result, err := handler(context.Background(), event)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if result.TotalDisabled != 2 {
		t.Errorf("expected 2 functions disabled, got %d", result.TotalDisabled)
	}

	if len(mock.PutConcurrencyCalls) != 2 {
		t.Errorf("expected 2 PutFunctionConcurrency calls, got %d", len(mock.PutConcurrencyCalls))
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
	mock := &MockLambdaClient{
		Functions: []types.FunctionConfiguration{
			{FunctionName: strPtr("roxas-dev-circuit-breaker")},
			{FunctionName: strPtr("roxas-prod-circuit-breaker")},
		},
	}
	lambdaClient = mock

	event := events.SNSEvent{}

	result, err := handler(context.Background(), event)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if result.TotalDisabled != 0 {
		t.Errorf("expected 0 functions disabled, got %d", result.TotalDisabled)
	}

	if len(mock.PutConcurrencyCalls) != 0 {
		t.Errorf("expected 0 PutFunctionConcurrency calls, got %d", len(mock.PutConcurrencyCalls))
	}
}

func TestHandler_HandlesAPIErrors(t *testing.T) {
	mock := &MockLambdaClient{
		Functions: []types.FunctionConfiguration{
			{FunctionName: strPtr("roxas-function-1")},
			{FunctionName: strPtr("roxas-function-2")},
		},
		PutConcurrencyErr: map[string]error{
			"roxas-function-2": errors.New("access denied"),
		},
	}
	lambdaClient = mock

	event := events.SNSEvent{}

	result, err := handler(context.Background(), event)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if result.TotalDisabled != 1 {
		t.Errorf("expected 1 function disabled, got %d", result.TotalDisabled)
	}

	if result.TotalFailed != 1 {
		t.Errorf("expected 1 function failed, got %d", result.TotalFailed)
	}
}

func TestHandler_EmptyFunctionList(t *testing.T) {
	mock := &MockLambdaClient{
		Functions: []types.FunctionConfiguration{},
	}
	lambdaClient = mock

	event := events.SNSEvent{}

	result, err := handler(context.Background(), event)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if result.Status != "circuit_breaker_activated" {
		t.Errorf("expected status 'circuit_breaker_activated', got %q", result.Status)
	}

	if result.TotalDisabled != 0 {
		t.Errorf("expected 0 functions disabled, got %d", result.TotalDisabled)
	}
}
