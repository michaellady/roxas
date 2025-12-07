// Package main implements the budget circuit breaker Lambda.
// When triggered by SNS (at 200% budget), it disables all roxas-* Lambda functions
// by setting their reserved concurrent executions to 0.
//
// Recovery:
//
//	aws lambda delete-function-concurrency --function-name FUNCTION_NAME
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
)

// Response is the circuit breaker execution result
type Response struct {
	Status            string   `json:"status"`
	FunctionsDisabled []string `json:"functions_disabled"`
	FunctionsFailed   []string `json:"functions_failed"`
	TotalDisabled     int      `json:"total_disabled"`
	TotalFailed       int      `json:"total_failed"`
}

// LambdaClient interface for testing
type LambdaClient interface {
	ListFunctions(ctx context.Context, params *awslambda.ListFunctionsInput, optFns ...func(*awslambda.Options)) (*awslambda.ListFunctionsOutput, error)
	PutFunctionConcurrency(ctx context.Context, params *awslambda.PutFunctionConcurrencyInput, optFns ...func(*awslambda.Options)) (*awslambda.PutFunctionConcurrencyOutput, error)
}

var (
	functionPrefix = getEnv("FUNCTION_PREFIX", "roxas-")
	lambdaClient   LambdaClient
)

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func handler(ctx context.Context, snsEvent events.SNSEvent) (Response, error) {
	// Log the triggering event
	if len(snsEvent.Records) > 0 {
		log.Printf("Circuit breaker triggered by SNS: %s", snsEvent.Records[0].SNS.Message)
	}

	// Initialize AWS client if not set (allows injection for testing)
	if lambdaClient == nil {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return Response{Status: "error"}, fmt.Errorf("failed to load AWS config: %w", err)
		}
		lambdaClient = awslambda.NewFromConfig(cfg)
	}

	var functionsDisabled []string
	var functionsFailed []string

	// List all Lambda functions
	var nextMarker *string
	for {
		output, err := lambdaClient.ListFunctions(ctx, &awslambda.ListFunctionsInput{
			Marker: nextMarker,
		})
		if err != nil {
			return Response{Status: "error"}, fmt.Errorf("failed to list functions: %w", err)
		}

		for _, fn := range output.Functions {
			functionName := *fn.FunctionName

			// Skip functions that don't match our prefix
			if !strings.HasPrefix(functionName, functionPrefix) {
				continue
			}

			// Skip the circuit breaker itself to allow manual recovery
			if strings.Contains(strings.ToLower(functionName), "circuit-breaker") {
				log.Printf("Skipping circuit breaker function: %s", functionName)
				continue
			}

			// Disable function by setting concurrency to 0
			_, err := lambdaClient.PutFunctionConcurrency(ctx, &awslambda.PutFunctionConcurrencyInput{
				FunctionName:                 &functionName,
				ReservedConcurrentExecutions: ptr(int32(0)),
			})
			if err != nil {
				log.Printf("Failed to disable %s: %v", functionName, err)
				functionsFailed = append(functionsFailed, functionName)
				continue
			}

			log.Printf("Disabled function: %s", functionName)
			functionsDisabled = append(functionsDisabled, functionName)
		}

		nextMarker = output.NextMarker
		if nextMarker == nil {
			break
		}
	}

	result := Response{
		Status:            "circuit_breaker_activated",
		FunctionsDisabled: functionsDisabled,
		FunctionsFailed:   functionsFailed,
		TotalDisabled:     len(functionsDisabled),
		TotalFailed:       len(functionsFailed),
	}

	resultJSON, _ := json.Marshal(result)
	log.Printf("Circuit breaker complete: %s", string(resultJSON))

	return result, nil
}

func ptr(i int32) *int32 {
	return &i
}

func main() {
	lambda.Start(handler)
}
