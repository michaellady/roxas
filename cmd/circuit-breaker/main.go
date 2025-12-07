// Package main implements the budget circuit breaker Lambda.
// When triggered by SNS (at 200% budget), it performs a hard stop:
// 1. Disables all roxas-* Lambda functions (concurrency=0)
// 2. Stops all roxas-* RDS instances
// 3. Stops all roxas-* NAT instances (EC2 with specific tag)
//
// Recovery:
//
//	# Lambda functions:
//	aws lambda delete-function-concurrency --function-name FUNCTION_NAME
//
//	# RDS instances:
//	aws rds start-db-instance --db-instance-identifier INSTANCE_ID
//
//	# NAT instances:
//	aws ec2 start-instances --instance-ids INSTANCE_ID
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
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

// Response is the circuit breaker execution result
type Response struct {
	Status            string   `json:"status"`
	FunctionsDisabled []string `json:"functions_disabled"`
	FunctionsFailed   []string `json:"functions_failed"`
	RDSStopped        []string `json:"rds_stopped"`
	RDSFailed         []string `json:"rds_failed"`
	NATStopped        []string `json:"nat_stopped"`
	NATFailed         []string `json:"nat_failed"`
	TotalDisabled     int      `json:"total_disabled"`
	TotalFailed       int      `json:"total_failed"`
}

// LambdaClient interface for testing
type LambdaClient interface {
	ListFunctions(ctx context.Context, params *awslambda.ListFunctionsInput, optFns ...func(*awslambda.Options)) (*awslambda.ListFunctionsOutput, error)
	PutFunctionConcurrency(ctx context.Context, params *awslambda.PutFunctionConcurrencyInput, optFns ...func(*awslambda.Options)) (*awslambda.PutFunctionConcurrencyOutput, error)
}

// RDSClient interface for testing
type RDSClient interface {
	DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
	StopDBInstance(ctx context.Context, params *rds.StopDBInstanceInput, optFns ...func(*rds.Options)) (*rds.StopDBInstanceOutput, error)
}

// EC2Client interface for testing
type EC2Client interface {
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	StopInstances(ctx context.Context, params *ec2.StopInstancesInput, optFns ...func(*ec2.Options)) (*ec2.StopInstancesOutput, error)
}

var (
	functionPrefix = getEnv("FUNCTION_PREFIX", "roxas-")
	lambdaClient   LambdaClient
	rdsClient      RDSClient
	ec2Client      EC2Client
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

	// Initialize AWS clients if not set (allows injection for testing)
	if lambdaClient == nil || rdsClient == nil || ec2Client == nil {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return Response{Status: "error"}, fmt.Errorf("failed to load AWS config: %w", err)
		}
		if lambdaClient == nil {
			lambdaClient = awslambda.NewFromConfig(cfg)
		}
		if rdsClient == nil {
			rdsClient = rds.NewFromConfig(cfg)
		}
		if ec2Client == nil {
			ec2Client = ec2.NewFromConfig(cfg)
		}
	}

	var result Response
	result.Status = "circuit_breaker_activated"

	// Step 1: Disable Lambda functions
	log.Println("Step 1: Disabling Lambda functions...")
	result.FunctionsDisabled, result.FunctionsFailed = disableLambdaFunctions(ctx)

	// Step 2: Stop RDS instances
	log.Println("Step 2: Stopping RDS instances...")
	result.RDSStopped, result.RDSFailed = stopRDSInstances(ctx)

	// Step 3: Stop NAT instances
	log.Println("Step 3: Stopping NAT instances...")
	result.NATStopped, result.NATFailed = stopNATInstances(ctx)

	// Calculate totals
	result.TotalDisabled = len(result.FunctionsDisabled) + len(result.RDSStopped) + len(result.NATStopped)
	result.TotalFailed = len(result.FunctionsFailed) + len(result.RDSFailed) + len(result.NATFailed)

	resultJSON, _ := json.Marshal(result)
	log.Printf("Circuit breaker complete: %s", string(resultJSON))

	return result, nil
}

// disableLambdaFunctions sets concurrency=0 on all roxas-* Lambda functions
func disableLambdaFunctions(ctx context.Context) (disabled, failed []string) {
	var nextMarker *string
	for {
		output, err := lambdaClient.ListFunctions(ctx, &awslambda.ListFunctionsInput{
			Marker: nextMarker,
		})
		if err != nil {
			log.Printf("Failed to list Lambda functions: %v", err)
			return disabled, failed
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
				log.Printf("Failed to disable Lambda %s: %v", functionName, err)
				failed = append(failed, functionName)
				continue
			}

			log.Printf("Disabled Lambda: %s", functionName)
			disabled = append(disabled, functionName)
		}

		nextMarker = output.NextMarker
		if nextMarker == nil {
			break
		}
	}
	return disabled, failed
}

// stopRDSInstances stops all roxas-* RDS instances
func stopRDSInstances(ctx context.Context) (stopped, failed []string) {
	output, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		log.Printf("Failed to list RDS instances: %v", err)
		return stopped, failed
	}

	for _, db := range output.DBInstances {
		dbID := *db.DBInstanceIdentifier

		// Skip instances that don't match our prefix
		if !strings.HasPrefix(dbID, functionPrefix) {
			continue
		}

		// Skip if already stopped or stopping
		status := *db.DBInstanceStatus
		if status == "stopped" || status == "stopping" {
			log.Printf("RDS %s already %s, skipping", dbID, status)
			continue
		}

		// Can only stop instances that are "available"
		if status != "available" {
			log.Printf("RDS %s in state %s, cannot stop", dbID, status)
			failed = append(failed, fmt.Sprintf("%s (state: %s)", dbID, status))
			continue
		}

		// Stop the instance
		_, err := rdsClient.StopDBInstance(ctx, &rds.StopDBInstanceInput{
			DBInstanceIdentifier: &dbID,
		})
		if err != nil {
			log.Printf("Failed to stop RDS %s: %v", dbID, err)
			failed = append(failed, dbID)
			continue
		}

		log.Printf("Stopped RDS: %s", dbID)
		stopped = append(stopped, dbID)
	}
	return stopped, failed
}

// stopNATInstances stops all EC2 instances tagged as roxas NAT instances
func stopNATInstances(ctx context.Context) (stopped, failed []string) {
	// Find instances with Name tag starting with roxas- and containing "nat"
	output, err := ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("tag:Name"),
				Values: []string{"roxas-*"},
			},
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running"},
			},
		},
	})
	if err != nil {
		log.Printf("Failed to list EC2 instances: %v", err)
		return stopped, failed
	}

	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			instanceID := *instance.InstanceId

			// Check if this is a NAT instance by looking at tags
			isNAT := false
			instanceName := ""
			for _, tag := range instance.Tags {
				if *tag.Key == "Name" {
					instanceName = *tag.Value
					if strings.Contains(strings.ToLower(*tag.Value), "nat") {
						isNAT = true
					}
				}
			}

			if !isNAT {
				continue
			}

			// Stop the instance
			_, err := ec2Client.StopInstances(ctx, &ec2.StopInstancesInput{
				InstanceIds: []string{instanceID},
			})
			if err != nil {
				log.Printf("Failed to stop NAT instance %s (%s): %v", instanceID, instanceName, err)
				failed = append(failed, instanceID)
				continue
			}

			log.Printf("Stopped NAT instance: %s (%s)", instanceID, instanceName)
			stopped = append(stopped, instanceID)
		}
	}
	return stopped, failed
}

func ptr(i int32) *int32 {
	return &i
}

func main() {
	lambda.Start(handler)
}
