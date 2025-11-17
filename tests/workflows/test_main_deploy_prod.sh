#!/bin/bash
# Test script for main-deploy-prod.yml workflow
# Tests that the workflow is properly configured for prod deployment

set -e

WORKFLOW_FILE=".github/workflows/main-deploy-prod.yml"
FAILED=0

echo "Testing main-deploy-prod.yml workflow configuration..."
echo

# Test 1: Workflow file exists
echo "Test 1: Workflow file exists"
if [ -f "$WORKFLOW_FILE" ]; then
    echo "✓ PASS: Workflow file exists"
else
    echo "✗ FAIL: Workflow file not found"
    FAILED=1
fi
echo

# Test 2: Only triggers on push to main
echo "Test 2: Triggers only on push to main branch"
if grep -q "push:" "$WORKFLOW_FILE" && grep -A2 "push:" "$WORKFLOW_FILE" | grep -q "branches:" && grep -A3 "push:" "$WORKFLOW_FILE" | grep -q "main"; then
    # Check that it doesn't trigger on all branches
    if ! grep -A3 "push:" "$WORKFLOW_FILE" | grep -F "**" > /dev/null 2>&1; then
        echo "✓ PASS: Triggers only on main branch"
    else
        echo "✗ FAIL: Triggers on all branches (should be main only)"
        FAILED=1
    fi
else
    echo "✗ FAIL: Does not trigger on push to main"
    FAILED=1
fi
echo

# Test 3: Runs test suite
echo "Test 3: Runs full test suite"
if grep -q "make test" "$WORKFLOW_FILE" && grep -q "make test-int" "$WORKFLOW_FILE"; then
    echo "✓ PASS: Runs unit and integration tests"
else
    echo "✗ FAIL: Does not run full test suite"
    FAILED=1
fi
echo

# Test 4: Uses prod environment
echo "Test 4: Uses prod environment and credentials"
if grep -q "environment: prod" "$WORKFLOW_FILE"; then
    echo "✓ PASS: Uses prod environment"
else
    echo "✗ FAIL: Does not use prod environment"
    FAILED=1
fi
echo

# Test 5: Uses prod backend configuration
echo "Test 5: Uses prod terraform backend"
if grep -q "backend-prod.hcl" "$WORKFLOW_FILE"; then
    echo "✓ PASS: Uses prod terraform backend"
else
    echo "✗ FAIL: Does not use prod terraform backend"
    FAILED=1
fi
echo

# Test 6: Has prod workspace or environment var
echo "Test 6: Targets prod workspace/environment"
if grep -q "TF_VAR_environment: prod" "$WORKFLOW_FILE" || grep -q "workspace select prod" "$WORKFLOW_FILE"; then
    echo "✓ PASS: Targets prod environment"
else
    echo "✗ FAIL: Does not target prod environment"
    FAILED=1
fi
echo

# Test 7: Has function name for prod (no PR number)
echo "Test 7: Uses prod function name (not PR-specific)"
if grep -q "TF_VAR_function_name:" "$WORKFLOW_FILE"; then
    # Should NOT contain PR number variable
    if ! grep "TF_VAR_function_name:" "$WORKFLOW_FILE" | grep -q "github.event.pull_request.number"; then
        echo "✓ PASS: Uses prod function name"
    else
        echo "✗ FAIL: Function name contains PR reference"
        FAILED=1
    fi
else
    echo "✗ FAIL: Does not set function name"
    FAILED=1
fi
echo

# Summary
echo "================================"
if [ $FAILED -eq 0 ]; then
    echo "✓ ALL TESTS PASSED"
    exit 0
else
    echo "✗ SOME TESTS FAILED"
    exit 1
fi
