# IAM Permissions Setup for GitHub Actions

This document explains how to configure IAM permissions for the `github-actions-ci` user in the dev AWS account.

## Required Permissions

The `github-actions-ci` user needs permissions to:
1. Manage Terraform state (S3 and DynamoDB)
2. Create and manage Lambda functions
3. Create and manage IAM roles for Lambda execution
4. Create and manage API Gateway
5. Create and manage CloudWatch Log Groups

## Policy Files

### 1. `iam-policy-backend.json`
Backend-only permissions for S3 and DynamoDB state management.
- For both dev and prod accounts
- Minimal permissions for state access only

### 2. `iam-policy-github-actions-ci.json` (Comprehensive)
**Complete permissions for dev account (539402214167)**

Includes:
- Terraform backend (S3 + DynamoDB)
- IAM role management (create/delete Lambda execution roles)
- Lambda function management (create/update/delete functions)
- API Gateway management (HTTP APIs)
- CloudWatch Logs management (log groups)

## How to Apply the Policy

### Option 1: AWS Console (Recommended for initial setup)

1. **Log in to AWS Console**
   - Account: 539402214167 (dev)
   - Use admin credentials

2. **Navigate to IAM**
   - Go to IAM → Users → github-actions-ci

3. **Create Inline Policy**
   - Click "Add permissions" → "Create inline policy"
   - Click "JSON" tab
   - Copy contents of `iam-policy-github-actions-ci.json`
   - Paste into editor
   - Click "Review policy"
   - Name: `RoxasGitHubActionsDevPolicy`
   - Click "Create policy"

4. **Verify**
   - Check that the policy is attached to the user
   - Review permissions summary

### Option 2: AWS CLI

```bash
# Set up AWS CLI profile for dev account admin access
aws configure --profile dev-admin

# Create the policy document (already done - iam-policy-github-actions-ci.json)

# Apply inline policy to user
aws iam put-user-policy \
  --profile dev-admin \
  --user-name github-actions-ci \
  --policy-name RoxasGitHubActionsDevPolicy \
  --policy-document file://iam-policy-github-actions-ci.json

# Verify the policy was applied
aws iam get-user-policy \
  --profile dev-admin \
  --user-name github-actions-ci \
  --policy-name RoxasGitHubActionsDevPolicy
```

### Option 3: Terraform (Advanced)

If you manage IAM users with Terraform:

```hcl
resource "aws_iam_user_policy" "github_actions_ci_dev" {
  name   = "RoxasGitHubActionsDevPolicy"
  user   = "github-actions-ci"
  policy = file("${path.module}/iam-policy-github-actions-ci.json")
}
```

## Policy Breakdown

### Terraform Backend Permissions
```json
S3: GetObject, PutObject, DeleteObject, ListBucket
DynamoDB: GetItem, PutItem, DeleteItem
```
- Read/write Terraform state in S3
- Lock state using DynamoDB

### IAM Role Management
```json
IAM: CreateRole, DeleteRole, GetRole, PutRolePolicy, AttachRolePolicy, PassRole
```
- Create Lambda execution roles
- Attach policies to roles
- Pass roles to Lambda functions

### Lambda Function Management
```json
Lambda: CreateFunction, DeleteFunction, UpdateFunctionCode, CreateFunctionUrlConfig
```
- Deploy Lambda functions
- Update function code
- Configure function URLs

### API Gateway Management
```json
APIGatewayV2: * (on /apis/*)
```
- Create HTTP APIs
- Configure routes and integrations

### CloudWatch Logs Management
```json
Logs: CreateLogGroup, DeleteLogGroup, PutRetentionPolicy
```
- Create log groups for Lambda and API Gateway
- Set retention policies

## Resource Naming Convention

All resources are scoped to `roxas-*` prefix:
- IAM Roles: `arn:aws:iam::539402214167:role/roxas-*`
- Lambda Functions: `arn:aws:lambda:us-east-1:539402214167:function:roxas-*`
- Log Groups: `/aws/lambda/roxas-*` and `/aws/apigateway/roxas-*`

This prevents the user from modifying resources outside the Roxas project.

## Security Considerations

### Principle of Least Privilege
- Permissions are scoped to specific resources (roxas-* prefix)
- No wildcard (*) permissions on sensitive actions
- Read-only access to logs

### Resource Boundaries
- Can only create roles with `roxas-*` naming
- Can only manage Lambda functions with `roxas-*` naming
- Cannot modify other AWS resources

### State Backend Security
- Separate permissions for backend access
- DynamoDB locking prevents state corruption
- S3 versioning enabled for state recovery

## Prod Account

For the prod account (598821842404), you'll need to:

1. Create similar policy with prod account number
2. Apply to `github-actions-prod` user
3. Use separate backend resources:
   - S3: `roxas-terraform-state-prod`
   - DynamoDB: `roxas-terraform-locks-prod`

## Verification

After applying the policy, test with:

```bash
# Trigger a PR deployment workflow
# Should succeed without permission errors

# Check CloudWatch logs for any permission denials
aws logs tail /aws/lambda/roxas-webhook-handler-dev-pr-N --follow
```

## Troubleshooting

### AccessDenied Errors

If you see `AccessDenied` errors in GitHub Actions:

1. **Check the policy is attached**
   ```bash
   aws iam list-user-policies --user-name github-actions-ci
   ```

2. **Verify policy content**
   ```bash
   aws iam get-user-policy \
     --user-name github-actions-ci \
     --policy-name RoxasGitHubActionsDevPolicy
   ```

3. **Check resource naming**
   - Ensure resources follow `roxas-*` convention
   - ARNs must match policy restrictions

### Common Issues

**"Cannot create role"**
- Ensure IAM permissions include `iam:CreateRole`, `iam:PassRole`
- Check role name starts with `roxas-`

**"Cannot access S3 bucket"**
- Verify backend permissions are included
- Check bucket name matches policy

**"DynamoDB lock error"**
- Ensure DynamoDB permissions are included
- Verify table name matches policy

## Updates

When adding new AWS services to the infrastructure:

1. Update `iam-policy-github-actions-ci.json`
2. Add appropriate permissions with resource scoping
3. Re-apply policy using AWS CLI or Console
4. Test with a PR deployment

## Cost

These permissions themselves have no cost. They only allow the user to create resources that may incur charges (Lambda, API Gateway, CloudWatch Logs).
