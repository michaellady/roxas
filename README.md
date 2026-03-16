# Roxas

**Transform git commits into professional social media posts via Buffer**

Roxas is an open-source automation service that helps OSS projects reach decision-makers and secure funding by automatically converting git commits into engaging social media posts via Buffer with AI-generated summaries and professional images.

## 🚀 Status

✅ **Production Ready** - Deployed and operational in multi-environment AWS infrastructure

- **Environments**: Development (PR testing) + Production (main branch)
- **CI/CD**: Fully automated deployment pipeline
- **Test Coverage**: 61 tests passing (unit + integration + E2E)
- **Infrastructure**: AWS Lambda + API Gateway + Terraform

## Architecture

### System Flow

```mermaid
flowchart LR
    A[GitHub Push] -->|Webhook| B[API Gateway]
    B --> C[Lambda Function]
    C --> D[Webhook Handler]
    D --> E[Orchestrator]
    E --> F[Claude Summarizer]
    F --> G[Titan Image Generator]
    G --> H[Buffer Poster]
    H --> I[Posts Scheduled/Published]

    style A fill:#24292e,color:#fff
    style I fill:#0077b5,color:#fff
    style C fill:#ff9900,color:#000
```

### Component Architecture

```mermaid
graph TB
    subgraph "AWS Lambda"
        Handler[Webhook Handler<br/>Signature Validation]
        Orch[Orchestrator<br/>Workflow Coordination]

        Handler --> Orch
    end

    subgraph "Services"
        Summarizer[Claude Summarizer<br/>Commit Analysis]
        ImageGen[Titan Image Generator<br/>Visual Content]
        Buffer[Buffer Poster<br/>Social Scheduling]

        Orch --> Summarizer
        Orch --> ImageGen
        Orch --> Buffer
    end

    subgraph "External APIs"
        Bedrock[AWS Bedrock<br/>Claude + Titan]
        S3[AWS S3<br/>Image Storage]
        BufAPI[Buffer API<br/>Social Scheduling]

        Summarizer --> Bedrock
        ImageGen --> Bedrock
        ImageGen --> S3
        Buffer --> BufAPI
    end

    subgraph "Clients"
        BRClient[Bedrock Client]
        BufClient[Buffer Client]

        Summarizer --> BRClient
        ImageGen --> BRClient
        Buffer --> BufClient
    end

    style Handler fill:#3498db,color:#fff
    style Orch fill:#9b59b6,color:#fff
    style Bedrock fill:#ff9900,color:#000
    style BufAPI fill:#0077b5,color:#fff
```

### Infrastructure

```mermaid
graph TB
    subgraph "GitHub"
        Repo[Repository<br/>Code Push]
        Actions[GitHub Actions<br/>CI/CD Pipeline]
    end

    subgraph "AWS - Dev Account (539402214167)"
        subgraph "VPC (10.0.0.0/16)"
            subgraph "Public Subnets"
                NAT_Dev[NAT Instance<br/>t4g.nano on-demand<br/>~$3/month]
                IGW_Dev[Internet Gateway]
            end

            subgraph "Private Subnets"
                Lambda_Dev[Lambda Function<br/>roxas-webhook-handler-dev<br/>VPC Enabled]
                RDS_Dev[RDS PostgreSQL 15<br/>db.t4g.micro<br/>Multi-tenant DB]
            end
        end

        APIGW_Dev[API Gateway<br/>Custom Domain<br/>pr-XX.roxasapp.com]
        Secrets_Dev[Secrets Manager<br/>DB Credentials]
        CW_Dev[CloudWatch Logs<br/>Lambda + RDS]
        S3_Dev[S3 Bucket<br/>Terraform State]

        APIGW_Dev --> Lambda_Dev
        Lambda_Dev --> RDS_Dev
        Lambda_Dev --> Secrets_Dev
        Lambda_Dev --> NAT_Dev
        NAT_Dev --> IGW_Dev
        Lambda_Dev --> CW_Dev
    end

    subgraph "AWS - Prod Account (598821842404)"
        subgraph "VPC (10.0.0.0/16)"
            subgraph "Public Subnets"
                NAT_Prod[NAT Instance<br/>t4g.nano on-demand<br/>~$3/month]
                IGW_Prod[Internet Gateway]
            end

            subgraph "Private Subnets"
                Lambda_Prod[Lambda Function<br/>roxas-webhook-handler-prod<br/>VPC Enabled]
                RDS_Prod[RDS PostgreSQL 15<br/>db.t4g.micro<br/>Multi-tenant DB]
            end
        end

        APIGW_Prod[API Gateway<br/>Custom Domain<br/>roxas.ai]
        Secrets_Prod[Secrets Manager<br/>DB Credentials]
        CW_Prod[CloudWatch Logs<br/>Lambda + RDS]
        S3_Prod[S3 Bucket<br/>Terraform State]

        APIGW_Prod --> Lambda_Prod
        Lambda_Prod --> RDS_Prod
        Lambda_Prod --> Secrets_Prod
        Lambda_Prod --> NAT_Prod
        NAT_Prod --> IGW_Prod
        Lambda_Prod --> CW_Prod
    end

    subgraph "External Services"
        Bedrock[AWS Bedrock<br/>Claude + Titan]
        BufferAPI[Buffer API<br/>Social Scheduling]
    end

    Repo -->|Webhook| APIGW_Prod
    Repo -->|PR Open/Update| Actions
    Actions -->|Deploy Dev| Lambda_Dev
    Actions -->|Deploy Prod| Lambda_Prod

    Lambda_Dev -->|via NAT| Bedrock
    Lambda_Dev -->|via NAT| BufferAPI
    Lambda_Prod -->|via NAT| Bedrock
    Lambda_Prod -->|via NAT| BufferAPI

    style Repo fill:#24292e,color:#fff
    style Actions fill:#2088ff,color:#fff
    style Lambda_Dev fill:#ff9900,color:#000
    style Lambda_Prod fill:#ff9900,color:#000
    style RDS_Dev fill:#527fff,color:#fff
    style RDS_Prod fill:#527fff,color:#fff
    style NAT_Dev fill:#ec7211,color:#fff
    style NAT_Prod fill:#ec7211,color:#fff
    style Bedrock fill:#ff9900,color:#000
    style BufferAPI fill:#0077b5,color:#fff
```

### Shared RDS for PR Deployments

**Problem:** Each PR deployment previously provisioned a dedicated RDS instance, taking ~6 minutes and costing $12/month per PR.

**Solution:** Shared RDS instance where each PR gets its own database (not a whole RDS instance).

**Benefits:**
- **Deploy Time:** 6 min → 30 sec (200x faster!)
- **Cost:** Same for 1 PR, saves $12/month per additional PR
- **Isolation:** Strong isolation via separate PostgreSQL databases
- **Simplicity:** No application code changes needed

```mermaid
graph TB
    subgraph "PR Lifecycle"
        PR_Open[PR Opened/Updated]
        PR_Close[PR Closed]
    end

    subgraph "GitHub Actions"
        Deploy[Deploy Workflow]
        Cleanup[Cleanup Workflow]
    end

    subgraph "Terraform"
        TF_Create[Create Database<br/>CREATE DATABASE pr_N]
        TF_Destroy[Drop Database<br/>DROP DATABASE pr_N]
    end

    subgraph "Shared RDS Instance"
        subgraph "PostgreSQL 15"
            Master[Master DB<br/>roxas_shared]
            PR22[PR Database<br/>pr_22]
            PR156[PR Database<br/>pr_156]
            PR289[PR Database<br/>pr_289]
        end

        Connections[100 Connections<br/>~20 per PR]
        Storage[20 GB Storage<br/>Expandable]
    end

    subgraph "Lambda Functions"
        Lambda22[Lambda PR-22<br/>→ pr_22]
        Lambda156[Lambda PR-156<br/>→ pr_156]
        Lambda289[Lambda PR-289<br/>→ pr_289]
    end

    PR_Open --> Deploy
    Deploy --> TF_Create
    TF_Create --> PR22
    TF_Create --> PR156
    TF_Create --> PR289

    PR22 -.-> Lambda22
    PR156 -.-> Lambda156
    PR289 -.-> Lambda289

    PR_Close --> Cleanup
    Cleanup --> TF_Destroy
    TF_Destroy -.->|DROP| PR22

    style PR22 fill:#4caf50,color:#fff
    style PR156 fill:#4caf50,color:#fff
    style PR289 fill:#4caf50,color:#fff
    style Master fill:#2196f3,color:#fff
    style Lambda22 fill:#ff9900,color:#000
    style Lambda156 fill:#ff9900,color:#000
    style Lambda289 fill:#ff9900,color:#000
```

**Database Isolation Strategy:**

| Approach | Isolation | Cleanup | Selected |
|----------|-----------|---------|----------|
| Separate Databases | ✅ Strong | ✅ Simple (DROP DATABASE) | **✅ YES** |
| Separate Schemas | ⚠️ Medium | ⚠️ Complex | ❌ No |
| Row-Level Security | ❌ Weak | ❌ Complex | ❌ No |

**Database Naming:**
- Master: `roxas` (RDS default database)
- PR databases: `pr_{number}` (e.g., `pr_22`, `pr_156`)
- Connection: `postgres://roxas_app:PWD@roxas-dev-rds:5432/pr_{PR_NUMBER}`

**Resource Limits & Connection Pool Sizing:**
- **Instance:** db.t4g.micro (~80 max connections, ~400MB RAM)
- **Connection Pool:** Each PR Lambda should use max 10 connections
- **Comfortable Capacity:** 3 concurrent PRs (30 connections + system overhead)
- **Storage:** 20 GB allocated, alarm at 4 GB free (16 GB used)
- **Scaling Trigger:** Consistently >3 PRs OR >16GB disk usage → upgrade to db.t4g.small (~$24/month)

**CloudWatch Monitoring:**
- **Dashboard:** `roxas-dev-health` - Connections, CPU, Memory, Storage, IOPS
- **Alarms:** Connection count >60, CPU >80%, Free memory <100MB, Storage <4GB free
- **Logs:** PostgreSQL and upgrade logs exported to CloudWatch

**Security:**
- Application user: `roxas_app` (owns all PR databases)
- Master user: `postgres` (admin, in Secrets Manager)
- Network: Private subnets only
- SSL/TLS: Required (`sslmode=require`)

### Dev RDS Operations Runbook

**1. Check which PRs are using dev RDS:**
```bash
# Get RDS credentials
SECRET_ARN=$(AWS_PROFILE=dev-admin aws secretsmanager list-secrets \
  --query 'SecretList[?starts_with(Name, `roxas-dev-db-credentials-`) && DeletedDate == null].ARN | [0]' \
  --output text)
SECRET=$(AWS_PROFILE=dev-admin aws secretsmanager get-secret-value \
  --secret-id "$SECRET_ARN" --query SecretString --output text)

# Extract credentials
DB_HOST=$(echo $SECRET | jq -r '.host')
DB_USER=$(echo $SECRET | jq -r '.username')
DB_PASS=$(echo $SECRET | jq -r '.password')

# List all PR databases
PGPASSWORD=$DB_PASS psql -h $DB_HOST -U $DB_USER -d postgres -c \
  "SELECT datname FROM pg_database WHERE datname LIKE 'pr_%' ORDER BY datname;"
```

**2. Manually create/drop PR database:**
```bash
# Create database for PR (if automation failed)
PGPASSWORD=$DB_PASS psql -h $DB_HOST -U $DB_USER -d postgres -c \
  "CREATE DATABASE pr_123;"

# Drop database for PR (manual cleanup)
# First terminate connections
PGPASSWORD=$DB_PASS psql -h $DB_HOST -U $DB_USER -d postgres -c \
  "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='pr_123' AND pid <> pg_backend_pid();"
# Then drop
PGPASSWORD=$DB_PASS psql -h $DB_HOST -U $DB_USER -d postgres -c \
  "DROP DATABASE IF EXISTS pr_123;"
```

**3. Connection limit troubleshooting:**
```bash
# Check current connections by database
PGPASSWORD=$DB_PASS psql -h $DB_HOST -U $DB_USER -d postgres -c \
  "SELECT datname, count(*) FROM pg_stat_activity GROUP BY datname ORDER BY count DESC;"

# Check max connections setting
PGPASSWORD=$DB_PASS psql -h $DB_HOST -U $DB_USER -d postgres -c \
  "SHOW max_connections;"

# Kill idle connections older than 10 minutes
PGPASSWORD=$DB_PASS psql -h $DB_HOST -U $DB_USER -d postgres -c \
  "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
   WHERE state = 'idle' AND state_change < NOW() - INTERVAL '10 minutes';"
```

**4. Disk space cleanup:**
```bash
# Check database sizes
PGPASSWORD=$DB_PASS psql -h $DB_HOST -U $DB_USER -d postgres -c \
  "SELECT datname, pg_size_pretty(pg_database_size(datname)) as size
   FROM pg_database WHERE datname LIKE 'pr_%' ORDER BY pg_database_size(datname) DESC;"

# Identify tables consuming most space (run per database)
PGPASSWORD=$DB_PASS psql -h $DB_HOST -U $DB_USER -d pr_123 -c \
  "SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
   FROM pg_catalog.pg_statio_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 10;"

# VACUUM to reclaim space (run per database)
PGPASSWORD=$DB_PASS psql -h $DB_HOST -U $DB_USER -d pr_123 -c "VACUUM FULL;"
```

**5. When to scale up:**
| Metric | Current Limit | Warning | Action |
|--------|--------------|---------|--------|
| Connections | 80 max | >60 sustained | Upgrade to db.t4g.small (200 connections) |
| Storage | 20 GB | <4 GB free | Increase allocated storage or cleanup |
| CPU | 100% | >80% sustained | Upgrade instance class |
| Memory | ~400 MB | <100 MB free | Upgrade instance class |
| Concurrent PRs | 3 comfortable | >3 sustained | Upgrade to db.t4g.small (~$24/month) |

```bash
# Scale up via Terraform (in terraform/shared/)
# Edit rds.tf: change instance_class = "db.t4g.small"
# Then: terraform plan && terraform apply
```

**6. Dedicated RDS for special cases:**

All PR deployments use the shared `roxas-dev-rds` instance by default. For PRs requiring dedicated resources (load testing, sensitive data), contact the infrastructure team to provision a dedicated RDS instance manually.

## Quick Start

### Prerequisites

- **Go 1.25.3+**
- **AWS Account** (for deployment)
- **API Keys**:
  - AWS credentials with Bedrock access (Claude + Titan models)
  - GitHub webhook secret
  - Buffer credentials (configured per-user via the settings page)

### Installation

```bash
# Clone repository
git clone git@github.com:michaellady/roxas.git
cd roxas

# Install dependencies
go mod download

# Copy environment template
cp .env.example .env

# Edit .env with your API keys
# See "Environment Variables" section below
```

### Database Setup

Roxas requires PostgreSQL for multi-tenant data storage.

**Local PostgreSQL Setup (Development Only):**

```bash
# Install PostgreSQL (macOS)
brew install postgresql@16

# Start PostgreSQL
brew services start postgresql@16

# Create local databases
createdb roxas_dev   # For local development
createdb roxas_test  # For running tests

# Set DATABASE_URL in .env
echo "DATABASE_URL=postgres://postgres:postgres@localhost:5432/roxas_dev?sslmode=disable" >> .env
```

**Note:** Production uses AWS RDS PostgreSQL (managed service), not a local database. RDS setup is automated via Terraform.

**Run Migrations:**

```bash
# Install golang-migrate CLI
brew install golang-migrate

# Run migrations
cd db
migrate -path migrations -database "${DATABASE_URL}" up

# Verify tables created
psql ${DATABASE_URL} -c "\dt"
```

**Database Schema:**
- `users` - User accounts with authentication
- `repositories` - GitHub repositories tracked per user
- `commits` - Commit metadata (lightweight storage)
- `posts` - Generated social media content per platform (includes `buffer_post_id`, `buffer_status`, `scheduled_at` columns for Buffer integration)
- `buffer_connections` - Per-user Buffer OAuth credentials and channel selections (access tokens, refresh tokens, selected profiles/channels)

See `db/migrations/` for complete schema definitions.

### Local Development

```bash
# Run all tests
make test

# Run integration tests
make test-int

# Build Lambda deployment package
make build

# Clean build artifacts
make clean
```

## Development

### Project Structure

```
roxas/
├── cmd/
│   └── server/              # Lambda entry point
│       ├── main.go          # Handler initialization
│       └── main_test.go     # Lambda handler tests
├── internal/
│   ├── clients/             # External API clients
│   │   ├── bedrock.go       # AWS Bedrock client (Claude + Titan)
│   │   ├── bedrock_test.go
│   │   ├── buffer.go         # Buffer API client
│   │   └── buffer_test.go
│   ├── handlers/            # HTTP request handlers
│   │   ├── webhook.go       # GitHub webhook handler
│   │   └── webhook_test.go
│   ├── models/              # Data structures
│   │   ├── commit.go        # Commit payload models
│   │   └── commit_test.go
│   ├── orchestrator/        # Workflow coordination
│   │   └── orchestrator.go  # End-to-end flow orchestration
│   ├── web/                  # Web UI
│   │   ├── router.go         # HTTP route definitions
│   │   ├── router_test.go
│   │   ├── templates/
│   │   │   ├── layouts/
│   │   │   │   └── base.html
│   │   │   └── pages/
│   │   │       ├── home.html
│   │   │       ├── dashboard.html
│   │   │       ├── login.html
│   │   │       ├── signup.html
│   │   │       └── settings.html  # Buffer connection configuration
│   │   └── static/
│   │       └── css/style.css
│   └── services/            # Business logic
│       ├── summarizer.go    # AI commit summarization via Bedrock
│       ├── summarizer_test.go
│       ├── imagegen.go      # AI image generation via Bedrock
│       ├── imagegen_test.go
│       ├── buffer.go         # Buffer posting/scheduling logic
│       ├── buffer_test.go
│       └── buffer_store.go   # Buffer connection persistence
├── tests/
│   └── integration_test.go  # End-to-end integration tests
├── terraform/               # Infrastructure as Code
│   ├── main.tf              # AWS resources
│   ├── variables.tf         # Configuration variables
│   ├── outputs.tf           # Deployment outputs
│   ├── backend-dev.hcl      # Dev backend config
│   ├── backend-prod.hcl     # Prod backend config
│   ├── README.md            # Terraform documentation
│   └── BACKEND.md           # Backend setup guide
├── scripts/
│   ├── e2e-test.sh          # End-to-end test script
│   └── setup-terraform-backend.sh  # Backend initialization
├── .github/
│   └── workflows/
│       ├── test.yml         # Branch test workflow
│       ├── pr-deploy-dev.yml       # PR dev deployment
│       ├── pr-cleanup-dev.yml      # PR cleanup
│       └── main-deploy-prod.yml    # Production deployment
├── Makefile                 # Build and test commands
├── go.mod                   # Go dependencies
└── README.md                # This file
```

### Testing

```bash
# Unit tests (fast, no external APIs)
make test

# Integration tests (mocked external services)
make test-int

# System tests (requires real API credentials)
make test-system

# End-to-end test (requires deployed Lambda)
LAMBDA_URL=https://... WEBHOOK_SECRET=... make e2e
```

**Test Coverage:**
- **Unit tests**: 54 tests (handlers, services, clients)
- **Integration tests**: 7 tests (end-to-end flow)
- **Total**: 61 tests passing

### Development Workflow

1. **Create feature branch**: `git checkout -b feature-name`
2. **Write tests first** (TDD approach)
3. **Implement feature**
4. **Run tests**: `make test`
5. **Create PR** to `main`
6. **Automatic deployment**: PR → Dev environment, Merge → Prod

## Deployment

### CI/CD Pipeline

Roxas uses GitHub Actions for automated testing and deployment:

```mermaid
flowchart LR
    subgraph "On Branch Push"
        A[Push to Branch] --> B[Run Tests]
    end

    subgraph "On PR Open/Update"
        C[Open/Update PR] --> D[Run Tests]
        D --> E[Deploy to Dev]
        E --> F[Run E2E Tests]
        F --> G[Comment PR with Results]
    end

    subgraph "On PR Close"
        H[Close PR] --> I[Cleanup Dev Resources]
    end

    subgraph "On Main Push"
        J[Merge to Main] --> K[Run Tests]
        K --> L[Deploy to Prod]
        L --> M[Run E2E Tests]
    end

    style B fill:#28a745,color:#fff
    style E fill:#ff9900,color:#000
    style L fill:#dc3545,color:#fff
```

**Workflows:**

1. **`test.yml`** - Runs on every branch push
   - Executes unit and integration tests
   - Fast feedback loop (~30 seconds)

2. **`pr-deploy-dev.yml`** - Runs on PR open/update
   - Deploys to dev AWS account
   - Creates isolated workspace: `dev-pr-{PR_NUMBER}`
   - Runs E2E tests against dev deployment
   - Comments PR with webhook URL and test results

3. **`pr-cleanup-dev.yml`** - Runs on PR close
   - Destroys dev resources for the PR
   - Cleans up Terraform workspace

4. **`main-deploy-prod.yml`** - Runs on main branch push
   - Deploys to production AWS account
   - Single workspace: `prod`
   - Runs E2E tests to verify deployment
   - Production webhook URL available

### Environments

**Development Environment:**
- AWS Account: `539402214167`
- IAM User: `github-actions-ci`
- Terraform Backend: `roxas-terraform-state-dev`
- Function Naming: `roxas-webhook-handler-dev-pr-{NUMBER}`

**Production Environment:**
- AWS Account: `598821842404`
- IAM User: `github-actions-prod`
- Terraform Backend: `roxas-terraform-state-prod`
- Function Naming: `roxas-webhook-handler-prod`

### Manual Deployment

If you need to deploy manually (not recommended):

```bash
# Build deployment package
make build

# Deploy to AWS (requires AWS credentials)
cd terraform

# Initialize backend
terraform init -backend-config=backend-prod.hcl

# Select workspace
terraform workspace select prod || terraform workspace new prod

# Deploy
terraform apply
```

For detailed Terraform documentation, see [`terraform/README.md`](terraform/README.md).

## Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `WEBHOOK_SECRET` | GitHub webhook secret for signature validation | Random 32+ char string |

> **Note:** AI features use AWS Bedrock (Claude + Titan) with IAM authentication. No API keys needed — just ensure the Lambda role has `bedrock:InvokeModel` permission.

> **Note:** Buffer credentials are stored per-user in the database (in the `buffer_connections` table), not as environment variables. Users configure their Buffer connection via the settings page.

> **Note:** `BEDROCK_CHAT_MODEL` and `BEDROCK_IMAGE_MODEL` are optional. Defaults: `anthropic.claude-sonnet-4-20250514-v1:0` and `amazon.titan-image-generator-v1`.

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | Logging level (`debug`, `info`, `warn`, `error`) |
| `AWS_REGION` | `us-east-1` | AWS region (set by Lambda runtime) |
| `PORT` | `8080` | Local server port (not used in Lambda) |

### Setting Environment Variables

**Local Development:**
```bash
cp .env.example .env
# Edit .env with your values
```

**GitHub Actions (CI/CD):**
1. Go to repository Settings → Secrets and variables → Actions
2. Add secrets to appropriate environment (`dev` or `prod`):
   - `AWS_ACCESS_KEY_ID`
   - `AWS_SECRET_ACCESS_KEY`
   - `WEBHOOK_SECRET`

**AWS Lambda:**
- Environment variables are set via Terraform (`terraform/variables.tf`)
- Sensitive values pulled from GitHub Secrets during deployment

## API Reference

### Webhook Endpoint

**Production URL:** `https://roxas.ai/webhook/{repository-id}`

> **Important:** Use `https://roxas.ai` - do NOT use `www.roxas.ai` (www subdomain is not configured).

**Method:** `POST /webhook/{repository-id}`

**Headers:**
- `X-Hub-Signature-256`: GitHub webhook signature (HMAC SHA256)
- `X-GitHub-Event`: Event type (must be `push`)
- `Content-Type`: `application/json`

**Request Body:**
```json
{
  "ref": "refs/heads/main",
  "repository": {
    "name": "repo-name",
    "full_name": "owner/repo-name"
  },
  "commits": [
    {
      "id": "abc123...",
      "message": "Add new feature",
      "author": {
        "name": "Developer Name",
        "email": "dev@example.com"
      },
      "url": "https://github.com/owner/repo/commit/abc123"
    }
  ]
}
```

**Response Codes:**
- `200 OK`: Webhook processed successfully
- `400 Bad Request`: Invalid payload or missing signature
- `401 Unauthorized`: Invalid signature
- `500 Internal Server Error`: Processing failed

**Example:**
```bash
# Generate signature
PAYLOAD='{"ref":"refs/heads/main",...}'
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | sed 's/^.* //')

# Send webhook
curl -X POST https://your-api-gateway-url/webhook \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
  -H "X-GitHub-Event: push" \
  -d "$PAYLOAD"
```

## Troubleshooting

### Common Issues

**1. Tests failing with API errors**
- **Cause**: Missing or invalid AWS credentials
- **Solution**: Verify AWS credentials are configured and Bedrock model access is enabled. Check that Buffer credentials are configured in the database via the settings page

**2. Webhook signature validation fails**
- **Cause**: Mismatched `WEBHOOK_SECRET` between GitHub and Lambda
- **Solution**: Ensure GitHub webhook secret matches Lambda environment variable

**3. Lambda deployment fails**
- **Cause**: Missing AWS credentials or insufficient IAM permissions
- **Solution**: Verify GitHub Secrets are set and IAM policies are attached

**4. Buffer post not appearing**
- **Cause**: Invalid or expired Buffer access token, or no Buffer connection configured
- **Solution**: Re-authenticate with Buffer via the settings page to refresh your connection and verify your selected channels

**5. Image generation fails**
- **Cause**: Bedrock model access not enabled, IAM permissions missing, or S3 bucket misconfigured
- **Solution**: Check CloudWatch logs for error details, verify Bedrock model access in AWS console, and ensure Lambda IAM role has `bedrock:InvokeModel` and `s3:PutObject`/`s3:GetObject` permissions

### Debugging

**View Lambda Logs:**
```bash
# AWS CLI
aws logs tail /aws/lambda/roxas-webhook-handler-prod --follow

# Or via AWS Console
# CloudWatch → Log Groups → /aws/lambda/roxas-webhook-handler-prod
```

**Test Webhook Locally:**
```bash
# Run unit tests with verbose output
go test -v ./internal/handlers/

# Test specific function
go test -v -run TestWebhookHandler ./internal/handlers/
```

**Check Deployment Status:**
```bash
# View GitHub Actions runs
# Repository → Actions tab

# Check Terraform state
cd terraform
terraform show
```

## Contributing

We welcome contributions! Here's how to get started:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/your-feature`
3. **Write tests** for your changes (TDD approach)
4. **Implement your feature**
5. **Ensure all tests pass**: `make test`
6. **Commit your changes**: Include issue ID in commit message
7. **Push to your fork**: `git push origin feature/your-feature`
8. **Create a Pull Request**

### Code Style

- Follow standard Go conventions (`gofmt`, `golint`)
- Write godoc comments for exported functions
- Maintain test coverage (aim for >80%)
- Keep functions focused and testable

### Testing Requirements

All PRs must:
- Pass all existing tests (`make test`)
- Include tests for new functionality
- Maintain or improve code coverage
- Pass E2E tests in dev environment

### PR Process

1. **Automatic checks run** (tests + dev deployment)
2. **E2E tests verify** functionality in dev
3. **Code review** by maintainers
4. **Merge to main** → automatic prod deployment

## License

TBD

---

**Built with Go, AWS Lambda, AWS Bedrock (Claude + Titan), and Buffer API**

For questions or issues, please open a GitHub issue.

