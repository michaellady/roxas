# Roxas

OSS LinkedIn Automation - Transform git commits into professional LinkedIn posts to help open source projects reach decision-makers and secure funding.

## Architecture

GitHub Webhook → GPT-4 Summary → DALL-E Image → LinkedIn Post

## Development

### Prerequisites

- Go 1.21+
- OpenAI API key
- LinkedIn API credentials
- AWS account (for deployment)

### Setup

```bash
# Clone repository
git clone git@github.com:michaellady/roxas.git
cd roxas

# Copy environment template
cp .env.example .env
# Edit .env with your API keys

# Run tests
make test

# Build
make build
```

### Testing

```bash
# Unit tests
make test

# Integration tests
make test-int

# End-to-end test
make e2e
```

### Project Structure

```
roxas/
├── cmd/server/          # Lambda entry point
├── internal/
│   ├── handlers/        # HTTP handlers
│   ├── services/        # Business logic (GPT-4, DALL-E, LinkedIn)
│   └── models/          # Data structures
├── tests/               # Integration tests
├── terraform/           # Infrastructure as code
└── Makefile            # Build and test commands
```

## Current Status

🚧 **Tracer Bullet Phase** - Building MVP vertical slice (TB01-TB12)

- [x] TB01: Project setup and test framework
- [ ] TB02-TB03: Webhook endpoint
- [ ] TB04-TB05: GPT-4 integration
- [ ] TB06-TB07: DALL-E integration
- [ ] TB08-TB09: LinkedIn integration
- [ ] TB10-TB11: End-to-end orchestration
- [ ] TB12: AWS Lambda deployment

## License

TBD
