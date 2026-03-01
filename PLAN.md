# Plan: Bedrock + Buffer Integration

## Overview

Replace OpenAI API with Claude via AWS Bedrock for AI text generation, and replace direct social media clients (Threads, Bluesky, LinkedIn) with Buffer API for unified cross-platform posting. Target the smallest platform character limit (280 chars for X/Twitter) when generating content through Buffer.

## Character Limit Research

| Platform    | Character Limit |
|-------------|----------------|
| X/Twitter   | **280**        |
| Bluesky     | 300            |
| Threads     | 500            |
| LinkedIn    | ~3,000         |
| Facebook    | ~63,000        |
| Instagram   | 2,200          |

**Conclusion:** X/Twitter at **280 characters** is the smallest. When posting through Buffer (which distributes to all platforms), content should be generated at 280 characters max.

---

## Step 1: Create AWS Bedrock Client

Replace the OpenAI client with a Bedrock client that implements the existing `ChatClient` interface.

### 1a. Add `bedrockruntime` dependency

```bash
go get github.com/aws/aws-sdk-go-v2/service/bedrockruntime
```

### 1b. Create `internal/clients/bedrock.go`

New client that implements:
```go
// ChatClient interface (defined in services/post_generator.go)
type ChatClient interface {
    CreateChatCompletion(prompt string) (string, error)
}
```

- Uses AWS SDK v2 `bedrockruntime` client
- Calls the Bedrock Converse API (`client.Converse()`)
- Default model: `us.anthropic.claude-sonnet-4-5-20250929-v1:0` (cost-effective, fast)
- Configurable via `BEDROCK_MODEL_ID` env var
- Authenticates via Lambda's IAM execution role (no API key needed)
- Uses `AWS_REGION` (already set, defaults to `us-east-1`)
- Parameters: `temperature: 0.7`, `maxTokens: 500` (matching current OpenAI config)

### 1c. Create `internal/clients/bedrock_test.go`

- Test successful chat completion with mock HTTP server
- Test error handling (throttling, timeouts, empty responses)
- Test model ID configuration

### 1d. Remove OpenAI dependency from main flow

- **Keep** `internal/clients/openai.go` and tests (don't delete - may be needed for DALL-E image generation later)
- Remove `OPENAI_API_KEY` from required config path in `cmd/server/main.go`
- Replace all `NewOpenAIClient` calls with `NewBedrockClient` for text generation
- Update `aiGeneratorAdapter` and `createRouter` to use Bedrock client

---

## Step 2: Create Buffer API Client

Replace direct platform posting (Threads, Bluesky) with Buffer's API.

### 2a. Create `internal/clients/buffer.go`

Buffer client using the **legacy REST API** (simpler, better documented for creating posts):

- **Auth:** Bearer token via `BUFFER_ACCESS_TOKEN` env var
- **Base URL:** `https://api.bufferapp.com/1`
- **Key methods:**
  - `ListProfiles()` - Get connected channel/profile IDs
  - `CreatePost(profileIDs []string, text string, now bool)` - Create a post
  - `GetConfiguration()` - Get platform character limits dynamically
- **Implements `SocialClient` interface:**
  ```go
  Post(ctx context.Context, content PostContent) (*PostResult, error)
  ValidateContent(content PostContent) error
  Platform() string
  GetRateLimits() RateLimitInfo
  ```
- Posts the **same text** to all connected Buffer profiles (since we target 280 char minimum)
- `ValidateContent` enforces 280 character limit

### 2b. Create `internal/clients/buffer_test.go`

- Test `ListProfiles` with mock server
- Test `CreatePost` with mock server
- Test error handling (rate limits, auth failures)
- Test content validation (280 char limit)

### 2c. Add "buffer" platform constant

In `internal/services/credential_store.go`:
```go
PlatformBuffer = "buffer"
```

---

## Step 3: Update Post Generator for Buffer

### 3a. Update `internal/services/post_generator.go`

Add a new `PlatformBuffer` config:
```go
PlatformBuffer: {
    Name:       "Buffer",
    MaxLength:  280,  // X/Twitter is the smallest platform
    Tone:       "concise, engaging, casual but informative",
    HashtagReq: false,
}
```

Add platform-specific prompt instructions for Buffer:
- "MUST be 280 characters or less (targeting X/Twitter as the smallest platform)"
- "Be concise and punchy - this will be cross-posted to all social platforms"
- "No hashtags needed (Buffer handles per-platform optimization)"

### 3b. Update `aiGeneratorAdapter.TriggerGeneration` in `cmd/server/main.go`

Change the default platform from `"linkedin"` to `"buffer"` when generating content for drafts.

---

## Step 4: Wire Everything Together in `cmd/server/main.go`

### 4a. Update `Config` struct

Remove:
- ~~`OpenAIAPIKey`~~ (keep for backwards compatibility but make optional)
- ~~`OpenAIChatModel`~~
- ~~`OpenAIImageModel`~~

Add:
- `BedrockModelID string` — env var `BEDROCK_MODEL_ID` (optional, defaults to Sonnet 4.5)
- `BufferAccessToken string` — env var `BUFFER_ACCESS_TOKEN`

### 4b. Update `loadConfig()`

Load new env vars, keep old ones for fallback.

### 4c. Update `createRouter()`

- Replace `clients.NewOpenAIClient(...)` with `clients.NewBedrockClient(...)` for AI generation
- Replace `socialPosterAdapter` to use Buffer client instead of direct Bluesky/Threads clients
- The Buffer client becomes the primary posting mechanism

### 4d. Update `socialPosterAdapter.PostDraft()`

Change from trying Bluesky → Threads fallback to:
1. Get Buffer credentials/token
2. List Buffer profiles (connected channels)
3. Post to all profiles via Buffer API

---

## Step 5: Update Infrastructure

### 5a. Update `terraform/service/main.tf` — Lambda environment variables

Remove:
- `OPENAI_API_KEY` (no longer needed for text gen)

Add:
- `BUFFER_ACCESS_TOKEN`
- `BEDROCK_MODEL_ID` (optional)

### 5b. Update `terraform/service/variables.tf`

Add new variables:
- `buffer_access_token` (sensitive)
- `bedrock_model_id` (default: `us.anthropic.claude-sonnet-4-5-20250929-v1:0`)

### 5c. Update `terraform/service/secrets.tf` — Lambda IAM policy

Add Bedrock permissions to the Lambda execution role:
```hcl
{
  Effect = "Allow"
  Action = [
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream"
  ]
  Resource = "arn:aws:bedrock:*::foundation-model/anthropic.*"
}
```

### 5d. Update `.env.example`

Replace OpenAI vars with:
```
# AWS Bedrock Configuration (Claude)
# BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-4-5-20250929-v1:0  # default
AWS_REGION=us-east-1

# Buffer API Configuration
BUFFER_ACCESS_TOKEN=your-buffer-access-token
```

---

## Step 6: Update Tests

### 6a. Update `cmd/server/main_test.go`

- Update config initialization to use Bedrock instead of OpenAI
- Update webhook handler tests

### 6b. Update `internal/services/post_generator_test.go`

- Add test for `PlatformBuffer` config
- Verify 280 character enforcement

### 6c. Run full test suite

```bash
make test
```

---

## Files Changed (Summary)

| Action  | File                                      | Description                          |
|---------|-------------------------------------------|--------------------------------------|
| CREATE  | `internal/clients/bedrock.go`             | AWS Bedrock Claude client            |
| CREATE  | `internal/clients/bedrock_test.go`        | Bedrock client tests                 |
| CREATE  | `internal/clients/buffer.go`              | Buffer API client                    |
| CREATE  | `internal/clients/buffer_test.go`         | Buffer client tests                  |
| MODIFY  | `internal/services/post_generator.go`     | Add Buffer platform config           |
| MODIFY  | `internal/services/credential_store.go`   | Add Buffer platform constant         |
| MODIFY  | `cmd/server/main.go`                      | Wire Bedrock + Buffer, update config |
| MODIFY  | `terraform/service/main.tf`               | Update Lambda env vars               |
| MODIFY  | `terraform/service/variables.tf`          | Add new variables                    |
| MODIFY  | `terraform/service/secrets.tf`            | Add Bedrock IAM permissions          |
| MODIFY  | `.env.example`                            | Update env var documentation         |
| MODIFY  | `go.mod` / `go.sum`                       | Add bedrockruntime dependency        |

---

## What Stays Unchanged

- **Direct platform clients** (Threads, Bluesky, LinkedIn) — kept for users who prefer direct posting
- **OpenAI client** — kept for potential DALL-E image generation use
- **SocialClient interface** — Buffer client implements this same interface
- **Database schema** — no migrations needed
- **Web UI** — no changes (draft preview, edit, post flow stays the same)
- **GitHub webhook handling** — unchanged
- **OAuth flows** — Threads/Bluesky OAuth kept as alternative connections

## Risks & Notes

- **Buffer API rate limit:** 60 requests/user/minute (should be fine for Roxas's use case)
- **Buffer doesn't support per-platform text in a single call** — this is fine since we generate at 280 chars for all
- **DALL-E image generation** uses OpenAI, not Bedrock. The current draft flow doesn't use images, so this is not blocking. Can be replaced with Bedrock Titan Image later.
- **Buffer legacy API** is more documented than the new GraphQL beta API, so we use legacy REST for reliability
