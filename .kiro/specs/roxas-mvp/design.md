# Design Document: Roxas MVP

## Overview

Roxas is a serverless Go application deployed on AWS Lambda that automatically transforms GitHub commits into social media posts. The system follows an event-driven architecture where GitHub webhooks trigger asynchronous AI content generation, creating drafts that users can review, edit, and publish to Bluesky.

The MVP implementation prioritizes simplicity and reliability:
- **Single social platform**: Bluesky (AT Protocol) with app password authentication
- **Text-only posts**: 300 character limit, no image generation
- **Async generation**: Fire-and-forget webhook handling to prevent timeouts
- **Multi-tenant**: Multiple users can track the same repository with personalized content
- **Idempotent**: Duplicate webhook deliveries are safely handled

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT (Browser)                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      AWS API GATEWAY                             │
│                   (HTTPS, Custom Domain)                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      AWS LAMBDA (Go 1.25.3+)                     │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │  Web Router  │  │   Webhook    │  │    OAuth     │          │
│  │   Handler    │  │   Handler    │  │   Handlers   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │    Draft     │  │     Post     │  │  Connection  │          │
│  │   Service    │  │   Service    │  │   Service    │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐                             │
│  │   OpenAI     │  │   Bluesky    │                             │
│  │   Client     │  │   Client     │                             │
│  └──────────────┘  └──────────────┘                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
          │                   │                    │
          ▼                   ▼                    ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  PostgreSQL  │    │   OpenAI     │    │   Bluesky    │
│    (RDS)     │    │     API      │    │     API      │
└──────────────┘    └──────────────┘    └──────────────┘
```

### Request Flow

**User Registration & Authentication:**
1. User submits email/password → Lambda validates → bcrypt hash → Store in DB
2. Generate JWT token (24-hour expiration) → Return to client
3. Client stores JWT in localStorage → Includes in Authorization header

**GitHub Connection:**
1. User clicks "Connect GitHub" → Redirect to GitHub OAuth
2. GitHub redirects back with code → Lambda exchanges for access token
3. Fetch user's repositories via GitHub API → Display selection page
4. User selects repos → Lambda installs webhooks via GitHub API
5. Store repository records with webhook secrets

**Bluesky Connection:**
1. User submits handle + app password → Lambda validates format
2. Create Bluesky session (com.atproto.server.createSession)
3. Store app password (as access_token) and handle (as refresh_token)
4. Store DID (Decentralized Identifier) as platform_user_id

**Webhook Processing (Async):**
1. GitHub sends push webhook → Lambda validates HMAC signature
2. Check idempotency (X-GitHub-Delivery header + draft tuple)
3. Return HTTP 200 immediately
4. Launch Goroutine for async processing:
   - Fetch commit diffs via GitHub API
   - Call GPT-5.2 for content generation (300 char limit)
   - Create draft record per subscribed user
   - Create activity feed item

**Draft Publishing:**
1. User clicks "Post It" → Lambda fetches draft
2. Get Bluesky credentials → Create session
3. Call com.atproto.repo.createRecord with post content
4. Convert AT URI to web URL → Store post record
5. Update draft status to "posted" → Create activity item

## Components and Interfaces

### 1. Authentication Layer

**JWT Token Manager**
```go
type JWTManager interface {
    // Generate creates a new JWT token with 24-hour expiration
    Generate(userID string) (string, error)
    
    // Validate verifies a JWT token and returns the user ID
    Validate(token string) (string, error)
}
```

**Password Manager**
```go
type PasswordManager interface {
    // Hash creates a bcrypt hash of the password
    Hash(password string) (string, error)
    
    // Verify checks if the password matches the hash
    Verify(password, hash string) bool
}
```

**Middleware**
```go
type AuthMiddleware interface {
    // RequireAuth validates JWT and injects user ID into context
    RequireAuth(next http.Handler) http.Handler
}
```

### 2. GitHub Integration

**GitHub Client**
```go
type GitHubClient interface {
    // ListRepositories fetches user's personal repositories with admin access
    ListRepositories(ctx context.Context, accessToken string) ([]Repository, error)
    
    // CreateWebhook installs a webhook on a repository
    CreateWebhook(ctx context.Context, accessToken, repoFullName, webhookURL, secret string) (int64, error)
    
    // DeleteWebhook removes a webhook from a repository
    DeleteWebhook(ctx context.Context, accessToken, repoFullName string, webhookID int64) error
    
    // GetCommitDiff fetches the diff for a specific commit
    GetCommitDiff(ctx context.Context, accessToken, repoFullName, sha string) (string, error)
    
    // ValidateWebhookSignature verifies HMAC-SHA256 signature
    ValidateWebhookSignature(payload []byte, signature, secret string) bool
}

type Repository struct {
    ID          int64
    FullName    string
    Name        string
    IsPrivate   bool
    HasAdminAccess bool
}
```

### 3. Bluesky Integration

**Bluesky Client**
```go
type BlueskyClient interface {
    // Platform returns "bluesky"
    Platform() string
    
    // Authenticate creates a session with Bluesky
    Authenticate(ctx context.Context) error
    
    // Post creates a new Bluesky post
    Post(ctx context.Context, content PostContent) (*PostResult, error)
    
    // ValidateContent checks if content meets Bluesky requirements
    ValidateContent(content PostContent) error
    
    // ATURIToWebURL converts AT Protocol URI to web URL
    ATURIToWebURL(atURI string) string
    
    // IsAuthError returns true if error is authentication-related
    IsAuthError(err error) bool
    
    // IsRateLimitError returns true if error is rate limit-related
    IsRateLimitError(err error) bool
}

type PostContent struct {
    Text     string
    Media    []MediaAttachment
    ThreadID *string  // For replies
}

type PostResult struct {
    PostID  string  // AT Protocol URI
    PostURL string  // Web URL (bsky.app)
}

const BlueskyCharLimit = 300
```

### 4. AI Content Generation

**OpenAI Client**
```go
type OpenAIClient interface {
    // GeneratePostText creates social media content from commit data
    GeneratePostText(ctx context.Context, prompt string, maxLength int) (string, error)
}
```

**Post Generator**
```go
type PostGenerator interface {
    // Generate creates platform-specific content from commit data
    Generate(ctx context.Context, platform string, commit CommitData) (*GeneratedPost, error)
}

type CommitData struct {
    Messages    []string  // All commit messages in the push
    Diffs       []string  // Commit diffs (or summaries if large)
    Author      string
    RepoName    string
    CommitCount int
}

type GeneratedPost struct {
    Platform string
    Text     string
    Metadata map[string]interface{}
}
```

**Diff Summarizer**
```go
type DiffSummarizer interface {
    // Summarize converts large diffs into file-level summaries
    Summarize(diff string, threshold int) string
}

const DiffThreshold = 500  // lines
```

### 5. Webhook Processing

**Webhook Handler**
```go
type WebhookHandler interface {
    // HandlePush processes GitHub push webhooks
    HandlePush(ctx context.Context, payload PushPayload, signature, secret string) error
}

type PushPayload struct {
    Ref        string      // e.g., "refs/heads/main"
    Before     string      // SHA before push
    After      string      // SHA after push
    Commits    []Commit
    Repository Repository
    DeliveryID string      // X-GitHub-Delivery header
}

type Commit struct {
    SHA     string
    Message string
    Author  Author
}
```

**Idempotency Store**
```go
type IdempotencyStore interface {
    // RecordDelivery stores a webhook delivery ID
    RecordDelivery(ctx context.Context, repoID, deliveryID string) error
    
    // HasDelivery checks if a delivery ID was already processed
    HasDelivery(ctx context.Context, repoID, deliveryID string) (bool, error)
}
```

**Draft Creator**
```go
type DraftCreator interface {
    // CreateDraft generates AI content and creates a draft record
    CreateDraft(ctx context.Context, userID, repoID string, push PushPayload) error
}
```

### 6. Data Access Layer

**User Store**
```go
type UserStore interface {
    // Create creates a new user account
    Create(ctx context.Context, email, passwordHash string) (string, error)
    
    // GetByEmail retrieves a user by email
    GetByEmail(ctx context.Context, email string) (*User, error)
    
    // GetByID retrieves a user by ID
    GetByID(ctx context.Context, userID string) (*User, error)
}

type User struct {
    ID           string
    Email        string
    PasswordHash string
    CreatedAt    time.Time
    UpdatedAt    time.Time
}
```

**Repository Store**
```go
type RepositoryStore interface {
    // Create stores a new repository connection
    Create(ctx context.Context, repo *RepositoryRecord) error
    
    // GetByID retrieves a repository by ID
    GetByID(ctx context.Context, repoID string) (*RepositoryRecord, error)
    
    // ListByUser retrieves all repositories for a user
    ListByUser(ctx context.Context, userID string) ([]*RepositoryRecord, error)
    
    // GetUsersByRepo retrieves all users tracking a repository
    GetUsersByRepo(ctx context.Context, githubRepoID int64) ([]string, error)
    
    // Delete removes a repository connection
    Delete(ctx context.Context, repoID string) error
}

type RepositoryRecord struct {
    ID            string
    UserID        string
    GitHubRepoID  int64
    GitHubURL     string
    Name          string
    IsPrivate     bool
    WebhookID     int64
    WebhookSecret string
    IsActive      bool
    LastPushAt    *time.Time
    CreatedAt     time.Time
}
```

**Credential Store**
```go
type CredentialStore interface {
    // SaveCredentials stores or updates platform credentials
    SaveCredentials(ctx context.Context, creds *PlatformCredentials) error
    
    // GetCredentials retrieves credentials for a user and platform
    GetCredentials(ctx context.Context, userID, platform string) (*PlatformCredentials, error)
    
    // DeleteCredentials removes credentials for a platform
    DeleteCredentials(ctx context.Context, userID, platform string) error
}

type PlatformCredentials struct {
    ID             string
    UserID         string
    Platform       string     // "github", "bluesky", "threads"
    AccessToken    string     // Encrypted
    RefreshToken   string     // Encrypted (handle for Bluesky)
    TokenExpiresAt *time.Time
    PlatformUserID string
    Scopes         string
    CreatedAt      time.Time
    UpdatedAt      time.Time
}
```

**Draft Store**
```go
type DraftStore interface {
    // Create creates a new draft
    Create(ctx context.Context, draft *Draft) error
    
    // GetDraft retrieves a draft by ID
    GetDraft(ctx context.Context, draftID string) (*Draft, error)
    
    // ListByUser retrieves drafts for a user (paginated)
    ListByUser(ctx context.Context, userID string, limit, offset int) ([]*Draft, error)
    
    // Update updates a draft
    Update(ctx context.Context, draft *Draft) error
    
    // Delete removes a draft
    Delete(ctx context.Context, draftID string) error
}

type Draft struct {
    ID               string
    UserID           string
    RepositoryID     string
    Ref              string
    BeforeSHA        *string
    AfterSHA         string
    CommitSHAs       []string
    CommitCount      int
    GeneratedContent *string
    EditedContent    *string
    Status           string  // "draft", "posted", "error"
    ErrorMessage     *string
    CreatedAt        time.Time
    UpdatedAt        time.Time
    PostedAt         *time.Time
}
```

**Post Store**
```go
type PostStore interface {
    // Create creates a new post record
    Create(ctx context.Context, post *Post) error
    
    // ListByDraft retrieves posts for a draft
    ListByDraft(ctx context.Context, draftID string) ([]*Post, error)
    
    // ListByUser retrieves posts for a user (paginated)
    ListByUser(ctx context.Context, userID string, limit, offset int) ([]*Post, error)
}

type Post struct {
    ID             string
    DraftID        string
    Platform       string
    PlatformPostID string
    PlatformPostURL string
    Content        string
    Status         string  // "posted", "failed"
    ErrorMessage   *string
    PostedAt       *time.Time
    CreatedAt      time.Time
}
```

**Activity Store**
```go
type ActivityStore interface {
    // Create creates a new activity item
    Create(ctx context.Context, activity *Activity) error
    
    // ListByUser retrieves activity for a user (paginated)
    ListByUser(ctx context.Context, userID string, limit, offset int) ([]*Activity, error)
}

type Activity struct {
    ID       string
    UserID   string
    Type     string  // "draft_created", "post_success", "post_failed"
    DraftID  *string
    PostID   *string
    Platform *string
    Message  string
    Metadata map[string]interface{}
    CreatedAt time.Time
}
```

## Data Models

### Database Schema

**users**
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
```

**repositories**
```sql
CREATE TABLE repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    github_repo_id BIGINT NOT NULL,
    github_url VARCHAR(512) NOT NULL,
    name VARCHAR(255) NOT NULL,
    is_private BOOLEAN NOT NULL DEFAULT false,
    webhook_id BIGINT,
    webhook_secret VARCHAR(255) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_push_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_user_github_repo UNIQUE(user_id, github_repo_id)
);

CREATE INDEX idx_repositories_user ON repositories(user_id);
CREATE INDEX idx_repositories_github_repo ON repositories(github_repo_id);
```

**platform_credentials**
```sql
CREATE TABLE platform_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    platform VARCHAR(50) NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    token_expires_at TIMESTAMP,
    platform_user_id VARCHAR(255),
    scopes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_user_platform UNIQUE(user_id, platform)
);

CREATE INDEX idx_credentials_user_platform ON platform_credentials(user_id, platform);
```

**drafts**
```sql
CREATE TABLE drafts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    ref VARCHAR(255) NOT NULL,
    before_sha VARCHAR(40),
    after_sha VARCHAR(40) NOT NULL,
    commit_shas JSONB NOT NULL,
    commit_count INT NOT NULL DEFAULT 1,
    generated_content TEXT,
    edited_content TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'draft',
    error_message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    posted_at TIMESTAMP,
    CONSTRAINT unique_user_push UNIQUE(user_id, repository_id, ref, after_sha)
);

CREATE INDEX idx_drafts_user_status ON drafts(user_id, status);
CREATE INDEX idx_drafts_user_created ON drafts(user_id, created_at DESC);
```

**posts**
```sql
CREATE TABLE posts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    draft_id UUID NOT NULL REFERENCES drafts(id) ON DELETE CASCADE,
    platform VARCHAR(50) NOT NULL,
    platform_post_id VARCHAR(255),
    platform_post_url VARCHAR(512),
    content TEXT NOT NULL,
    status VARCHAR(20) NOT NULL,
    error_message TEXT,
    posted_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_posts_draft ON posts(draft_id);
```

**activities**
```sql
CREATE TABLE activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    draft_id UUID REFERENCES drafts(id) ON DELETE SET NULL,
    post_id UUID REFERENCES posts(id) ON DELETE SET NULL,
    platform VARCHAR(50),
    message TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_activities_user_created ON activities(user_id, created_at DESC);
```

**webhook_deliveries**
```sql
CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    delivery_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    ref VARCHAR(255),
    before_sha VARCHAR(40),
    after_sha VARCHAR(40),
    payload JSONB,
    status VARCHAR(20) NOT NULL,
    error_message TEXT,
    processed_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_delivery UNIQUE(repository_id, delivery_id)
);

CREATE INDEX idx_webhook_deliveries_repo ON webhook_deliveries(repository_id, created_at DESC);
```

### Data Flow Diagrams

**Draft Creation Flow:**
```
GitHub Push → Webhook Handler → Validate Signature
                                      ↓
                              Check Idempotency
                                      ↓
                              Return 200 OK
                                      ↓
                              Async Goroutine:
                                      ↓
                              Get Subscribed Users
                                      ↓
                              For Each User:
                                      ↓
                              Fetch Commit Diffs
                                      ↓
                              Summarize if > 500 lines
                                      ↓
                              Call GPT-5.2 (300 char limit)
                                      ↓
                              Create Draft Record
                                      ↓
                              Create Activity Item
```

**Publishing Flow:**
```
User Clicks "Post It" → Get Draft
                            ↓
                    Get Bluesky Credentials
                            ↓
                    Create Bluesky Session
                            ↓
                    Call com.atproto.repo.createRecord
                            ↓
                    Convert AT URI to Web URL
                            ↓
                    Create Post Record
                            ↓
                    Update Draft Status
                            ↓
                    Create Activity Item
                            ↓
                    Return Success
```


## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Authentication and Authorization Properties

**Property 1: User Registration Creates Valid Accounts**
*For any* valid email and password (≥8 characters), when a user registers, the system should create a user record with a bcrypt-hashed password and return a JWT token with 24-hour expiration.
**Validates: Requirements 1.1, 1.4, 13.1**

**Property 2: Password Validation Rejects Short Passwords**
*For any* password shorter than 8 characters, registration should be rejected with a validation error.
**Validates: Requirements 1.3**

**Property 3: JWT Token Generation**
*For any* successful authentication (registration or login), the system should generate a JWT token that expires exactly 24 hours from creation.
**Validates: Requirements 1.4, 1.6**

**Property 4: Expired Token Rejection**
*For any* JWT token with an expiration timestamp in the past, authentication middleware should reject the request and require re-authentication.
**Validates: Requirements 1.8, 12.5**

### GitHub Integration Properties

**Property 5: OAuth URL Contains Required Scopes**
*For any* GitHub OAuth initiation, the generated authorization URL should contain the scopes "repo" and "admin:repo_hook".
**Validates: Requirements 2.1**

**Property 6: Credential Encryption**
*For any* platform credentials stored in the database, the access_token and refresh_token fields should be encrypted before storage.
**Validates: Requirements 2.3, 13.2**

**Property 7: Repository Filtering by Admin Access**
*For any* list of repositories fetched from GitHub, only repositories where the user has admin access should be included in the filtered result.
**Validates: Requirements 2.5**

**Property 8: Unique Webhook Secrets**
*For any* set of webhooks installed for different repositories, each webhook should have a unique secret generated for signature validation.
**Validates: Requirements 3.5**

**Property 9: Webhook Configuration**
*For any* webhook installed on a repository, the webhook should be configured to listen for "push" events and include the correct callback URL and secret.
**Validates: Requirements 3.4, 3.6**

**Property 10: Multi-Tenant Webhook Installation**
*For any* repository tracked by N users, the system should install N separate webhooks (one per user) with unique secrets.
**Validates: Requirements 3.9**

### Bluesky Integration Properties

**Property 11: Handle Normalization**
*For any* Bluesky handle input, the system should remove "@" prefix and append ".bsky.social" if no domain is present.
**Validates: Requirements 4.1, 4.2**

**Property 12: Bluesky Credential Storage**
*For any* successful Bluesky authentication, the system should store the app password as access_token, handle as refresh_token, and DID as platform_user_id.
**Validates: Requirements 4.5, 4.6**

### Webhook Processing Properties

**Property 13: Webhook Signature Validation**
*For any* incoming webhook with a valid HMAC-SHA256 signature matching the stored secret, the webhook should be accepted; for any invalid signature, the webhook should be rejected and logged.
**Validates: Requirements 5.1, 5.2, 13.3, 13.4**

**Property 14: Branch Filtering**
*For any* push webhook with ref not equal to "refs/heads/main", the webhook should be ignored without creating drafts.
**Validates: Requirements 5.3**

**Property 15: Webhook Payload Extraction**
*For any* valid push webhook to main branch, the system should extract ref, before_sha, after_sha, and all commit_shas from the payload.
**Validates: Requirements 5.4**

**Property 16: Webhook Idempotency**
*For any* webhook delivery ID that has already been processed for a repository, subsequent deliveries with the same ID should return success without creating new drafts.
**Validates: Requirements 5.5, 5.6**

**Property 17: Multi-Tenant Draft Creation**
*For any* repository tracked by N users, a push webhook should trigger the creation of N separate drafts (one per user) with personalized AI-generated content.
**Validates: Requirements 5.7, 5.9, 14.1, 14.2**

**Property 18: Commit Diff Fetching**
*For any* push webhook containing M commits, the system should fetch M commit diffs via the GitHub API.
**Validates: Requirements 5.10**

**Property 19: Diff Summarization by Size**
*For any* commit diff, if the diff exceeds 500 lines, the system should send a file-level summary to GPT; if under 500 lines, the system should send the full diff content.
**Validates: Requirements 5.11, 5.12**

**Property 20: AI Prompt Construction**
*For any* draft generation, the GPT prompt should include all commit messages, diffs (or summaries), author name, repository name, and a 300-character limit instruction.
**Validates: Requirements 5.13, 5.14**

**Property 21: Draft Creation with Status**
*For any* successful AI content generation, the system should create a draft record with status "draft" and the generated content.
**Validates: Requirements 5.15**

**Property 22: Draft Uniqueness Constraint**
*For any* draft creation attempt, the system should enforce uniqueness by the tuple (user_id, repository_id, ref, after_sha), preventing duplicate drafts for the same push.
**Validates: Requirements 5.19**

**Property 23: Activity Logging on Draft Creation**
*For any* draft created (successful or error), the system should create a corresponding activity feed item for the user.
**Validates: Requirements 5.18, 12.2**

### Draft Management Properties

**Property 24: Draft Content Update**
*For any* draft regeneration request, the system should call GPT-5.2 again and update the draft's generated_content field with the new result.
**Validates: Requirements 6.9**

### Publishing Properties

**Property 25: Bluesky Post Creation**
*For any* draft with valid content (≤300 characters), posting to Bluesky should create a session, call com.atproto.repo.createRecord, and return an AT Protocol URI.
**Validates: Requirements 7.4**

**Property 26: AT URI to Web URL Conversion**
*For any* AT Protocol URI in the format "at://did:plc:xxx/app.bsky.feed.post/rkey", the system should convert it to "https://bsky.app/profile/{handle}/post/{rkey}".
**Validates: Requirements 7.6**

**Property 27: Post Success Workflow**
*For any* successful Bluesky post, the system should create a post record with status "posted", update the draft status to "posted" with posted_at timestamp, and create an activity feed item with the post URL.
**Validates: Requirements 7.5, 7.7, 7.8**

**Property 28: Post Idempotency**
*For any* draft that has already been posted, subsequent post requests should return success without creating duplicate posts.
**Validates: Requirements 7.14**

### Pagination Properties

**Property 29: Activity Feed Pagination**
*For any* user, fetching the activity feed should return the 20 most recent items sorted by created_at DESC, and subsequent "load more" requests should return the next 20 items with correct offset.
**Validates: Requirements 8.1, 8.6**

**Property 30: Drafts List Pagination**
*For any* user, fetching drafts should return only drafts with status "draft" or "error", sorted by created_at DESC, with pagination support (20 items per page).
**Validates: Requirements 9.1, 9.6**

### Repository Management Properties

**Property 31: Repository Deletion Preserves Drafts**
*For any* repository removal, the system should delete the repository record but keep all existing drafts associated with that repository.
**Validates: Requirements 10.7, 10.8**

### Connection Management Properties

**Property 32: Token Expiration Status**
*For any* platform credential, if token_expires_at is within 7 days, the connection should be marked "expiring soon"; if token_expires_at is in the past, the connection should be marked "expired".
**Validates: Requirements 11.3, 11.4**

**Property 33: Platform Disconnection Preserves Drafts**
*For any* platform disconnection, the system should delete the platform credentials but keep all existing drafts, which should fail to post until the platform is reconnected.
**Validates: Requirements 11.6, 11.7**

**Property 34: GitHub Disconnection Cascades**
*For any* GitHub disconnection, the system should delete all repository connections, attempt to delete webhooks via GitHub API, and remove the GitHub credentials.
**Validates: Requirements 11.8**

### Security Properties

**Property 35: CSRF Protection**
*For any* form submission endpoint, the system should validate CSRF tokens and reject requests with missing or invalid tokens.
**Validates: Requirements 13.6**

**Property 36: Authentication Rate Limiting**
*For any* authentication endpoint (login, register), the system should enforce rate limiting to prevent brute force attacks.
**Validates: Requirements 13.7**

### Multi-Tenant Data Isolation Properties

**Property 37: User Data Isolation**
*For any* user, fetching drafts or activity feed should return only records where user_id matches the authenticated user, ensuring no cross-user data leakage.
**Validates: Requirements 14.3, 14.4**

**Property 38: Draft Independence**
*For any* user posting a draft for a shared repository, the operation should not affect the draft status or content of other users tracking the same repository.
**Validates: Requirements 14.5**

## Error Handling

### Error Categories

**1. Authentication Errors**
- Invalid credentials → Return 401 with user-friendly message
- Expired JWT token → Return 401 and redirect to login
- Missing authentication → Return 401 and redirect to login

**2. Validation Errors**
- Invalid email format → Return 400 with field-specific error
- Password too short → Return 400 with validation message
- Content exceeds character limit → Return 400 with limit information
- Missing required fields → Return 400 with field list

**3. External API Errors**
- GitHub API failure → Log error, return 500, display generic message
- Bluesky API failure → Log error, keep draft status, allow retry
- OpenAI API failure → Retry up to 3 times, create error draft if all fail
- Rate limit errors → Return 429 with retry-after time if available

**4. Database Errors**
- Connection failure → Log error, return 500, display generic message
- Constraint violation → Return 409 with conflict details
- Query timeout → Log error, return 500, suggest retry

**5. Webhook Errors**
- Invalid signature → Reject silently, log for security monitoring
- Malformed payload → Return 400, log for debugging
- Duplicate delivery → Return 200 (idempotent success)

### Error Response Format

```go
type ErrorResponse struct {
    Error   string                 `json:"error"`
    Message string                 `json:"message"`
    Code    string                 `json:"code"`
    Details map[string]interface{} `json:"details,omitempty"`
}
```

### Retry Strategies

**AI Content Generation:**
- Retry up to 3 times with exponential backoff (1s, 2s, 4s)
- After 3 failures, create draft with status "error"
- User can manually retry from UI

**Bluesky Posting:**
- No automatic retry (user-initiated only)
- Display specific error message (auth, rate limit, etc.)
- Keep draft in "draft" status for retry

**GitHub API Calls:**
- Retry up to 2 times for transient errors (500, 502, 503)
- No retry for auth errors (401, 403)
- No retry for not found errors (404)

### Logging Strategy

**Security Events (Always Log):**
- Failed webhook signature validation
- Failed authentication attempts
- Rate limit violations

**Error Events (Always Log):**
- External API failures with full context
- Database errors with query details
- Unexpected exceptions with stack traces

**Audit Events (Always Log):**
- User registration and login
- Repository connections and disconnections
- Platform connections and disconnections
- Draft publishing

## Testing Strategy

### Dual Testing Approach

The Roxas MVP uses both unit testing and property-based testing to ensure comprehensive coverage:

**Unit Tests:**
- Specific examples demonstrating correct behavior
- Edge cases (empty inputs, boundary conditions)
- Error conditions (invalid signatures, expired tokens)
- Integration points between components

**Property-Based Tests:**
- Universal properties that hold for all inputs
- Comprehensive input coverage through randomization
- Minimum 100 iterations per property test
- Each property test references its design document property

**Balance:**
- Unit tests focus on concrete scenarios and integration
- Property tests verify general correctness across input space
- Together they provide both specific validation and broad coverage

### Property-Based Testing Configuration

**Library:** Use `gopter` (Go property-based testing library)

**Test Configuration:**
```go
parameters := gopter.DefaultTestParameters()
parameters.MinSuccessfulTests = 100  // Minimum iterations
parameters.MaxSize = 100             // Maximum generated value size
```

**Test Tagging:**
Each property test must include a comment tag referencing the design property:
```go
// Feature: roxas-mvp, Property 1: User Registration Creates Valid Accounts
func TestProperty_UserRegistrationCreatesValidAccounts(t *testing.T) {
    // Property test implementation
}
```

### Test Coverage Goals

**Unit Test Coverage:**
- Handlers: 80%+ coverage
- Services: 85%+ coverage
- Clients: 75%+ coverage (mocked external APIs)
- Database stores: 90%+ coverage

**Property Test Coverage:**
- All 38 correctness properties implemented as property tests
- Each property test runs minimum 100 iterations
- Properties cover authentication, webhook processing, publishing, and data isolation

### Integration Testing

**End-to-End Flows:**
1. User registration → GitHub connection → Repository selection → Webhook installation
2. Webhook receipt → Draft creation → AI generation → Activity logging
3. Draft editing → Bluesky publishing → Post record creation
4. Repository removal → Webhook deletion → Draft preservation

**Test Environment:**
- Local PostgreSQL database
- Mocked external APIs (GitHub, Bluesky, OpenAI)
- Test fixtures for webhook payloads
- Seeded test data for multi-tenant scenarios

### Manual Testing Checklist

**Pre-Deployment:**
- [ ] User can register and login
- [ ] GitHub OAuth flow completes successfully
- [ ] Webhooks are installed on selected repositories
- [ ] Bluesky connection works with app password
- [ ] Push to main creates draft with AI content
- [ ] Draft can be edited and published to Bluesky
- [ ] Activity feed shows all events
- [ ] Repository removal works correctly
- [ ] Platform disconnection preserves drafts
- [ ] Error messages are user-friendly

**Security:**
- [ ] Passwords are bcrypt hashed
- [ ] OAuth tokens are encrypted at rest
- [ ] Webhook signatures are validated
- [ ] CSRF protection is enabled
- [ ] Rate limiting works on auth endpoints
- [ ] Expired JWT tokens are rejected

**Multi-Tenant:**
- [ ] Multiple users can track same repository
- [ ] Each user gets personalized draft content
- [ ] Users only see their own drafts and activity
- [ ] Posting one user's draft doesn't affect others
