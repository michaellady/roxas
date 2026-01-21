# Roxas Product Specification

> Transform GitHub merges into professional social media posts

## Overview

Roxas automatically generates social media content when users push to their main branch. It uses AI to create engaging post text, then lets users preview, edit, and publish to Threads (MVP), with LinkedIn and Instagram support coming later. Image generation is planned for post-MVP.

---

## User Flows

### 1. User Signup

```
┌─────────────────────────────────────────────────────────────────┐
│                         SIGNUP FLOW                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. User visits signup page                                      │
│     └─> Enter email + password                                   │
│         └─> Validate (email format, password strength)           │
│             └─> Create account                                   │
│                 └─> Generate JWT token                           │
│                     └─> Redirect to GitHub connection            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Fields:**
- Email (required, unique)
- Password (required, min 8 chars)

**Validation:**
- Email must be valid format
- Email must not already exist
- Password minimum 8 characters

**On Success:**
- Create user record
- Generate JWT token (24-hour expiration)
- Redirect to GitHub OAuth flow (required first step)

**Session Management:**
- JWT tokens expire after 24 hours
- User must re-login after expiration
- Logout clears token and redirects to login page

**Forgot Password (Post-MVP):**
- User clicks "Forgot Password" on login page
- Enter email address
- System sends password reset link via AWS SES (valid for 1 hour)
- User clicks link, enters new password
- Redirect to login page
- *Note: Requires AWS SES setup, deferred to post-MVP*

---

### 2. User Connects GitHub Account

```
┌─────────────────────────────────────────────────────────────────┐
│                    GITHUB CONNECTION FLOW                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. User clicks "Connect GitHub"                                 │
│     └─> Redirect to GitHub OAuth                                 │
│         └─> User authorizes Roxas app                            │
│             └─> GitHub redirects back with code                  │
│                 └─> Exchange code for access token               │
│                     └─> Fetch user's repositories                │
│                         └─> Display repo selection page          │
│                                                                  │
│  2. User selects repositories to track                           │
│     └─> For each selected repo:                                  │
│         └─> Create webhook via GitHub API                        │
│             └─> Store repo + webhook secret in DB                │
│                 └─> Show success confirmation                    │
│                     └─> Redirect to Connections page             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**GitHub OAuth Scopes Required:**

*MVP Scopes:*
- `repo` - Access to user's personal repositories
- `admin:repo_hook` - Create/manage webhooks on personal repos

*Post-MVP Scopes (for organization support):*
- `read:org` - List organization memberships and access org repositories

**Repo Selection Page:**
- **MVP:** Show user's personal repos they have admin access to (required for webhook installation)
- Checkboxes to select which to track
- Already-connected repos shown with disabled checkbox and "Connected" label
- "Select All" / "Deselect All" options (skips already-connected)
- Show repo name, visibility (public/private), last updated

**Multi-User Support:**
- Multiple Roxas users can connect the same GitHub repo
- Each user gets their own webhook on the repo
- Each user receives their own personalized AI-generated draft (unique generation per user)

**Webhook Installation:**
- Automatically install webhook via GitHub API
- Webhook URL: `https://roxas.ai/webhooks/github/:repo_id`
- Events: `push`
- Secret: Auto-generated per repo
- **Partial success**: If webhook fails for some repos, continue with others and show "4 of 5 connected" with option to retry failed ones

---

### 3. User Connects Social Media Accounts

```
┌─────────────────────────────────────────────────────────────────┐
│                 SOCIAL ACCOUNT CONNECTION FLOW                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Threads (MVP - Primary Platform):                               │
│  1. Click "Connect Threads"                                      │
│     └─> Redirect to Threads OAuth                                │
│         └─> User authorizes                                      │
│             └─> Exchange code for tokens                         │
│                 └─> Store credentials                            │
│                     └─> Show success, redirect to Connections    │
│                                                                  │
│  Note: Threads chosen for MVP because:                           │
│  - Client already implemented and tested                         │
│  - No special account requirements (any personal account)        │
│  - Supports text-only posts (image optional)                     │
│  - Generous rate limits (250 posts/day)                          │
│  - Simpler API than Instagram                                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Supported Platforms (MVP):**

| Platform  | Auth Method | Requirements | Post Type |
|-----------|-------------|--------------|-----------|
| Threads   | Threads OAuth | Any account | Text only (images post-MVP) |

**Supported Platforms (Post-MVP):**

| Platform  | Auth Method | Requirements | Post Type |
|-----------|-------------|--------------|-----------|
| LinkedIn  | OAuth 2.0   | Any account  | Text + Image |
| Instagram | Meta OAuth  | Business/Creator account | Feed (Image + Caption) |
| Twitter/X | OAuth 2.0   | Any account  | Text + Image |

**Connection States:**
- `connected` - Active, can post
- `disconnected` - Not connected
- `expired` - Token expired, needs reconnection

**Token Expiration (MVP):**
- Threads tokens expire (~60 days)
- When expired: Show "Reconnect" button in Settings, user must re-authorize
- Post-MVP: Auto-refresh using refresh tokens

---

### 4. Push to Main Triggers Draft Creation

```
┌─────────────────────────────────────────────────────────────────┐
│                    DRAFT CREATION FLOW                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. User pushes/merges to main branch                            │
│     └─> GitHub sends webhook to Roxas                            │
│         └─> Validate webhook signature                           │
│             └─> Identify repository + all subscribed users       │
│                 └─> Extract push info (ref, SHAs, commit count)  │
│                     └─> Fetch commit diffs via GitHub API        │
│                         └─> Generate post content via GPT-5.2    │
│                             └─> Create draft record per user     │
│                                 └─> Create activity feed item    │
│                                                                  │
│  Note: One draft per push event, not per commit                  │
│  (A PR with 5 commits = 1 draft when merged)                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Webhook Payload Processing:**
- Event type: `push`
- Branch filter: Only `refs/heads/main`
- All merge strategies supported (squash, rebase, regular merge)

**Async Generation (Fire-and-Forget):**
- Webhook handler returns 200 immediately after validation and recording delivery
- AI content generation runs asynchronously via Goroutine (Lambda) or background job
- This prevents GitHub webhook timeouts and improves reliability
- Draft appears in user's feed when generation completes (or with error state if it fails)

**Content Generation:**
- Input: All commit messages combined (for multi-commit pushes), commit diffs (fetched via GitHub API), author, repo name
- GPT-5.2 generates platform-appropriate text based on commit context and actual code changes
- **No commit URLs in post text** - keep posts clean (post-MVP: optionally add as reply/comment)
- **MVP is text-only** - image generation is post-MVP
- **Post-MVP image storage**: Images will be uploaded to S3 with 30-day lifecycle policy

**Diff Handling:**
- Fetch diffs via GitHub API for each commit in the push
- **Smart summarization for large diffs**: If diff exceeds threshold (e.g., 500 lines), send file-level summary (files changed, insertions/deletions) instead of full diff
- Small diffs: Send full diff content to AI for detailed context

**Generation Failure Handling:**
- Auto-retry up to 3 times on API failure
- If text generation fails after retries: Create draft with error state, show "Generation failed - Retry" in activity feed

**Draft Record:**
```
{
  id: uuid,
  user_id: uuid,
  repository_id: uuid,
  ref: string,                          // e.g., "refs/heads/main"
  before_sha: string | null,            // Push before SHA (NULL for new branches)
  after_sha: string,                    // Push after SHA (head of push)
  commit_shas: string[],                // All commit SHAs in the push
  commit_count: number,                 // Number of commits in push
  generated_content: string | null,     // NULL if generation failed
  edited_content: string | null,        // User's edited version (NULL if not edited)
  generated_image_url: string | null,   // Post-MVP: S3 URL with 30-day expiration
  status: "draft" | "posted" | "partial" | "failed" | "error",
  error_message: string | null,         // Error details if status is 'error' or 'failed'
  created_at: timestamp,
  updated_at: timestamp,
  posted_at: timestamp | null           // When first successfully posted
}
```

**Draft Status Values:**
- `draft` - Ready for review/posting
- `posted` - Successfully published to all selected platforms
- `partial` - Posted to some platforms, failed on others (can retry failed)
- `failed` - Posting to platform failed (can retry)
- `error` - AI generation failed (can retry generation)

---

### 5. User Reviews and Edits Draft

```
┌─────────────────────────────────────────────────────────────────┐
│                    PREVIEW & EDIT FLOW                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. User sees new draft in activity feed or drafts page          │
│     └─> Click to open preview                                    │
│                                                                  │
│  2. Preview page shows:                                          │
│     ┌─────────────────────────────────────────┐                  │
│     │  [Mock Social Media Card]               │                  │
│     │                                         │                  │
│     │  [Editable Text Area]                   │                  │
│     │  "Your commit introduced a new..."      │                  │
│     │                                         │                  │
│     │  Characters: 142 / 500                  │                  │
│     │                                         │                  │
│     │  (Post-MVP: AI-generated image here)    │                  │
│     └─────────────────────────────────────────┘                  │
│                                                                  │
│     Platform selection:                                          │
│     [x] Threads                                                  │
│     [ ] LinkedIn (coming soon)                                   │
│     [ ] Instagram (coming soon)                                  │
│                                                                  │
│     [Regenerate]  [Delete Draft]  [Post It]                      │
│                                                                  │
│  3. User can:                                                    │
│     - Edit the text (character limit shown)                      │
│     - Click "Regenerate" for new AI content                      │
│     - Select which platforms to post to                          │
│     - Delete/dismiss the draft                                   │
│     - Click "Post It" to publish                                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Character Limits:**
- **MVP: Threads only = 500 char limit**
- Post-MVP platforms:
  - LinkedIn: 3,000 chars
  - Instagram: 2,200 chars
  - Twitter/X: 280 chars

**Platform Selection:**
- Checkboxes for each connected platform
- Disconnected platforms show "Connect now" link
- At least one platform must be selected to post

**Actions:**
- **Edit**: Inline text editing with live character count, auto-saves while typing (debounced)
- **Regenerate**: Call GPT-5.2 again for fresh content
- **Delete Draft**: Remove draft, no posting
- **Post It**: Publish to selected platforms

**Loading States:**
- Show spinner + progress text during operations
- "Regenerating content..." during text regeneration
- "Posting to Threads..." during publish
- All buttons disabled while operation in progress

**Idempotency:**
- Backend handles duplicate requests gracefully (e.g., double-click on "Post It")
- If draft already posted, return success without re-posting

---

### 6. User Posts to Social Media

```
┌─────────────────────────────────────────────────────────────────┐
│                       POSTING FLOW                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. User clicks "Post It"                                        │
│     └─> Validate at least one platform selected                  │
│         └─> For each selected platform:                          │
│             └─> Create post with text                            │
│                 └─> Record result (success/failure)              │
│                                                                  │
│  2. On Full Success (all platforms):                             │
│     └─> Update draft status to "posted"                          │
│         └─> Create activity feed item "Posted to Threads"        │
│             └─> Show success toast                               │
│                 └─> Redirect to activity feed                    │
│                                                                  │
│  3. On Partial Success (some platforms fail, post-MVP):          │
│     └─> Update draft status to "partial"                         │
│         └─> Create activity items for each platform result       │
│             └─> Show mixed result message                        │
│                 └─> User can retry failed platforms              │
│                                                                  │
│  4. On Full Failure (all platforms fail):                        │
│     └─> Keep draft status as "draft"                             │
│         └─> Show error message with details                      │
│             └─> User can retry                                   │
│                                                                  │
│  Failure Reasons:                                                │
│  - Token expired → "Reconnect your [platform] account"           │
│  - Rate limited → "Rate limit reached. Try again in X minutes"   │
│  - API error → "Failed to post. Please try again."               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Post Result Handling:**

| Scenario | Action |
|----------|--------|
| All platforms succeed | Mark draft "posted", redirect to feed |
| Some platforms fail | Mark draft "partial", show which failed |
| All platforms fail | Keep draft "draft", show error |

**Activity Feed Items Created (MVP):**
- "Posted to Threads" (with link to post)
- "Failed to post to Threads" (with retry option)

**Activity Feed Items (Post-MVP, multi-platform):**
- "Posted to Threads and LinkedIn" (with links to each post)
- "Partially posted - succeeded on Threads, failed on LinkedIn" (with retry for failed)
- "Failed to post to all platforms" (with retry option)

---

## Pages & Navigation

### Navigation Structure

```
┌─────────────────────────────────────────────────────────────────┐
│  [Logo] Roxas          Dashboard | Drafts | Repos | Settings    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Current Page Content                                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Page: Dashboard (Home)

**Purpose:** Recent activity feed focused on posting

**Content:**
```
┌─────────────────────────────────────────────────────────────────┐
│  Recent Activity                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ● New draft created                              2 minutes ago  │
│    "Add user authentication feature"                             │
│    [View Draft →]                                                │
│                                                                  │
│  ✓ Posted to Threads                             1 hour ago     │
│    "Improved database performance..."                            │
│    [View Post →]                                                 │
│                                                                  │
│  ✗ Failed to post to Threads                     2 hours ago    │
│    Token expired                                                 │
│    [Reconnect Threads]                                           │
│                                                                  │
│  ✓ Posted to Threads                             Yesterday      │
│    "New API endpoints for..."                                    │
│    [View Post →]                                                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Empty State:**
> "Your activity will appear here"
>
> Push to main on a connected repository to generate your first post.

**Activity Types:**
- Draft created (clickable → preview page)
- Post successful (clickable → platform URL)
- Post failed (shows error + action)

**List Behavior:**
- Sorted by newest first
- Initial load: 20 items
- "Load more" button at bottom to fetch next 20

---

### Page: Drafts

**Purpose:** Queue of pending posts awaiting action

**Content:**
```
┌─────────────────────────────────────────────────────────────────┐
│  Pending Drafts (3)                                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Add authentication middleware                                ││
│  │ repo-name • 2 minutes ago                                    ││
│  │ "This commit introduces secure authentication..."            ││
│  │                                              [Preview →]     ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Fix database connection pooling                              ││
│  │ another-repo • 1 hour ago                                    ││
│  │ "Performance improvements to database..."                    ││
│  │                                              [Preview →]     ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Empty State:**
> "No pending posts"
>
> Drafts appear here when you push to main on a connected repository.

**Draft Card Shows:**
- Commit message as title (fetched from GitHub API using first commit SHA)
- Repository name
- Time since creation
- Generated content preview (truncated)
- "Preview" button

**List Behavior:**
- Sorted by newest first
- Initial load: 20 items
- "Load more" button at bottom to fetch next 20

---

### Page: Repositories

**Purpose:** Manage connected GitHub repositories

**Content:**
```
┌─────────────────────────────────────────────────────────────────┐
│  Connected Repositories                        [+ Add Repos]     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ 📁 my-awesome-project                              [Remove]  ││
│  │    Public • 12 posts generated • Last push: 2 hours ago     ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ 🔒 private-api                                     [Remove]  ││
│  │    Private • 3 posts generated • Last push: Yesterday       ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Empty State:**
> "No repositories connected"
>
> [Connect GitHub] to select repositories to track.

**Repo Card Shows:**
- Repo name with visibility icon
- Post count generated from this repo
- Last push timestamp
- Remove button

**Remove Repo Flow:**
- User clicks "Remove" on repo card
- Confirmation modal: "Remove [repo-name]? This will stop tracking pushes."
- On confirm:
  - Try to delete webhook from GitHub via API
  - If GitHub token expired: Show warning "Webhook may still exist on GitHub. You can remove it manually in repo settings."
  - Remove repo from database regardless
- Existing drafts from this repo are kept (orphaned but viewable)

**Add Repos Flow:**
- Click "+ Add Repos"
- Shows repo selection modal (same as onboarding)
- Select additional repos to track

---

### Page: Settings

**Purpose:** Manage account and connections

**Content:**
```
┌─────────────────────────────────────────────────────────────────┐
│  Settings                                                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ACCOUNT                                                         │
│  ─────────────────────────────────────────────────────────────  │
│  Email: user@example.com                                         │
│  [Change Password]                                               │
│                                                                  │
│  CONNECTED ACCOUNTS                                              │
│  ─────────────────────────────────────────────────────────────  │
│                                                                  │
│  GitHub ✓ Connected                                              │
│  @username • 2 repositories tracked           [Disconnect]       │
│                                                                  │
│  Threads ✓ Connected                                             │
│  @threaduser • Healthy                        [Disconnect]       │
│                                                                  │
│  ─────────────────────────────────────────────────────────────  │
│  COMING SOON                                                     │
│  ─────────────────────────────────────────────────────────────  │
│  LinkedIn (coming soon)                                          │
│  Instagram (coming soon)                                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

*Note: "Delete Account" button deferred to post-MVP.*

**Connection States:**
- ✓ Connected + Healthy (green)
- ⚠ Connected + Expiring Soon (yellow)
- ✗ Not Connected (gray)
- ✗ Connected + Expired (red, needs reconnect)

**Disconnect Behavior:**
- Removes OAuth tokens
- Keeps existing drafts (show "reconnect to post" on those drafts)
- Confirmation modal: "Disconnect Threads? Pending drafts will need reconnection to post."

---

## Data Models

### User
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

### Repository
```sql
CREATE TABLE repositories (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    github_repo_id BIGINT NOT NULL,           -- GitHub's repo ID
    github_url VARCHAR(512) NOT NULL,
    name VARCHAR(255) NOT NULL,
    is_private BOOLEAN NOT NULL DEFAULT false,
    webhook_id BIGINT,                         -- GitHub webhook ID
    webhook_secret VARCHAR(255) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_push_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_user_github_repo UNIQUE(user_id, github_repo_id)
);

-- Index for listing user's repositories
CREATE INDEX idx_repositories_user ON repositories(user_id);
```

### Platform Credentials
```sql
CREATE TABLE platform_credentials (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    platform VARCHAR(50) NOT NULL,             -- github, threads (MVP); linkedin, instagram (post-MVP)
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    token_expires_at TIMESTAMP,
    platform_user_id VARCHAR(255),
    platform_username VARCHAR(255),
    scopes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_user_platform UNIQUE(user_id, platform)
);
```

### Draft
```sql
CREATE TABLE drafts (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    repository_id UUID NOT NULL REFERENCES repositories(id),
    ref VARCHAR(255) NOT NULL,                 -- e.g., 'refs/heads/main'
    before_sha VARCHAR(40),                    -- Push before SHA (NULL for new branches)
    after_sha VARCHAR(40) NOT NULL,            -- Push after SHA (head of push)
    commit_shas JSONB NOT NULL,                -- Array of commit SHAs in the push
    commit_count INT NOT NULL DEFAULT 1,       -- Number of commits in push
    generated_content TEXT,                    -- NULL if generation failed
    generated_image_url VARCHAR(512),          -- Post-MVP: S3 URL with 30-day lifecycle
    edited_content TEXT,                       -- NULL if not edited
    status VARCHAR(20) NOT NULL DEFAULT 'draft',  -- draft, posted, partial, failed, error
    error_message TEXT,                        -- Error details if status is 'error' or 'failed'
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    posted_at TIMESTAMP,                       -- When draft was first successfully posted
    CONSTRAINT unique_user_push UNIQUE(user_id, repository_id, ref, after_sha)
);

-- Index for drafts page (pending drafts by user)
CREATE INDEX idx_drafts_user_status ON drafts(user_id, status);
-- Index for drafts sorted by creation time
CREATE INDEX idx_drafts_user_created ON drafts(user_id, created_at DESC);
```

### Post (Published)
```sql
CREATE TABLE posts (
    id UUID PRIMARY KEY,
    draft_id UUID NOT NULL REFERENCES drafts(id),
    platform VARCHAR(50) NOT NULL,
    platform_post_id VARCHAR(255),             -- ID from the platform
    platform_post_url VARCHAR(512),
    content TEXT NOT NULL,
    status VARCHAR(20) NOT NULL,               -- posted, failed
    error_message TEXT,
    posted_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Index for looking up posts by draft
CREATE INDEX idx_posts_draft ON posts(draft_id);
```

### Activity
```sql
CREATE TABLE activities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    type VARCHAR(50) NOT NULL,                 -- draft_created, post_success, post_failed
    draft_id UUID REFERENCES drafts(id),
    post_id UUID REFERENCES posts(id),
    platform VARCHAR(50),
    message TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Index for activity feed queries (newest first per user)
CREATE INDEX idx_activities_user_created ON activities(user_id, created_at DESC);
```

### Webhook Deliveries (Observability)
```sql
CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY,
    repository_id UUID NOT NULL REFERENCES repositories(id),
    delivery_id VARCHAR(255) NOT NULL,        -- X-GitHub-Delivery header
    event_type VARCHAR(50) NOT NULL,          -- push, etc.
    ref VARCHAR(255),                          -- refs/heads/main
    before_sha VARCHAR(40),
    after_sha VARCHAR(40),
    payload JSONB,                             -- Full webhook payload (for debugging)
    status VARCHAR(20) NOT NULL,               -- received, processed, ignored, failed
    error_message TEXT,
    processed_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_delivery UNIQUE(repository_id, delivery_id)
);

-- Index for listing deliveries by repository
CREATE INDEX idx_webhook_deliveries_repo ON webhook_deliveries(repository_id, created_at DESC);
```

---

## API Endpoints (Internal - Web UI Only)

All API endpoints use the `/api/v1/` prefix for versioning.

**Pagination:** List endpoints support `?limit=20&offset=0` query parameters. Default limit is 20, max is 100.

### Auth
- `POST /api/v1/auth/register` - Create account
- `POST /api/v1/auth/login` - Login
- `POST /api/v1/auth/logout` - Logout
- `GET /api/v1/auth/me` - Get current user info

### Auth (Post-MVP)
- `POST /api/v1/auth/forgot-password` - Request password reset email
- `POST /api/v1/auth/reset-password` - Set new password with reset token
- `DELETE /api/v1/auth/account` - Delete account and all data

### OAuth (MVP)
- `GET /oauth/github` - Initiate GitHub OAuth
- `GET /oauth/github/callback` - GitHub OAuth callback
- `GET /oauth/threads` - Initiate Threads OAuth
- `GET /oauth/threads/callback` - Threads OAuth callback

### OAuth (Post-MVP)
- `GET /oauth/linkedin` - Initiate LinkedIn OAuth
- `GET /oauth/linkedin/callback` - LinkedIn OAuth callback
- `GET /oauth/instagram` - Initiate Instagram OAuth
- `GET /oauth/instagram/callback` - Instagram OAuth callback

### Repositories
- `GET /api/v1/repos` - List user's connected repos
- `GET /api/v1/repos/available` - List available GitHub repos to connect
- `POST /api/v1/repos` - Connect selected repos
- `DELETE /api/v1/repos/:id` - Remove repo

### Drafts
- `GET /api/v1/drafts` - List pending drafts
- `GET /api/v1/drafts/:id` - Get draft details
- `PUT /api/v1/drafts/:id` - Update draft content (auto-save)
- `POST /api/v1/drafts/:id/regenerate` - Regenerate text content
- `POST /api/v1/drafts/:id/regenerate-image` - Regenerate image only (post-MVP)
- `POST /api/v1/drafts/:id/retry` - Retry failed draft generation
- `DELETE /api/v1/drafts/:id` - Delete draft

### Posts
- `POST /api/v1/drafts/:id/post` - Publish draft to selected platforms
- `GET /api/v1/posts` - List published posts

### Connections
- `GET /api/v1/connections` - List all connections with status
- `DELETE /api/v1/connections/:platform` - Disconnect platform

### Activity
- `GET /api/v1/activity` - Get activity feed

### Webhooks
- `POST /webhooks/github/:repo_id` - Receive GitHub webhooks

---

## MVP Scope

### Included in MVP

| Feature | Details |
|---------|---------|
| User signup/login | Email + password, 24-hour sessions |
| GitHub OAuth | Auto-discover repos, auto-install webhooks |
| **Threads OAuth** | **Primary social platform for MVP** |
| Auto draft generation | On any push to main |
| AI content generation | GPT-5.2 for text (uses commit messages + diffs) |
| Preview page | Mock card, editable text |
| Character limits | Show count (500 char Threads limit) |
| Regenerate content | New AI generation |
| Delete drafts | Dismiss without posting |
| Immediate posting | Post now (text-only) |
| Activity feed | Drafts, successes, failures |
| Drafts page | Queue of pending posts |
| Repository management | Add/remove repos |
| Connection management | Connect/disconnect Threads |
| Error handling | Show errors, keep draft, retry |

### Post-MVP (Future)

| Feature | Details |
|---------|---------|
| **GitHub App** | Replace per-user OAuth with GitHub App for simplified permissions, no per-user tokens, single webhook per repo with fan-out |
| **Organization repos** | Add `read:org` scope to access org repositories (requires GitHub App for best UX) |
| **AI image generation** | DALL-E images, uploaded to S3 with 30-day lifecycle |
| **Forgot password** | Email-based reset via AWS SES |
| **Delete account** | Hard delete all user data |
| **LinkedIn support** | Additional platform |
| **Instagram support** | Business/Creator accounts, feed posts |
| **Twitter/X support** | Additional platform |
| Scheduled posting | Pick date/time to post |
| Release tag filters | Only post for tagged releases |
| Email notifications | Notify on new drafts, failures |
| Per-platform images | Different aspect ratios/styles |
| Custom image upload | Use own image instead of AI |
| Pause/unpause repos | Temporarily stop tracking |
| Per-platform previews | See platform-specific mocks |
| Real-time updates | WebSocket for instant draft appearance |
| Public API | Programmatic access |
| Per-user branch selection | Track non-default branches, auto-update when repo default changes |

---

## Error States & Edge Cases

### No GitHub Connected
- Block access to main app
- Show "Connect GitHub to get started" prompt
- Required first step after signup

### No Repositories Selected
- Show empty state on Repos page
- Show prompt on Dashboard
- Can still connect social accounts

### No Social Accounts Connected
- Drafts still created
- Preview page shows "Connect accounts to post"
- Platform checkboxes disabled with "Connect" links

### Token Expired
- Show warning on Settings page
- Show error when trying to post
- Prompt to reconnect

### Rate Limited
- Show "Rate limit reached" error
- Display retry time if available
- Keep draft for retry

### Webhook Signature Invalid
- Reject webhook
- Log for debugging
- No user-facing error (security)

### AI Generation Fails
- Auto-retry up to 3 times
- If text generation fails: Create draft with error state, user can click "Retry" in activity feed

### Duplicate Webhook (Redeliveries)
- Idempotent: Don't create duplicate draft
- **Dual idempotency check**:
  1. Store `X-GitHub-Delivery` header per webhook delivery
  2. Dedupe drafts by `(user_id, repository_id, ref, after_sha)` tuple (enforced by DB constraint)
- This handles both exact redeliveries (same delivery ID) and GitHub retries with new delivery IDs

### User Disconnects Threads with Pending Drafts
- Keep drafts
- Show "Reconnect Threads to post" on affected drafts
- Cannot post until reconnected (Threads is only platform in MVP)

---

## Security Considerations

- Passwords hashed with bcrypt
- JWT tokens for session management
- OAuth tokens encrypted at rest
- Webhook signatures validated (HMAC-SHA256)
- HTTPS only
- CSRF protection on forms
- Rate limiting on auth endpoints
- Secrets in AWS Secrets Manager (production)

---

## Technical Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT                                   │
│                    (Web Browser)                                 │
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
│                      AWS LAMBDA                                  │
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
│  │   OpenAI     │  │   Social     │                             │
│  │   Client     │  │   Clients    │                             │
│  └──────────────┘  └──────────────┘                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
          │                   │                    │
          ▼                   ▼                    ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  PostgreSQL  │    │   OpenAI     │    │   Social     │
│    (RDS)     │    │     API      │    │    APIs      │
└──────────────┘    └──────────────┘    └──────────────┘
```

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-19 | Alice (Roxas Crew) | Initial spec |
| 1.1 | 2026-01-19 | Alice (Roxas Crew) | Threads as primary MVP platform; LinkedIn/Instagram moved to post-MVP |
| 1.2 | 2026-01-19 | Alice (Roxas Crew) | Added: AI failure handling, partial webhook success, forgot password, 24h sessions, auto-save editing, multi-commit handling |
| 1.3 | 2026-01-19 | Alice (Roxas Crew) | Moved forgot password & delete account to post-MVP; added draft 'error' status; clarified image storage & repo removal cleanup |
| 1.4 | 2026-01-19 | Alice (Roxas Crew) | Added: token expiration handling, pagination (load more), sort order (newest first), GitHub token expiry warning on repo removal |
| 1.5 | 2026-01-19 | Alice (Roxas Crew) | Added: duplicate repo handling, multi-user support, loading states, backend idempotency |
| 1.6 | 2026-01-19 | Alice (Roxas Crew) | MVP is text-only (image gen moved to post-MVP with S3 + 30-day lifecycle); AI now uses commit diffs via GitHub API; upgraded to GPT-5.2 |
| 1.7 | 2026-01-19 | Alice (Roxas Crew) | Personal repos only for MVP (org repos post-MVP); personalized AI drafts per user; smart diff summarization for large diffs; no commit URLs in posts |
| 1.8 | 2026-01-19 | Alice (Roxas Crew) | Dual idempotency (X-GitHub-Delivery + repo/ref/sha tuple); API versioning with /api/v1/ prefix |
| 1.9 | 2026-01-19 | Alice (Roxas Crew) | Added webhook_deliveries table for observability and debugging |
| 2.0 | 2026-01-19 | Alice (Roxas Crew) | Added async generation (Goroutine/fire-and-forget); GitHub App + org repos + per-user branch selection to post-MVP |
| 2.1 | 2026-01-20 | Alice (Roxas Crew) | Fixed draft schema for multi-commit push handling (commit_shas array, before/after SHA, ref field); clarified MVP vs post-MVP OAuth scopes; added activity feed index |
| 2.2 | 2026-01-20 | Alice (Roxas Crew) | Added 'partial' draft status for multi-platform partial failures; clarified commit message fetched from GitHub API; updated draft creation flow for multi-user fan-out; added indexes for repositories, drafts, and posts tables |
| 2.3 | 2026-01-20 | Alice (Roxas Crew) | Added posted_at to drafts schema; aligned JSON record with SQL (edited_content, error_message, updated_at); updated posting flow for partial success; added post-MVP activity types; fixed idempotency constraint to include ref; added API pagination docs; added webhook_deliveries index |
