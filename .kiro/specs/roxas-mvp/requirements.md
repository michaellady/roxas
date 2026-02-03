# Requirements Document: Roxas MVP

## Introduction

Roxas is a production-ready application that automatically transforms GitHub commits into professional social media posts. When users push to their main branch, Roxas uses AI to generate engaging content, then allows users to preview, edit, and publish to social platforms. The MVP focuses on core functionality with Bluesky as the primary social platform, supporting text-only posts with a streamlined user experience.

## Glossary

- **System**: The Roxas application (web UI, API, and backend services)
- **User**: A registered Roxas account holder who connects GitHub repositories and social accounts
- **Draft**: An AI-generated social media post awaiting user review and publishing
- **Repository**: A GitHub repository connected to Roxas for automatic post generation
- **Platform**: A social media service (Bluesky in MVP; Threads, LinkedIn, Instagram post-MVP)
- **Push_Event**: A GitHub webhook notification when commits are pushed to a tracked branch
- **JWT_Token**: JSON Web Token used for user session authentication
- **Webhook**: GitHub's HTTP callback mechanism for notifying Roxas of repository events
- **Activity_Feed**: Chronological list of user events (drafts created, posts published, failures)
- **OAuth**: Authentication protocol for connecting external accounts (GitHub, Threads)
- **Main_Branch**: The default branch of a repository (typically "main" or "master")
- **Commit_Diff**: The code changes introduced by a commit, fetched via GitHub API
- **GPT**: OpenAI's language model (GPT-5.2) used for content generation
- **Character_Limit**: Maximum text length for a platform (300 chars for Bluesky)
- **Delivery_ID**: Unique identifier from GitHub's X-GitHub-Delivery header for webhook deduplication
- **App_Password**: Bluesky-specific authentication credential that doesn't expire
- **Handle**: Bluesky username (e.g., "user.bsky.social")
- **AT_Protocol**: The underlying protocol for Bluesky (Authenticated Transfer Protocol)

## Requirements

### Requirement 1: User Registration and Authentication

**User Story:** As a new user, I want to create an account with email and password, so that I can access Roxas and manage my social media posts.

#### Acceptance Criteria

1. WHEN a user submits a registration form with valid email and password, THE System SHALL create a new user account with hashed password
2. WHEN a user submits a registration form with an email that already exists, THE System SHALL reject the registration and return an error message
3. WHEN a user submits a registration form with a password shorter than 8 characters, THE System SHALL reject the registration and return a validation error
4. WHEN a user successfully registers, THE System SHALL generate a JWT_Token with 24-hour expiration
5. WHEN a user successfully registers, THE System SHALL redirect to the GitHub OAuth connection flow
6. WHEN a user submits valid login credentials, THE System SHALL generate a JWT_Token with 24-hour expiration
7. WHEN a user submits invalid login credentials, THE System SHALL reject the login and return an error message
8. WHEN a JWT_Token expires after 24 hours, THE System SHALL require the user to re-authenticate
9. WHEN a user logs out, THE System SHALL invalidate the JWT_Token and redirect to the login page

### Requirement 2: GitHub Account Connection

**User Story:** As a user, I want to connect my GitHub account, so that Roxas can access my repositories and install webhooks.

#### Acceptance Criteria

1. WHEN a user initiates GitHub OAuth, THE System SHALL redirect to GitHub's authorization page with required scopes (repo, admin:repo_hook)
2. WHEN GitHub redirects back with an authorization code, THE System SHALL exchange the code for an access token
3. WHEN the System receives a GitHub access token, THE System SHALL store the encrypted token in the platform_credentials table
4. WHEN the System receives a GitHub access token, THE System SHALL fetch the user's personal repositories via GitHub API
5. WHEN fetching repositories, THE System SHALL filter to only repositories where the user has admin access
6. WHEN the System successfully connects GitHub, THE System SHALL display a repository selection page
7. WHEN a user has no GitHub connection, THE System SHALL block access to the main application and display a connection prompt

### Requirement 3: Repository Selection and Webhook Installation

**User Story:** As a user, I want to select which repositories to track, so that Roxas generates posts only for the projects I choose.

#### Acceptance Criteria

1. WHEN displaying the repository selection page, THE System SHALL show all personal repositories with admin access
2. WHEN displaying the repository selection page, THE System SHALL mark already-connected repositories as disabled with a "Connected" label
3. WHEN a user selects repositories and submits, THE System SHALL install a webhook on each selected repository via GitHub API
4. WHEN installing a webhook, THE System SHALL configure it to listen for push events to the main branch
5. WHEN installing a webhook, THE System SHALL generate a unique secret for signature validation
6. WHEN installing a webhook, THE System SHALL store the repository record with webhook_id and webhook_secret
7. WHEN webhook installation fails for some repositories, THE System SHALL continue with successful installations and display partial success message
8. WHEN webhook installation completes, THE System SHALL redirect to the Connections page
9. WHEN multiple users connect the same repository, THE System SHALL install separate webhooks for each user

### Requirement 4: Bluesky Account Connection

**User Story:** As a user, I want to connect my Bluesky account using my handle and app password, so that I can publish generated posts to my social media.

#### Acceptance Criteria

1. WHEN a user submits a Bluesky handle and app password, THE System SHALL normalize the handle by removing "@" prefix
2. WHEN a handle does not contain a domain, THE System SHALL append ".bsky.social" as the default domain
3. WHEN a user submits Bluesky credentials, THE System SHALL validate them by creating a session with the Bluesky API
4. WHEN Bluesky authentication fails, THE System SHALL return an error message indicating invalid credentials
5. WHEN Bluesky authentication succeeds, THE System SHALL store the app password as access_token and handle as refresh_token
6. WHEN Bluesky authentication succeeds, THE System SHALL store the user's DID (Decentralized Identifier) as platform_user_id
7. WHEN the System successfully connects Bluesky, THE System SHALL redirect to the Connections page with success message
8. WHEN a user has no connected social platforms, THE System SHALL display a connection prompt

### Requirement 5: Automated Draft Generation from Push Events

**User Story:** As a user, I want Roxas to automatically generate post drafts when I push to main, so that I don't have to manually create content for my commits.

#### Acceptance Criteria

1. WHEN GitHub sends a push webhook to a tracked repository, THE System SHALL validate the webhook signature using HMAC-SHA256
2. WHEN a webhook signature is invalid, THE System SHALL reject the webhook and log the attempt
3. WHEN a valid push webhook is received for a non-main branch, THE System SHALL ignore the webhook
4. WHEN a valid push webhook is received for the main branch, THE System SHALL extract the ref, before_sha, after_sha, and commit_shas
5. WHEN processing a push webhook, THE System SHALL check for duplicate delivery using the X-GitHub-Delivery header
6. WHEN a duplicate webhook delivery is detected, THE System SHALL return success without creating a new draft
7. WHEN processing a push webhook, THE System SHALL identify all users who have connected that repository
8. WHEN processing a push webhook, THE System SHALL return HTTP 200 immediately after validation and recording
9. WHEN processing a push webhook, THE System SHALL initiate async content generation for each subscribed user
10. WHEN generating content, THE System SHALL fetch commit diffs via GitHub API for all commits in the push
11. WHEN a commit diff exceeds 500 lines, THE System SHALL send a file-level summary instead of the full diff
12. WHEN a commit diff is under 500 lines, THE System SHALL send the full diff content to GPT
13. WHEN generating content, THE System SHALL call GPT-5.2 with commit messages, diffs, author, and repository name
14. WHEN generating content, THE System SHALL instruct GPT-5.2 to generate text within the platform character limit (300 chars for Bluesky)
15. WHEN GPT successfully generates content, THE System SHALL create a draft record with status "draft"
16. WHEN GPT content generation fails, THE System SHALL retry up to 3 times
17. WHEN GPT content generation fails after 3 retries, THE System SHALL create a draft record with status "error" and error message
18. WHEN a draft is created, THE System SHALL create an activity feed item for the user
19. WHEN creating a draft, THE System SHALL enforce uniqueness by (user_id, repository_id, ref, after_sha) tuple

### Requirement 6: Draft Preview and Editing

**User Story:** As a user, I want to preview and edit generated drafts, so that I can refine the content before publishing.

#### Acceptance Criteria

1. WHEN a user opens a draft, THE System SHALL display the generated content in an editable text area
2. WHEN a user opens a draft, THE System SHALL display a mock social media card preview
3. WHEN a user opens a draft, THE System SHALL display a character count with the platform limit (300 for Bluesky)
4. WHEN a user edits draft content, THE System SHALL auto-save changes with debouncing
5. WHEN a user edits draft content, THE System SHALL update the character count in real-time
6. WHEN a user edits draft content exceeding the character limit, THE System SHALL display a warning
7. WHEN a user clicks "Regenerate", THE System SHALL call GPT-5.2 for new content generation
8. WHEN regeneration is in progress, THE System SHALL disable all buttons and display a loading spinner
9. WHEN regeneration completes, THE System SHALL update the draft with new generated_content
10. WHEN a user clicks "Delete Draft", THE System SHALL display a confirmation modal
11. WHEN a user confirms draft deletion, THE System SHALL remove the draft record
12. WHEN displaying platform selection, THE System SHALL show checkboxes for connected platforms
13. WHEN displaying platform selection, THE System SHALL show "Connect now" links for disconnected platforms
14. WHEN a user has no connected social platforms, THE System SHALL disable the "Post It" button and display a connection prompt

### Requirement 7: Social Media Publishing

**User Story:** As a user, I want to publish approved drafts to Bluesky, so that my followers can see my development updates.

#### Acceptance Criteria

1. WHEN a user clicks "Post It", THE System SHALL validate that at least one platform is selected
2. WHEN no platforms are selected, THE System SHALL display an error message
3. WHEN posting to Bluesky, THE System SHALL create a session using the stored app password and handle
4. WHEN posting to Bluesky, THE System SHALL call the Bluesky API (com.atproto.repo.createRecord) with the draft content
5. WHEN the Bluesky API returns success, THE System SHALL create a post record with status "posted" and the AT Protocol URI
6. WHEN the Bluesky API returns success, THE System SHALL convert the AT Protocol URI to a web URL (bsky.app format)
7. WHEN the Bluesky API returns success, THE System SHALL update the draft status to "posted" and set posted_at timestamp
8. WHEN the Bluesky API returns success, THE System SHALL create an activity feed item with the post URL
9. WHEN the Bluesky API returns success, THE System SHALL redirect to the activity feed with a success toast
10. WHEN the Bluesky API returns a rate limit error (429), THE System SHALL display an error with retry time
11. WHEN the Bluesky API returns an authentication error (401), THE System SHALL display a reconnection prompt
12. WHEN the Bluesky API returns any other error, THE System SHALL keep the draft status as "draft" and display the error message
13. WHEN posting fails, THE System SHALL allow the user to retry posting
14. WHEN a user double-clicks "Post It", THE System SHALL handle the duplicate request idempotently
15. WHEN a user has both Bluesky and Threads connected, THE System SHALL attempt Bluesky first then fall back to Threads

### Requirement 8: Activity Feed

**User Story:** As a user, I want to see a chronological feed of my posting activity, so that I can track what has been generated and published.

#### Acceptance Criteria

1. WHEN a user views the Dashboard, THE System SHALL display the 20 most recent activity items sorted by newest first
2. WHEN displaying activity items, THE System SHALL show the activity type, message, and timestamp
3. WHEN displaying a "draft created" activity, THE System SHALL include a clickable link to the draft preview
4. WHEN displaying a "post successful" activity, THE System SHALL include a clickable link to the platform post URL
5. WHEN displaying a "post failed" activity, THE System SHALL include the error message and a retry action
6. WHEN a user clicks "Load more", THE System SHALL fetch the next 20 activity items
7. WHEN a user has no activity, THE System SHALL display an empty state message

### Requirement 9: Drafts Management

**User Story:** As a user, I want to view all pending drafts in one place, so that I can review and publish them at my convenience.

#### Acceptance Criteria

1. WHEN a user views the Drafts page, THE System SHALL display all drafts with status "draft" or "error" sorted by newest first
2. WHEN displaying a draft card, THE System SHALL show the commit message as the title
3. WHEN displaying a draft card, THE System SHALL show the repository name and time since creation
4. WHEN displaying a draft card, THE System SHALL show a truncated preview of the generated content
5. WHEN displaying a draft card, THE System SHALL include a "Preview" button linking to the draft detail page
6. WHEN a user clicks "Load more", THE System SHALL fetch the next 20 drafts
7. WHEN a user has no pending drafts, THE System SHALL display an empty state message

### Requirement 10: Repository Management

**User Story:** As a user, I want to manage my connected repositories, so that I can add or remove repositories from tracking.

#### Acceptance Criteria

1. WHEN a user views the Repositories page, THE System SHALL display all connected repositories
2. WHEN displaying a repository card, THE System SHALL show the repository name, visibility, post count, and last push timestamp
3. WHEN a user clicks "Add Repos", THE System SHALL display the repository selection modal
4. WHEN a user clicks "Remove" on a repository, THE System SHALL display a confirmation modal
5. WHEN a user confirms repository removal, THE System SHALL attempt to delete the webhook via GitHub API
6. WHEN webhook deletion fails due to expired token, THE System SHALL display a warning about manual cleanup
7. WHEN a user confirms repository removal, THE System SHALL remove the repository record from the database
8. WHEN a repository is removed, THE System SHALL keep existing drafts from that repository
9. WHEN a user has no connected repositories, THE System SHALL display an empty state with a connection prompt

### Requirement 11: Connection Management

**User Story:** As a user, I want to manage my connected accounts, so that I can disconnect or reconnect platforms as needed.

#### Acceptance Criteria

1. WHEN a user views the Settings page, THE System SHALL display all platform connections with their status
2. WHEN displaying a connected platform, THE System SHALL show the platform name, username, and connection health
3. WHEN a platform token is expiring within 7 days, THE System SHALL display a warning indicator
4. WHEN a platform token is expired, THE System SHALL display an error indicator and "Reconnect" button
5. WHEN a user clicks "Disconnect" on a platform, THE System SHALL display a confirmation modal
6. WHEN a user confirms disconnection, THE System SHALL remove the platform credentials from the database
7. WHEN a user disconnects a platform, THE System SHALL keep existing drafts but disable posting until reconnection
8. WHEN a user disconnects GitHub, THE System SHALL remove all repository connections and webhooks

### Requirement 12: Error Handling and Edge Cases

**User Story:** As a user, I want clear error messages and recovery options, so that I can resolve issues and continue using Roxas.

#### Acceptance Criteria

1. WHEN any API call fails, THE System SHALL display a user-friendly error message
2. WHEN a draft generation fails, THE System SHALL create an activity item with "Retry" action
3. WHEN a user retries a failed draft, THE System SHALL attempt content generation again
4. WHEN a webhook delivery fails validation, THE System SHALL log the failure without notifying the user
5. WHEN a user attempts an action requiring authentication with an expired token, THE System SHALL redirect to login
6. WHEN a user attempts to post without connected platforms, THE System SHALL display a connection prompt
7. WHEN the System encounters a database error, THE System SHALL log the error and display a generic error message
8. WHEN the System encounters a rate limit from an external API, THE System SHALL display the retry time if available

### Requirement 13: Security and Data Protection

**User Story:** As a user, I want my data to be secure, so that my credentials and content are protected.

#### Acceptance Criteria

1. WHEN a user registers, THE System SHALL hash the password using bcrypt before storage
2. WHEN storing OAuth tokens, THE System SHALL encrypt the tokens at rest
3. WHEN receiving a webhook, THE System SHALL validate the signature using the stored webhook secret
4. WHEN a webhook signature validation fails, THE System SHALL reject the request and log the attempt
5. THE System SHALL enforce HTTPS for all API endpoints
6. THE System SHALL implement CSRF protection on all form submissions
7. THE System SHALL implement rate limiting on authentication endpoints
8. WHEN storing secrets in production, THE System SHALL use AWS Secrets Manager

### Requirement 14: Multi-Tenant Support

**User Story:** As a user, I want my drafts to be personalized to me, so that multiple users tracking the same repository receive unique content.

#### Acceptance Criteria

1. WHEN a push event occurs on a repository tracked by multiple users, THE System SHALL generate a separate draft for each user
2. WHEN generating content for multiple users, THE System SHALL call GPT-5.2 separately for each user
3. WHEN a user views their drafts, THE System SHALL only display drafts associated with their user_id
4. WHEN a user views their activity feed, THE System SHALL only display activities associated with their user_id
5. WHEN a user posts a draft, THE System SHALL not affect drafts for other users tracking the same repository
