# Implementation Plan: Roxas MVP

## Overview

This implementation plan breaks down the Roxas MVP into discrete coding tasks. The system is already production-ready and deployed, so these tasks document the existing implementation for reference and future enhancements. Tasks are organized to build incrementally, with testing integrated throughout.

## Tasks

- [ ] 1. Authentication and User Management
  - [ ] 1.1 Implement JWT token generation and validation
    - Create JWTManager with Generate() and Validate() methods
    - Set 24-hour expiration on all tokens
    - Include user ID in token claims
    - _Requirements: 1.4, 1.6, 1.8_
  
  - [ ] 1.2 Write property test for JWT token generation
    - **Property 3: JWT Token Generation**
    - **Validates: Requirements 1.4, 1.6**
  
  - [ ] 1.3 Write property test for expired token rejection
    - **Property 4: Expired Token Rejection**
    - **Validates: Requirements 1.8, 12.5**
  
  - [ ] 1.4 Implement password hashing with bcrypt
    - Create PasswordManager with Hash() and Verify() methods
    - Use bcrypt cost factor of 10
    - _Requirements: 1.1, 13.1_
  
  - [ ] 1.5 Write property test for password hashing
    - **Property 1: User Registration Creates Valid Accounts**
    - **Validates: Requirements 1.1, 1.4, 13.1**
  
  - [ ] 1.6 Implement user registration handler
    - Validate email format and password length (≥8 chars)
    - Hash password before storage
    - Generate JWT token on success
    - Return appropriate error messages
    - _Requirements: 1.1, 1.2, 1.3, 1.4_
  
  - [ ] 1.7 Write property test for password validation
    - **Property 2: Password Validation Rejects Short Passwords**
    - **Validates: Requirements 1.3**
  
  - [ ] 1.8 Write unit tests for registration edge cases
    - Test duplicate email rejection
    - Test invalid email format
    - Test empty fields
    - _Requirements: 1.2_
  
  - [ ] 1.9 Implement login handler
    - Validate credentials against stored hash
    - Generate JWT token on success
    - Return 401 for invalid credentials
    - _Requirements: 1.6, 1.7_
  
  - [ ] 1.10 Write unit tests for login scenarios
    - Test successful login
    - Test invalid credentials
    - Test missing fields
    - _Requirements: 1.7_
  
  - [ ] 1.11 Implement authentication middleware
    - Extract JWT from Authorization header
    - Validate token and inject user ID into context
    - Return 401 for missing/invalid tokens
    - _Requirements: 1.8, 12.5_
  
  - [ ] 1.12 Implement logout handler
    - Clear client-side token (return success response)
    - _Requirements: 1.9_

- [ ] 2. Database Layer and Data Stores
  - [ ] 2.1 Set up PostgreSQL connection pool
    - Configure connection parameters from environment
    - Implement health check
    - Handle connection failures gracefully
    - _Requirements: All data persistence requirements_
  
  - [ ] 2.2 Implement database migrations
    - Create migration files for all tables (users, repositories, platform_credentials, drafts, posts, activities, webhook_deliveries)
    - Add indexes for performance
    - Add unique constraints for data integrity
    - _Requirements: All data model requirements_
  
  - [ ] 2.3 Implement UserStore
    - Create() - insert new user with hashed password
    - GetByEmail() - fetch user for login
    - GetByID() - fetch user by ID
    - _Requirements: 1.1, 1.6_
  
  - [ ] 2.4 Write unit tests for UserStore
    - Test user creation
    - Test duplicate email handling
    - Test user retrieval
    - _Requirements: 1.1, 1.2_
  
  - [ ] 2.5 Implement CredentialStore with encryption
    - SaveCredentials() - encrypt tokens before storage
    - GetCredentials() - decrypt tokens after retrieval
    - DeleteCredentials() - remove platform credentials
    - Use AES-256-GCM for encryption
    - _Requirements: 2.3, 4.5, 4.6, 11.6, 13.2_
  
  - [ ] 2.6 Write property test for credential encryption
    - **Property 6: Credential Encryption**
    - **Validates: Requirements 2.3, 13.2**
  
  - [ ] 2.7 Implement RepositoryStore
    - Create() - store repository with webhook details
    - GetByID() - fetch repository by ID
    - ListByUser() - fetch user's repositories
    - GetUsersByRepo() - fetch all users tracking a repository
    - Delete() - remove repository connection
    - _Requirements: 3.6, 5.7, 10.7_
  
  - [ ] 2.8 Write property test for repository uniqueness
    - **Property 10: Multi-Tenant Webhook Installation**
    - **Validates: Requirements 3.9**
  
  - [ ] 2.9 Implement DraftStore
    - Create() - insert draft with uniqueness constraint
    - GetDraft() - fetch draft by ID
    - ListByUser() - fetch user's drafts with pagination
    - Update() - update draft content and status
    - Delete() - remove draft
    - _Requirements: 5.15, 5.19, 6.9, 9.1_
  
  - [ ] 2.10 Write property test for draft uniqueness
    - **Property 22: Draft Uniqueness Constraint**
    - **Validates: Requirements 5.19**
  
  - [ ] 2.11 Implement PostStore
    - Create() - insert post record
    - ListByDraft() - fetch posts for a draft
    - ListByUser() - fetch user's posts with pagination
    - _Requirements: 7.5_
  
  - [ ] 2.12 Implement ActivityStore
    - Create() - insert activity item
    - ListByUser() - fetch user's activity with pagination
    - _Requirements: 5.18, 7.8, 8.1_
  
  - [ ] 2.13 Write property test for activity pagination
    - **Property 29: Activity Feed Pagination**
    - **Validates: Requirements 8.1, 8.6**
  
  - [ ] 2.14 Implement WebhookDeliveryStore for idempotency
    - RecordDelivery() - store delivery ID
    - HasDelivery() - check if delivery was processed
    - _Requirements: 5.5, 5.6_

- [ ] 3. Checkpoint - Database layer complete
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 4. GitHub Integration
  - [ ] 4.1 Implement GitHubClient
    - ListRepositories() - fetch user's repos with admin access
    - CreateWebhook() - install webhook on repository
    - DeleteWebhook() - remove webhook from repository
    - GetCommitDiff() - fetch diff for a commit
    - ValidateWebhookSignature() - verify HMAC-SHA256
    - _Requirements: 2.4, 2.5, 3.3, 3.4, 5.1, 5.10, 10.5_
  
  - [ ] 4.2 Write property test for repository filtering
    - **Property 7: Repository Filtering by Admin Access**
    - **Validates: Requirements 2.5**
  
  - [ ] 4.3 Write property test for webhook signature validation
    - **Property 13: Webhook Signature Validation**
    - **Validates: Requirements 5.1, 5.2, 13.3, 13.4**
  
  - [ ] 4.4 Write unit tests for GitHub API integration
    - Test repository listing with mocked API
    - Test webhook creation with mocked API
    - Test webhook deletion with mocked API
    - Test commit diff fetching with mocked API
    - _Requirements: 2.4, 3.3, 5.10, 10.5_
  
  - [ ] 4.5 Implement GitHub OAuth flow
    - Generate OAuth URL with required scopes (repo, admin:repo_hook)
    - Exchange authorization code for access token
    - Store encrypted token in CredentialStore
    - _Requirements: 2.1, 2.2, 2.3_
  
  - [ ] 4.6 Write property test for OAuth URL generation
    - **Property 5: OAuth URL Contains Required Scopes**
    - **Validates: Requirements 2.1**
  
  - [ ] 4.7 Implement repository selection handler
    - Fetch available repositories via GitHubClient
    - Display repositories with admin access
    - Mark already-connected repositories
    - _Requirements: 2.4, 2.5, 2.6_
  
  - [ ] 4.8 Implement webhook installation handler
    - For each selected repository, generate unique secret
    - Install webhook via GitHubClient
    - Store repository record with webhook details
    - Handle partial failures gracefully
    - _Requirements: 3.3, 3.4, 3.5, 3.6, 3.7_
  
  - [ ] 4.9 Write property test for unique webhook secrets
    - **Property 8: Unique Webhook Secrets**
    - **Validates: Requirements 3.5**
  
  - [ ] 4.10 Write property test for webhook configuration
    - **Property 9: Webhook Configuration**
    - **Validates: Requirements 3.4, 3.6**
  
  - [ ] 4.11 Write unit test for partial webhook installation failure
    - Test that successful installations proceed when some fail
    - _Requirements: 3.7_

- [ ] 5. Bluesky Integration
  - [ ] 5.1 Implement BlueskyClient
    - Platform() - return "bluesky"
    - Authenticate() - create session with handle and app password
    - Post() - create post via com.atproto.repo.createRecord
    - ValidateContent() - check 300 char limit
    - ATURIToWebURL() - convert AT URI to bsky.app URL
    - IsAuthError() - detect authentication errors
    - IsRateLimitError() - detect rate limit errors
    - _Requirements: 4.3, 7.3, 7.4, 7.6, 7.10, 7.11_
  
  - [ ] 5.2 Write property test for handle normalization
    - **Property 11: Handle Normalization**
    - **Validates: Requirements 4.1, 4.2**
  
  - [ ] 5.3 Write property test for AT URI conversion
    - **Property 26: AT URI to Web URL Conversion**
    - **Validates: Requirements 7.6**
  
  - [ ] 5.4 Write unit tests for Bluesky API integration
    - Test session creation with mocked API
    - Test post creation with mocked API
    - Test content validation (char limit)
    - Test error handling (auth, rate limit)
    - _Requirements: 4.3, 4.4, 7.4, 7.10, 7.11_
  
  - [ ] 5.5 Implement Bluesky connection handler
    - Normalize handle (remove "@", add default domain)
    - Validate credentials by creating session
    - Store app password as access_token, handle as refresh_token
    - Store DID as platform_user_id
    - _Requirements: 4.1, 4.2, 4.3, 4.5, 4.6_
  
  - [ ] 5.6 Write property test for Bluesky credential storage
    - **Property 12: Bluesky Credential Storage**
    - **Validates: Requirements 4.5, 4.6**

- [ ] 6. AI Content Generation
  - [ ] 6.1 Implement OpenAIClient
    - GeneratePostText() - call GPT-5.2 API with prompt
    - Handle API errors and timeouts
    - _Requirements: 5.13_
  
  - [ ] 6.2 Implement DiffSummarizer
    - Summarize() - convert large diffs to file-level summaries
    - Use 500-line threshold
    - _Requirements: 5.11, 5.12_
  
  - [ ] 6.3 Write property test for diff summarization
    - **Property 19: Diff Summarization by Size**
    - **Validates: Requirements 5.11, 5.12**
  
  - [ ] 6.3 Implement PostGenerator
    - Generate() - create platform-specific content
    - Build prompt with commit messages, diffs, author, repo name
    - Include 300-character limit instruction for Bluesky
    - Handle generation failures with retry logic (up to 3 times)
    - _Requirements: 5.13, 5.14, 5.16, 5.17_
  
  - [ ] 6.4 Write property test for AI prompt construction
    - **Property 20: AI Prompt Construction**
    - **Validates: Requirements 5.13, 5.14**
  
  - [ ] 6.5 Write unit tests for AI generation
    - Test successful generation
    - Test retry logic on failure
    - Test error draft creation after 3 failures
    - _Requirements: 5.16, 5.17_

- [ ] 7. Checkpoint - External integrations complete
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 8. Webhook Processing and Draft Creation
  - [ ] 8.1 Implement webhook validation handler
    - Extract X-GitHub-Delivery header
    - Validate HMAC-SHA256 signature
    - Reject invalid signatures silently with logging
    - _Requirements: 5.1, 5.2, 12.4_
  
  - [ ] 8.2 Implement webhook idempotency check
    - Check if delivery ID was already processed
    - Return 200 for duplicate deliveries
    - _Requirements: 5.5, 5.6_
  
  - [ ] 8.3 Write property test for webhook idempotency
    - **Property 16: Webhook Idempotency**
    - **Validates: Requirements 5.5, 5.6**
  
  - [ ] 8.4 Implement webhook payload parsing
    - Extract ref, before_sha, after_sha, commit_shas
    - Filter for refs/heads/main only
    - _Requirements: 5.3, 5.4_
  
  - [ ] 8.5 Write property test for branch filtering
    - **Property 14: Branch Filtering**
    - **Validates: Requirements 5.3**
  
  - [ ] 8.6 Write property test for payload extraction
    - **Property 15: Webhook Payload Extraction**
    - **Validates: Requirements 5.4**
  
  - [ ] 8.7 Implement multi-tenant user lookup
    - GetUsersByRepo() to find all users tracking the repository
    - _Requirements: 5.7_
  
  - [ ] 8.8 Implement async draft creation
    - Return HTTP 200 immediately after validation
    - Launch Goroutine for async processing
    - For each subscribed user:
      - Fetch commit diffs via GitHubClient
      - Summarize diffs if > 500 lines
      - Generate content via PostGenerator
      - Create draft record with status "draft" or "error"
      - Create activity feed item
    - _Requirements: 5.8, 5.9, 5.10, 5.11, 5.15, 5.18_
  
  - [ ] 8.9 Write property test for multi-tenant draft creation
    - **Property 17: Multi-Tenant Draft Creation**
    - **Validates: Requirements 5.7, 5.9, 14.1, 14.2**
  
  - [ ] 8.10 Write property test for commit diff fetching
    - **Property 18: Commit Diff Fetching**
    - **Validates: Requirements 5.10**
  
  - [ ] 8.11 Write property test for draft creation with status
    - **Property 21: Draft Creation with Status**
    - **Validates: Requirements 5.15**
  
  - [ ] 8.12 Write property test for activity logging
    - **Property 23: Activity Logging on Draft Creation**
    - **Validates: Requirements 5.18, 12.2**
  
  - [ ] 8.13 Write unit test for immediate webhook response
    - Test that webhook handler returns 200 before async processing
    - _Requirements: 5.8_

- [ ] 9. Draft Management and Editing
  - [ ] 9.1 Implement draft list handler
    - Fetch drafts with status "draft" or "error"
    - Sort by created_at DESC
    - Support pagination (20 items per page)
    - _Requirements: 9.1, 9.6_
  
  - [ ] 9.2 Write property test for drafts list pagination
    - **Property 30: Drafts List Pagination**
    - **Validates: Requirements 9.1, 9.6**
  
  - [ ] 9.3 Implement draft detail handler
    - Fetch draft by ID
    - Return generated_content or edited_content
    - Include character count
    - _Requirements: 6.1, 6.2, 6.3_
  
  - [ ] 9.4 Implement draft update handler (auto-save)
    - Update edited_content field
    - Implement debouncing on client side
    - _Requirements: 6.4_
  
  - [ ] 9.5 Write unit test for draft auto-save
    - Test that edits are saved correctly
    - _Requirements: 6.4_
  
  - [ ] 9.6 Implement draft regeneration handler
    - Call PostGenerator for new content
    - Update generated_content field
    - Clear edited_content field
    - _Requirements: 6.7, 6.9_
  
  - [ ] 9.7 Write property test for draft content update
    - **Property 24: Draft Content Update**
    - **Validates: Requirements 6.9**
  
  - [ ] 9.8 Implement draft deletion handler
    - Delete draft record
    - _Requirements: 6.11_
  
  - [ ] 9.9 Write unit test for draft deletion
    - Test that draft is removed from database
    - _Requirements: 6.11_

- [ ] 10. Social Media Publishing
  - [ ] 10.1 Implement post validation
    - Check that at least one platform is connected
    - Validate content length for platform
    - _Requirements: 7.1, 7.2_
  
  - [ ] 10.2 Write unit test for platform validation
    - Test error when no platforms connected
    - _Requirements: 7.1, 7.2_
  
  - [ ] 10.3 Implement Bluesky posting handler
    - Get Bluesky credentials from CredentialStore
    - Create BlueskyClient with handle and app password
    - Call Post() with draft content
    - Handle errors (auth, rate limit, other)
    - _Requirements: 7.3, 7.4, 7.10, 7.11, 7.12_
  
  - [ ] 10.4 Write property test for Bluesky post creation
    - **Property 25: Bluesky Post Creation**
    - **Validates: Requirements 7.4**
  
  - [ ] 10.5 Write unit tests for posting error handling
    - Test rate limit error (429)
    - Test authentication error (401)
    - Test other API errors
    - _Requirements: 7.10, 7.11, 7.12_
  
  - [ ] 10.6 Implement post success workflow
    - Create post record with AT URI and web URL
    - Update draft status to "posted" with posted_at timestamp
    - Create activity feed item with post URL
    - _Requirements: 7.5, 7.6, 7.7, 7.8_
  
  - [ ] 10.7 Write property test for post success workflow
    - **Property 27: Post Success Workflow**
    - **Validates: Requirements 7.5, 7.7, 7.8**
  
  - [ ] 10.8 Implement post idempotency
    - Check if draft is already posted
    - Return success without re-posting
    - _Requirements: 7.14_
  
  - [ ] 10.9 Write property test for post idempotency
    - **Property 28: Post Idempotency**
    - **Validates: Requirements 7.14**
  
  - [ ] 10.10 Implement platform fallback logic
    - Try Bluesky first, then Threads if available
    - _Requirements: 7.15_
  
  - [ ] 10.11 Write unit test for platform fallback
    - Test that Threads is tried if Bluesky fails
    - _Requirements: 7.15_

- [ ] 11. Checkpoint - Core posting flow complete
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 12. Repository and Connection Management
  - [ ] 12.1 Implement repository list handler
    - Fetch user's repositories via RepositoryStore
    - Include post count and last push timestamp
    - _Requirements: 10.1, 10.2_
  
  - [ ] 12.2 Implement repository removal handler
    - Attempt to delete webhook via GitHubClient
    - Handle expired token gracefully with warning
    - Delete repository record from database
    - Keep existing drafts (orphaned)
    - _Requirements: 10.5, 10.6, 10.7, 10.8_
  
  - [ ] 12.3 Write property test for repository deletion
    - **Property 31: Repository Deletion Preserves Drafts**
    - **Validates: Requirements 10.7, 10.8**
  
  - [ ] 12.4 Write unit tests for repository removal
    - Test webhook deletion success
    - Test webhook deletion with expired token
    - Test draft preservation
    - _Requirements: 10.5, 10.6, 10.8_
  
  - [ ] 12.5 Implement connections list handler
    - Check for Bluesky credentials
    - Check for Threads credentials
    - Calculate token expiration status
    - _Requirements: 11.1, 11.2, 11.3, 11.4_
  
  - [ ] 12.6 Write property test for token expiration status
    - **Property 32: Token Expiration Status**
    - **Validates: Requirements 11.3, 11.4**
  
  - [ ] 12.7 Implement platform disconnection handler
    - Delete platform credentials
    - Keep existing drafts
    - _Requirements: 11.6, 11.7_
  
  - [ ] 12.8 Write property test for platform disconnection
    - **Property 33: Platform Disconnection Preserves Drafts**
    - **Validates: Requirements 11.6, 11.7**
  
  - [ ] 12.9 Implement GitHub disconnection handler
    - Delete all repository connections
    - Attempt to delete webhooks via GitHubClient
    - Delete GitHub credentials
    - _Requirements: 11.8_
  
  - [ ] 12.10 Write property test for GitHub disconnection cascade
    - **Property 34: GitHub Disconnection Cascades**
    - **Validates: Requirements 11.8**

- [ ] 13. Security and Middleware
  - [ ] 13.1 Implement CSRF protection middleware
    - Generate CSRF tokens for forms
    - Validate tokens on form submissions
    - Reject requests with missing/invalid tokens
    - _Requirements: 13.6_
  
  - [ ] 13.2 Write property test for CSRF protection
    - **Property 35: CSRF Protection**
    - **Validates: Requirements 13.6**
  
  - [ ] 13.3 Implement rate limiting middleware
    - Apply rate limits to auth endpoints (login, register)
    - Use token bucket algorithm
    - Return 429 when limit exceeded
    - _Requirements: 13.7_
  
  - [ ] 13.4 Write property test for rate limiting
    - **Property 36: Authentication Rate Limiting**
    - **Validates: Requirements 13.7**

- [ ] 14. Multi-Tenant Data Isolation
  - [ ] 14.1 Write property test for user data isolation
    - **Property 37: User Data Isolation**
    - **Validates: Requirements 14.3, 14.4**
  
  - [ ] 14.2 Write property test for draft independence
    - **Property 38: Draft Independence**
    - **Validates: Requirements 14.5**

- [ ] 15. Integration and Wiring
  - [ ] 15.1 Wire all handlers into HTTP router
    - Auth routes: /api/v1/auth/register, /api/v1/auth/login, /api/v1/auth/logout
    - OAuth routes: /oauth/github, /oauth/github/callback, /oauth/bluesky
    - Repository routes: /api/v1/repos, /api/v1/repos/:id
    - Draft routes: /api/v1/drafts, /api/v1/drafts/:id, /api/v1/drafts/:id/regenerate, /api/v1/drafts/:id/post
    - Connection routes: /api/v1/connections, /api/v1/connections/:platform
    - Activity route: /api/v1/activity
    - Webhook route: /webhooks/github/:repo_id
    - _Requirements: All API requirements_
  
  - [ ] 15.2 Apply middleware to routes
    - Auth middleware on protected routes
    - CSRF middleware on form submissions
    - Rate limiting on auth endpoints
    - _Requirements: 1.8, 13.6, 13.7_
  
  - [ ] 15.3 Configure environment variables
    - Database connection string
    - JWT secret
    - GitHub OAuth credentials
    - OpenAI API key
    - Encryption key for credentials
    - _Requirements: All configuration requirements_
  
  - [ ] 15.4 Set up AWS Lambda deployment
    - Configure API Gateway
    - Set up VPC and security groups
    - Configure RDS PostgreSQL
    - Set up Secrets Manager for production secrets
    - _Requirements: Infrastructure requirements_

- [ ] 16. Final Checkpoint - End-to-End Testing
  - [ ] 16.1 Run full integration test suite
    - Test complete user registration → GitHub connection → webhook → draft → publish flow
    - Test multi-tenant scenarios
    - Test error handling paths
    - _Requirements: All requirements_
  
  - [ ] 16.2 Verify all property tests pass
    - Ensure all 38 properties are tested
    - Verify minimum 100 iterations per property test
    - _Requirements: All correctness properties_
  
  - [ ] 16.3 Manual testing checklist
    - Complete pre-deployment checklist from design document
    - Verify security checklist items
    - Verify multi-tenant checklist items
    - _Requirements: All requirements_

## Notes

- All tasks are required for comprehensive testing and validation
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties (minimum 100 iterations each)
- Unit tests validate specific examples and edge cases
- The system is production-ready and deployed on AWS Lambda with PostgreSQL
