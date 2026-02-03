package database

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// TestProperty22_DraftUniquenessConstraint tests Property 22:
// Draft uniqueness enforced by (user_id, repository_id, ref, after_sha) tuple.
// Validates Requirements 5.19
//
// The uniqueness constraint ensures that:
// 1. Duplicate tuples are rejected with ErrDuplicateDraft
// 2. Changing any single field allows a new draft to be created
// 3. Different combinations of the 4-tuple can coexist
func TestProperty22_DraftUniquenessConstraint(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping property test requiring database in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg := getTestDatabaseConfig()
	pool, err := NewPool(ctx, cfg)
	if err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer pool.Close()

	if err := RunMigrations(pool); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	parameters.MaxSize = 20
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	// Property 22a: Duplicate (user_id, repository_id, ref, after_sha) is rejected
	properties.Property("duplicate tuple is rejected with ErrDuplicateDraft", prop.ForAll(
		func(ref string, afterSHA string) bool {
			// Clean and create fresh user/repo for each test
			testCtx, testCancel := context.WithTimeout(ctx, 10*time.Second)
			defer testCancel()

			cleanupDraftTestData(t, testCtx, pool)
			userID := createTestUser(t, testCtx, pool, "prop22a@example.com")
			repoID := createTestRepository(t, testCtx, pool, userID, "https://github.com/test/prop22a-repo")

			store := NewDraftStore(pool)

			// Create first draft - should succeed
			_, err := store.CreateDraft(testCtx, userID, repoID, ref, "before1", afterSHA, []string{afterSHA}, "Content 1")
			if err != nil {
				return false
			}

			// Create second draft with same tuple - should fail with ErrDuplicateDraft
			_, err = store.CreateDraft(testCtx, userID, repoID, ref, "before2", afterSHA, []string{afterSHA}, "Content 2")
			return errors.Is(err, ErrDuplicateDraft)
		},
		genGitRef(),
		genGitSHA(),
	))

	// Property 22b: Different after_sha allows creation (same user_id, repository_id, ref)
	properties.Property("different after_sha allows draft creation", prop.ForAll(
		func(ref string, afterSHA1, afterSHA2 string) bool {
			if afterSHA1 == afterSHA2 {
				return true // Skip if SHAs happen to be the same
			}

			testCtx, testCancel := context.WithTimeout(ctx, 10*time.Second)
			defer testCancel()

			cleanupDraftTestData(t, testCtx, pool)
			userID := createTestUser(t, testCtx, pool, "prop22b@example.com")
			repoID := createTestRepository(t, testCtx, pool, userID, "https://github.com/test/prop22b-repo")

			store := NewDraftStore(pool)

			// Create first draft
			_, err := store.CreateDraft(testCtx, userID, repoID, ref, "before1", afterSHA1, []string{afterSHA1}, "Content 1")
			if err != nil {
				return false
			}

			// Create second draft with different after_sha - should succeed
			_, err = store.CreateDraft(testCtx, userID, repoID, ref, "before2", afterSHA2, []string{afterSHA2}, "Content 2")
			return err == nil
		},
		genGitRef(),
		genGitSHA(),
		genGitSHA(),
	))

	// Property 22c: Different ref allows creation (same user_id, repository_id, after_sha)
	properties.Property("different ref allows draft creation", prop.ForAll(
		func(ref1, ref2, afterSHA string) bool {
			if ref1 == ref2 {
				return true // Skip if refs happen to be the same
			}

			testCtx, testCancel := context.WithTimeout(ctx, 10*time.Second)
			defer testCancel()

			cleanupDraftTestData(t, testCtx, pool)
			userID := createTestUser(t, testCtx, pool, "prop22c@example.com")
			repoID := createTestRepository(t, testCtx, pool, userID, "https://github.com/test/prop22c-repo")

			store := NewDraftStore(pool)

			// Create first draft
			_, err := store.CreateDraft(testCtx, userID, repoID, ref1, "before1", afterSHA, []string{afterSHA}, "Content 1")
			if err != nil {
				return false
			}

			// Create second draft with different ref - should succeed
			_, err = store.CreateDraft(testCtx, userID, repoID, ref2, "before2", afterSHA, []string{afterSHA}, "Content 2")
			return err == nil
		},
		genGitRef(),
		genGitRef(),
		genGitSHA(),
	))

	// Property 22d: Different repository_id allows creation (same user_id, ref, after_sha)
	properties.Property("different repository_id allows draft creation", prop.ForAll(
		func(ref, afterSHA string) bool {
			testCtx, testCancel := context.WithTimeout(ctx, 10*time.Second)
			defer testCancel()

			cleanupDraftTestData(t, testCtx, pool)
			userID := createTestUser(t, testCtx, pool, "prop22d@example.com")
			repoID1 := createTestRepository(t, testCtx, pool, userID, "https://github.com/test/prop22d-repo1")
			repoID2 := createTestRepository(t, testCtx, pool, userID, "https://github.com/test/prop22d-repo2")

			store := NewDraftStore(pool)

			// Create first draft
			_, err := store.CreateDraft(testCtx, userID, repoID1, ref, "before1", afterSHA, []string{afterSHA}, "Content 1")
			if err != nil {
				return false
			}

			// Create second draft with different repository_id - should succeed
			_, err = store.CreateDraft(testCtx, userID, repoID2, ref, "before2", afterSHA, []string{afterSHA}, "Content 2")
			return err == nil
		},
		genGitRef(),
		genGitSHA(),
	))

	// Property 22e: Different user_id allows creation (same repository_id, ref, after_sha)
	properties.Property("different user_id allows draft creation", prop.ForAll(
		func(ref, afterSHA string) bool {
			testCtx, testCancel := context.WithTimeout(ctx, 10*time.Second)
			defer testCancel()

			cleanupDraftTestData(t, testCtx, pool)
			userID1 := createTestUser(t, testCtx, pool, "prop22e-user1@example.com")
			userID2 := createTestUser(t, testCtx, pool, "prop22e-user2@example.com")
			// Both users share access to the same repository (common in multi-tenant setups)
			repoID := createTestRepository(t, testCtx, pool, userID1, "https://github.com/test/prop22e-repo")

			store := NewDraftStore(pool)

			// Create first draft for user1
			_, err := store.CreateDraft(testCtx, userID1, repoID, ref, "before1", afterSHA, []string{afterSHA}, "Content 1")
			if err != nil {
				return false
			}

			// Create second draft for user2 with same repo/ref/sha - should succeed
			_, err = store.CreateDraft(testCtx, userID2, repoID, ref, "before2", afterSHA, []string{afterSHA}, "Content 2")
			return err == nil
		},
		genGitRef(),
		genGitSHA(),
	))

	// Property 22f: All four components must match for duplicate rejection
	properties.Property("all four tuple components must match for duplicate", prop.ForAll(
		func(ref1, ref2, afterSHA1, afterSHA2 string, changeIndex int) bool {
			testCtx, testCancel := context.WithTimeout(ctx, 10*time.Second)
			defer testCancel()

			cleanupDraftTestData(t, testCtx, pool)
			userID1 := createTestUser(t, testCtx, pool, "prop22f-user1@example.com")
			userID2 := createTestUser(t, testCtx, pool, "prop22f-user2@example.com")
			repoID1 := createTestRepository(t, testCtx, pool, userID1, "https://github.com/test/prop22f-repo1")
			repoID2 := createTestRepository(t, testCtx, pool, userID1, "https://github.com/test/prop22f-repo2")

			store := NewDraftStore(pool)

			// Create first draft with base tuple
			_, err := store.CreateDraft(testCtx, userID1, repoID1, ref1, "before1", afterSHA1, []string{afterSHA1}, "Content 1")
			if err != nil {
				return false
			}

			// Determine which component to change based on changeIndex
			useUserID := userID1
			useRepoID := repoID1
			useRef := ref1
			useAfterSHA := afterSHA1

			switch changeIndex % 4 {
			case 0:
				useUserID = userID2
			case 1:
				useRepoID = repoID2
			case 2:
				if ref2 != ref1 {
					useRef = ref2
				} else {
					useRef = ref1 + "-different"
				}
			case 3:
				if afterSHA2 != afterSHA1 {
					useAfterSHA = afterSHA2
				} else {
					useAfterSHA = afterSHA1[:len(afterSHA1)-1] + "0"
				}
			}

			// Create second draft with one component changed - should succeed
			_, err = store.CreateDraft(testCtx, useUserID, useRepoID, useRef, "before2", useAfterSHA, []string{useAfterSHA}, "Content 2")
			return err == nil
		},
		genGitRef(),
		genGitRef(),
		genGitSHA(),
		genGitSHA(),
		gen.IntRange(0, 100),
	))

	properties.TestingRun(t)
}

// TestProperty22_DraftUniquenessIdempotency tests that the uniqueness constraint
// provides idempotency for push events - the same push received twice results
// in only one draft.
func TestProperty22_DraftUniquenessIdempotency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping property test requiring database in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg := getTestDatabaseConfig()
	pool, err := NewPool(ctx, cfg)
	if err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer pool.Close()

	if err := RunMigrations(pool); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 30
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	// Property: Multiple attempts to create the same draft result in exactly one record
	properties.Property("duplicate creation attempts are idempotent", prop.ForAll(
		func(ref, afterSHA string, attemptCount int) bool {
			testCtx, testCancel := context.WithTimeout(ctx, 10*time.Second)
			defer testCancel()

			cleanupDraftTestData(t, testCtx, pool)
			userID := createTestUser(t, testCtx, pool, "prop22-idem@example.com")
			repoID := createTestRepository(t, testCtx, pool, userID, "https://github.com/test/prop22-idem-repo")

			store := NewDraftStore(pool)

			// Normalize attempt count to reasonable range
			attempts := (attemptCount % 5) + 2 // 2-6 attempts

			var successCount int
			var duplicateCount int

			for i := 0; i < attempts; i++ {
				_, err := store.CreateDraft(testCtx, userID, repoID, ref, "before", afterSHA, []string{afterSHA}, "Content")
				if err == nil {
					successCount++
				} else if errors.Is(err, ErrDuplicateDraft) {
					duplicateCount++
				} else {
					return false // Unexpected error
				}
			}

			// Property: Exactly one success, rest are duplicates
			return successCount == 1 && duplicateCount == attempts-1
		},
		genGitRef(),
		genGitSHA(),
		gen.IntRange(0, 100),
	))

	properties.TestingRun(t)
}

// genGitRef generates valid Git ref strings (e.g., refs/heads/main)
func genGitRef() gopter.Gen {
	branchName := gen.RegexMatch(`[a-z][a-z0-9-]{2,20}`)
	refType := gen.OneConstOf("refs/heads/", "refs/tags/")

	return gopter.CombineGens(refType, branchName).Map(func(vals []interface{}) string {
		return vals[0].(string) + vals[1].(string)
	})
}

// genGitSHA generates valid 40-character Git SHA strings
func genGitSHA() gopter.Gen {
	return gen.RegexMatch(`[0-9a-f]{40}`)
}
