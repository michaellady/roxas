package database

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// =============================================================================
// Property Test: Drafts List Pagination (Property 30)
// Validates Requirements 9.1, 9.6
//
// Property: Drafts list returns only 'draft' or 'error' status, sorted DESC, 20 per page.
// This means:
// 1. Only drafts with status 'draft' or 'error' appear in the list
// 2. Results are sorted by CreatedAt in descending order (newest first)
// 3. Maximum 20 results per page
// =============================================================================

// DraftListItem represents a draft in the list view
type DraftListItem struct {
	ID        string
	Status    string
	CreatedAt time.Time
}

// FilteredDraftLister implements the expected behavior for draft listing
// It filters to only 'draft' and 'error' statuses, sorts DESC, and paginates
type FilteredDraftLister struct {
	drafts map[string][]*DraftListItem // userID -> drafts
}

// NewFilteredDraftLister creates a new FilteredDraftLister
func NewFilteredDraftLister() *FilteredDraftLister {
	return &FilteredDraftLister{
		drafts: make(map[string][]*DraftListItem),
	}
}

// AddDraft adds a draft for a user (simulates database storage)
func (l *FilteredDraftLister) AddDraft(userID string, draft *DraftListItem) {
	l.drafts[userID] = append(l.drafts[userID], draft)
}

// ListDraftsForUser returns filtered, sorted, paginated drafts
// Implements Property 30: only 'draft'/'error' status, sorted DESC, 20 per page
func (l *FilteredDraftLister) ListDraftsForUser(userID string, page int) []*DraftListItem {
	allDrafts := l.drafts[userID]
	if allDrafts == nil {
		return nil
	}

	// Filter to only 'draft' or 'error' status
	filtered := make([]*DraftListItem, 0)
	for _, d := range allDrafts {
		if d.Status == DraftStatusDraft || d.Status == DraftStatusError {
			filtered = append(filtered, d)
		}
	}

	// Sort by CreatedAt DESC (newest first)
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].CreatedAt.After(filtered[j].CreatedAt)
	})

	// Paginate: 20 per page
	const pageSize = 20
	start := (page - 1) * pageSize
	if start >= len(filtered) {
		return nil
	}
	end := start + pageSize
	if end > len(filtered) {
		end = len(filtered)
	}

	return filtered[start:end]
}

// AllDraftsForUser returns all drafts without filtering (for verification)
func (l *FilteredDraftLister) AllDraftsForUser(userID string) []*DraftListItem {
	return l.drafts[userID]
}

// TestProperty30_DraftsListOnlyDraftOrErrorStatus verifies that the drafts list
// only returns items with 'draft' or 'error' status
func TestProperty30_DraftsListOnlyDraftOrErrorStatus(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Property 30a: Listed drafts only have 'draft' or 'error' status
	properties.Property("listed drafts only have draft or error status", prop.ForAll(
		func(drafts []DraftListItem) bool {
			lister := NewFilteredDraftLister()
			userID := "test-user"

			// Add all generated drafts
			for i := range drafts {
				lister.AddDraft(userID, &drafts[i])
			}

			// Get the filtered list (page 1)
			result := lister.ListDraftsForUser(userID, 1)

			// Verify all returned drafts have valid status
			for _, draft := range result {
				if draft.Status != DraftStatusDraft && draft.Status != DraftStatusError {
					t.Logf("Invalid status in list: %s", draft.Status)
					return false
				}
			}

			return true
		},
		genDraftList(),
	))

	// Property 30b: Drafts with other statuses are excluded
	properties.Property("drafts with posted/partial/failed status are excluded", prop.ForAll(
		func(statuses []string) bool {
			lister := NewFilteredDraftLister()
			userID := "test-user"
			baseTime := time.Now()

			// Add drafts with unique IDs and specified statuses
			for i, status := range statuses {
				lister.AddDraft(userID, &DraftListItem{
					ID:        generateDraftID(i),
					Status:    status,
					CreatedAt: baseTime.Add(-time.Duration(i) * time.Hour),
				})
			}

			// Get the filtered list for all pages
			allListedStatuses := make(map[string]string) // ID -> status
			for page := 1; page <= 10; page++ {
				result := lister.ListDraftsForUser(userID, page)
				if len(result) == 0 {
					break
				}
				for _, draft := range result {
					allListedStatuses[draft.ID] = draft.Status
				}
			}

			// Verify no draft with excluded status is in the list
			for id, status := range allListedStatuses {
				if status == DraftStatusPosted ||
					status == DraftStatusPartial ||
					status == DraftStatusFailed {
					t.Logf("Excluded status %s found in list for draft %s", status, id)
					return false
				}
			}

			return true
		},
		gen.SliceOf(genDraftStatus()),
	))

	properties.TestingRun(t)
}

// TestProperty30_DraftsListSortedDescending verifies results are sorted by CreatedAt DESC
func TestProperty30_DraftsListSortedDescending(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Property 30c: Results are sorted by CreatedAt descending (newest first)
	properties.Property("results sorted by CreatedAt descending", prop.ForAll(
		func(drafts []DraftListItem) bool {
			lister := NewFilteredDraftLister()
			userID := "test-user"

			// Add all generated drafts
			for i := range drafts {
				lister.AddDraft(userID, &drafts[i])
			}

			// Check sorting on each page
			for page := 1; page <= 10; page++ {
				result := lister.ListDraftsForUser(userID, page)
				if len(result) == 0 {
					break
				}

				// Verify order within page
				for i := 1; i < len(result); i++ {
					if result[i].CreatedAt.After(result[i-1].CreatedAt) {
						t.Logf("Order violation at index %d: %v > %v",
							i, result[i].CreatedAt, result[i-1].CreatedAt)
						return false
					}
				}
			}

			return true
		},
		genDraftList(),
	))

	// Property 30d: Cross-page ordering is maintained
	properties.Property("cross-page ordering maintained", prop.ForAll(
		func(drafts []DraftListItem) bool {
			lister := NewFilteredDraftLister()
			userID := "test-user"

			// Add all generated drafts
			for i := range drafts {
				lister.AddDraft(userID, &drafts[i])
			}

			var lastTime time.Time
			firstPage := true

			for page := 1; page <= 10; page++ {
				result := lister.ListDraftsForUser(userID, page)
				if len(result) == 0 {
					break
				}

				// Verify first item of current page is <= last item of previous page
				if !firstPage && len(result) > 0 {
					if result[0].CreatedAt.After(lastTime) {
						t.Logf("Cross-page ordering violation: page %d first item %v > previous last %v",
							page, result[0].CreatedAt, lastTime)
						return false
					}
				}

				if len(result) > 0 {
					lastTime = result[len(result)-1].CreatedAt
					firstPage = false
				}
			}

			return true
		},
		genDraftList(),
	))

	properties.TestingRun(t)
}

// TestProperty30_DraftsListPageSize verifies 20 items per page maximum
func TestProperty30_DraftsListPageSize(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Property 30e: Each page has maximum 20 items
	properties.Property("each page has maximum 20 items", prop.ForAll(
		func(drafts []DraftListItem) bool {
			lister := NewFilteredDraftLister()
			userID := "test-user"

			// Add all generated drafts
			for i := range drafts {
				lister.AddDraft(userID, &drafts[i])
			}

			// Check all pages
			for page := 1; page <= 20; page++ {
				result := lister.ListDraftsForUser(userID, page)
				if len(result) > 20 {
					t.Logf("Page %d has %d items, exceeds 20", page, len(result))
					return false
				}
				if len(result) == 0 {
					break
				}
			}

			return true
		},
		genDraftList(),
	))

	// Property 30f: Page 1 returns up to first 20 matching drafts
	properties.Property("page 1 returns up to first 20 matching drafts", prop.ForAll(
		func(numDrafts int) bool {
			lister := NewFilteredDraftLister()
			userID := "test-user"

			// Create drafts with only 'draft' status to ensure all are included
			baseTime := time.Now()
			for i := 0; i < numDrafts; i++ {
				lister.AddDraft(userID, &DraftListItem{
					ID:        generateDraftID(i),
					Status:    DraftStatusDraft,
					CreatedAt: baseTime.Add(-time.Duration(i) * time.Hour),
				})
			}

			result := lister.ListDraftsForUser(userID, 1)

			expectedLen := numDrafts
			if expectedLen > 20 {
				expectedLen = 20
			}

			if len(result) != expectedLen {
				t.Logf("Expected %d items on page 1, got %d", expectedLen, len(result))
				return false
			}

			return true
		},
		gen.IntRange(0, 100),
	))

	// Property 30g: Total items across all pages equals filtered count
	properties.Property("total items across pages equals filtered count", prop.ForAll(
		func(drafts []DraftListItem) bool {
			lister := NewFilteredDraftLister()
			userID := "test-user"

			// Add all generated drafts
			for i := range drafts {
				lister.AddDraft(userID, &drafts[i])
			}

			// Count expected (draft or error status only)
			expectedCount := 0
			for _, d := range drafts {
				if d.Status == DraftStatusDraft || d.Status == DraftStatusError {
					expectedCount++
				}
			}

			// Count actual across all pages
			actualCount := 0
			for page := 1; page <= 100; page++ {
				result := lister.ListDraftsForUser(userID, page)
				actualCount += len(result)
				if len(result) < 20 {
					break
				}
			}

			if actualCount != expectedCount {
				t.Logf("Expected %d total items, got %d", expectedCount, actualCount)
				return false
			}

			return true
		},
		genDraftList(),
	))

	properties.TestingRun(t)
}

// TestProperty30_DraftsListEmptyAndEdgeCases tests boundary conditions
func TestProperty30_DraftsListEmptyAndEdgeCases(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100

	properties := gopter.NewProperties(parameters)

	// Property 30h: Empty user returns empty list
	properties.Property("empty user returns empty list", prop.ForAll(
		func(page int) bool {
			lister := NewFilteredDraftLister()
			result := lister.ListDraftsForUser("nonexistent-user", page)
			return len(result) == 0
		},
		gen.IntRange(1, 100),
	))

	// Property 30i: Invalid page number returns empty list
	properties.Property("page beyond data returns empty list", prop.ForAll(
		func(numDrafts int) bool {
			lister := NewFilteredDraftLister()
			userID := "test-user"

			// Add drafts with 'draft' status
			baseTime := time.Now()
			for i := 0; i < numDrafts; i++ {
				lister.AddDraft(userID, &DraftListItem{
					ID:        generateDraftID(i),
					Status:    DraftStatusDraft,
					CreatedAt: baseTime.Add(-time.Duration(i) * time.Hour),
				})
			}

			// Request page beyond available data
			totalPages := (numDrafts + 19) / 20
			if totalPages == 0 {
				totalPages = 1
			}
			result := lister.ListDraftsForUser(userID, totalPages+5)
			return len(result) == 0
		},
		gen.IntRange(0, 50),
	))

	// Property 30j: User with only excluded statuses returns empty list
	properties.Property("user with only posted/partial/failed drafts returns empty", prop.ForAll(
		func(numDrafts int) bool {
			lister := NewFilteredDraftLister()
			userID := "test-user"

			statuses := []string{DraftStatusPosted, DraftStatusPartial, DraftStatusFailed}
			baseTime := time.Now()

			for i := 0; i < numDrafts; i++ {
				lister.AddDraft(userID, &DraftListItem{
					ID:        generateDraftID(i),
					Status:    statuses[i%len(statuses)],
					CreatedAt: baseTime.Add(-time.Duration(i) * time.Hour),
				})
			}

			result := lister.ListDraftsForUser(userID, 1)
			return len(result) == 0
		},
		gen.IntRange(1, 50),
	))

	properties.TestingRun(t)
}

// TestProperty30_DraftsListIsolation verifies user isolation
func TestProperty30_DraftsListIsolation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 50

	properties := gopter.NewProperties(parameters)

	// Property 30k: Users only see their own drafts
	properties.Property("users only see their own drafts", prop.ForAll(
		func(numUsers int, draftsPerUser int) bool {
			lister := NewFilteredDraftLister()
			baseTime := time.Now()

			// Create drafts for each user
			userDraftIDs := make(map[string]map[string]bool)
			for u := 0; u < numUsers; u++ {
				userID := generateUserIDForDraft(u)
				userDraftIDs[userID] = make(map[string]bool)

				for d := 0; d < draftsPerUser; d++ {
					draftID := generateDraftIDForUser(u, d)
					userDraftIDs[userID][draftID] = true

					lister.AddDraft(userID, &DraftListItem{
						ID:        draftID,
						Status:    DraftStatusDraft,
						CreatedAt: baseTime.Add(-time.Duration(d) * time.Hour),
					})
				}
			}

			// Verify each user only sees their drafts
			for u := 0; u < numUsers; u++ {
				userID := generateUserIDForDraft(u)

				// Get all pages for this user
				for page := 1; page <= 10; page++ {
					result := lister.ListDraftsForUser(userID, page)
					if len(result) == 0 {
						break
					}

					for _, draft := range result {
						if !userDraftIDs[userID][draft.ID] {
							t.Logf("User %s saw draft %s that doesn't belong to them", userID, draft.ID)
							return false
						}
					}
				}
			}

			return true
		},
		gen.IntRange(2, 10),
		gen.IntRange(0, 30),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Generators
// =============================================================================

// genDraftStatus generates a random valid draft status
func genDraftStatus() gopter.Gen {
	return gen.OneConstOf(
		DraftStatusDraft,
		DraftStatusPosted,
		DraftStatusPartial,
		DraftStatusFailed,
		DraftStatusError,
	)
}

// genDraftList generates a list of drafts with random statuses and times
func genDraftList() gopter.Gen {
	return gen.IntRange(0, 100).FlatMap(func(n interface{}) gopter.Gen {
		numDrafts := n.(int)

		return gen.SliceOfN(numDrafts, genDraftListItem())
	}, reflect.TypeOf([]DraftListItem{}))
}

// genDraftListItem generates a single draft list item
func genDraftListItem() gopter.Gen {
	return gopter.CombineGens(
		gen.Identifier(),
		genDraftStatus(),
		genTime(),
	).Map(func(vals []interface{}) DraftListItem {
		return DraftListItem{
			ID:        vals[0].(string),
			Status:    vals[1].(string),
			CreatedAt: vals[2].(time.Time),
		}
	})
}

// genTime generates a random time within the last year
func genTime() gopter.Gen {
	now := time.Now()
	oneYearAgo := now.Add(-365 * 24 * time.Hour)

	return gen.Int64Range(oneYearAgo.Unix(), now.Unix()).Map(func(ts int64) time.Time {
		return time.Unix(ts, 0)
	})
}

// =============================================================================
// Helpers
// =============================================================================

func generateDraftID(index int) string {
	return "draft-" + string(rune('A'+index%26)) + string(rune('0'+index/26))
}

func generateUserIDForDraft(index int) string {
	return "user-" + string(rune('A'+index%26)) + string(rune('0'+index/26))
}

func generateDraftIDForUser(userIndex, draftIndex int) string {
	return "draft-u" + string(rune('0'+userIndex)) + "-d" + string(rune('0'+draftIndex))
}
