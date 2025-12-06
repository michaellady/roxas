//go:build tools

package tools

// This file exists to keep tool dependencies visible to go mod tidy.
// Without this, dependencies only used in files with build tags (like
// browser_e2e_test.go with //go:build browser) would be removed by
// go mod tidy since they're not reachable under the default build.

import (
	_ "github.com/go-rod/rod"
)
