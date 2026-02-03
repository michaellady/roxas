package clients

import (
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// Property Test: AT URI to Web URL Conversion (Property 26)
// Validates Requirements 7.6
//
// Property: AT Protocol URI in the format "at://did:plc:xxx/app.bsky.feed.post/rkey"
// should convert to "https://bsky.app/profile/{handle}/post/{rkey}".

// genBlueskyRkey generates random Bluesky record keys (TID format)
// TIDs are base32-sortable timestamps, typically 13 characters
func genBlueskyRkey() gopter.Gen {
	return gen.RegexMatch(`[a-z2-7]{13}`)
}

// genBlueskyDIDForURI generates random Bluesky DIDs for AT URIs
// DIDs are in format: did:plc:<base32-encoded-identifier>
func genBlueskyDIDForURI() gopter.Gen {
	identifier := gen.RegexMatch(`[a-z2-7]{24}`)
	return identifier.Map(func(id string) string {
		return "did:plc:" + id
	})
}

// genBlueskyHandleForURI generates random Bluesky handles
// Handles are in format: username.bsky.social or custom domains
func genBlueskyHandleForURI() gopter.Gen {
	username := gen.RegexMatch(`[a-z][a-z0-9]{2,15}`)
	domain := gen.OneConstOf("bsky.social", "bsky.app", "example.com")

	return gopter.CombineGens(username, domain).Map(func(vals []interface{}) string {
		return vals[0].(string) + "." + vals[1].(string)
	})
}

// genValidATURI generates valid AT URIs for feed posts
func genValidATURI() gopter.Gen {
	return gopter.CombineGens(
		genBlueskyDIDForURI(),
		genBlueskyRkey(),
	).Map(func(vals []interface{}) string {
		did := vals[0].(string)
		rkey := vals[1].(string)
		return "at://" + did + "/app.bsky.feed.post/" + rkey
	})
}

// TestProperty26_ATURIToWebURLExtractsRkey verifies that the rkey is correctly extracted
func TestProperty26_ATURIToWebURLExtractsRkey(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)

	properties := gopter.NewProperties(parameters)

	// Property 26a: The rkey from the AT URI appears in the web URL
	properties.Property("rkey from AT URI appears in web URL", prop.ForAll(
		func(handle string, did string, rkey string) bool {
			client := NewBlueskyClient(handle, "password", "")
			atURI := "at://" + did + "/app.bsky.feed.post/" + rkey

			webURL := client.ATURIToWebURL(atURI)

			// The web URL must contain the rkey
			return strings.Contains(webURL, "/post/"+rkey)
		},
		genBlueskyHandleForURI(),
		genBlueskyDIDForURI(),
		genBlueskyRkey(),
	))

	properties.TestingRun(t)
}

// TestProperty26_ATURIToWebURLUsesHandle verifies that the handle is used in the web URL
func TestProperty26_ATURIToWebURLUsesHandle(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)

	properties := gopter.NewProperties(parameters)

	// Property 26b: The client's handle appears in the web URL
	properties.Property("client handle appears in web URL", prop.ForAll(
		func(handle string, did string, rkey string) bool {
			client := NewBlueskyClient(handle, "password", "")
			atURI := "at://" + did + "/app.bsky.feed.post/" + rkey

			webURL := client.ATURIToWebURL(atURI)

			// The web URL must contain the handle
			return strings.Contains(webURL, "/profile/"+handle+"/post/")
		},
		genBlueskyHandleForURI(),
		genBlueskyDIDForURI(),
		genBlueskyRkey(),
	))

	properties.TestingRun(t)
}

// TestProperty26_ATURIToWebURLFormat verifies the complete web URL format
func TestProperty26_ATURIToWebURLFormat(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)

	properties := gopter.NewProperties(parameters)

	// Property 26c: The web URL has the exact expected format
	properties.Property("web URL has correct format https://bsky.app/profile/{handle}/post/{rkey}", prop.ForAll(
		func(handle string, did string, rkey string) bool {
			client := NewBlueskyClient(handle, "password", "")
			atURI := "at://" + did + "/app.bsky.feed.post/" + rkey

			webURL := client.ATURIToWebURL(atURI)
			expectedURL := "https://bsky.app/profile/" + handle + "/post/" + rkey

			return webURL == expectedURL
		},
		genBlueskyHandleForURI(),
		genBlueskyDIDForURI(),
		genBlueskyRkey(),
	))

	properties.TestingRun(t)
}

// TestProperty26_ATURIToWebURLFallback verifies invalid AT URIs return the original
func TestProperty26_ATURIToWebURLFallback(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)

	properties := gopter.NewProperties(parameters)

	// Property 26d: Invalid AT URIs (with fewer than 5 path segments) return the original
	properties.Property("invalid AT URIs return original value", prop.ForAll(
		func(handle string, invalidURI string) bool {
			client := NewBlueskyClient(handle, "password", "")

			result := client.ATURIToWebURL(invalidURI)

			// Invalid URIs should be returned unchanged
			return result == invalidURI
		},
		genBlueskyHandleForURI(),
		genInvalidATURI(),
	))

	properties.TestingRun(t)
}

// genInvalidATURI generates AT URIs with fewer than 5 path segments
func genInvalidATURI() gopter.Gen {
	return gen.OneGenOf(
		// Too few segments
		gen.Const("at://did:plc:abc123"),
		gen.Const("at://did:plc:abc123/app.bsky.feed.post"),
		// Not starting with at://
		gen.AlphaString().Map(func(s string) string {
			return "invalid://" + s
		}),
		// Empty string
		gen.Const(""),
		// Just "at://"
		gen.Const("at://"),
	)
}

// TestProperty26_ATURIToWebURLBidirectionalConsistency verifies the rkey is always
// the last segment regardless of the DID format
func TestProperty26_ATURIToWebURLBidirectionalConsistency(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)

	properties := gopter.NewProperties(parameters)

	// Property 26e: Same rkey always produces same post path suffix
	properties.Property("same rkey always produces consistent post path", prop.ForAll(
		func(handle1, handle2, did1, did2, rkey string) bool {
			client1 := NewBlueskyClient(handle1, "password", "")
			client2 := NewBlueskyClient(handle2, "password", "")

			atURI1 := "at://" + did1 + "/app.bsky.feed.post/" + rkey
			atURI2 := "at://" + did2 + "/app.bsky.feed.post/" + rkey

			webURL1 := client1.ATURIToWebURL(atURI1)
			webURL2 := client2.ATURIToWebURL(atURI2)

			// Both should end with the same /post/{rkey}
			suffix := "/post/" + rkey
			return strings.HasSuffix(webURL1, suffix) && strings.HasSuffix(webURL2, suffix)
		},
		genBlueskyHandleForURI(),
		genBlueskyHandleForURI(),
		genBlueskyDIDForURI(),
		genBlueskyDIDForURI(),
		genBlueskyRkey(),
	))

	properties.TestingRun(t)
}

// TestProperty26_ATURIToWebURLStartsWithHTTPS verifies the output is always an HTTPS URL
func TestProperty26_ATURIToWebURLStartsWithHTTPS(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)

	properties := gopter.NewProperties(parameters)

	// Property 26f: Valid AT URIs always produce HTTPS URLs
	properties.Property("valid AT URIs always produce HTTPS URLs", prop.ForAll(
		func(handle, did, rkey string) bool {
			client := NewBlueskyClient(handle, "password", "")
			atURI := "at://" + did + "/app.bsky.feed.post/" + rkey

			webURL := client.ATURIToWebURL(atURI)

			return strings.HasPrefix(webURL, "https://bsky.app/")
		},
		genBlueskyHandleForURI(),
		genBlueskyDIDForURI(),
		genBlueskyRkey(),
	))

	properties.TestingRun(t)
}
