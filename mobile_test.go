package sniff

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsMobile exercises the Aho-Corasick matcher in IsMobile, which looks for
// the literal substrings "Mobile", "iPhone", or "Android" (case-sensitive).
func TestIsMobile(t *testing.T) {

	check := func(name string, userAgent string, expected bool) {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, expected, IsMobile(userAgent))
		})
	}

	// Matching cases -- one per keyword.
	check("Mobile keyword", "Mozilla/5.0 (Linux; Android) Mobile Safari", true)
	check("iPhone keyword", "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0)", true)
	check("Android keyword", "Mozilla/5.0 (Linux; Android 12; Pixel 6)", true)

	// Non-matching cases.
	check("Desktop Mac", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)", false)
	check("Desktop Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", false)
	check("Empty", "", false)

	// The matcher is case-sensitive, so the lowercase variants do NOT match.
	check("lowercase mobile does not match", "linux mobile safari", false)
	check("lowercase iphone does not match", "iphone os", false)
	check("lowercase android does not match", "android 12", false)
}

// FuzzIsMobile ensures IsMobile never panics on arbitrary input and stays
// consistent with the documented keyword matching.
func FuzzIsMobile(f *testing.F) {

	f.Add("")
	f.Add("Mobile")
	f.Add("iPhone")
	f.Add("Android")
	f.Add("Mozilla/5.0 (Macintosh)")

	f.Fuzz(func(t *testing.T, userAgent string) {
		// Must not panic; the result is a plain bool.
		_ = IsMobile(userAgent)
	})
}
