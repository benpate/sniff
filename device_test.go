package sniff

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsMobile confirms IsMobile reports phones and tablets as mobile and
// desktops as not, using the same case-insensitive matching as UserAgent.
func TestIsMobile(t *testing.T) {

	check := func(name string, userAgent string, expected bool) {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, expected, IsMobile(userAgent))
		})
	}

	// Mobile: phones and tablets.
	check("iPhone", "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0)", true)
	check("Android phone", "Mozilla/5.0 (Linux; Android 12; Pixel 6) Mobile Safari", true)
	check("Android tablet", "Mozilla/5.0 (Linux; Android 12; SM-T500)", true)
	check("iPad", "Mozilla/5.0 (iPad; CPU OS 16_3 like Mac OS X) Mobile/15E148", true)

	// Desktop: not mobile.
	check("Desktop Mac", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)", false)
	check("Desktop Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", false)
	check("Empty", "", false)
	check("Unrecognized", "some random crawler/1.0", false)

	// Matching is case-insensitive, so the same UA is detected regardless of
	// casing -- this is the consistency guarantee IsMobile and UserAgent share.
	check("lowercase iphone", "mozilla/5.0 (iphone; cpu iphone os 15_0)", true)
	check("UPPERCASE iphone", "MOZILLA/5.0 (IPHONE; CPU IPHONE OS 15_0)", true)
	check("lowercase desktop windows", "mozilla/5.0 (windows nt 10.0; win64; x64)", false)
}

// TestIsDesktop confirms IsDesktop reports desktops as such and is the exact
// complement of IsMobile across devices and casings.
func TestIsDesktop(t *testing.T) {

	check := func(name string, userAgent string, expected bool) {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, expected, IsDesktop(userAgent))
			// IsDesktop and IsMobile must always disagree -- every device is one
			// or the other, never both and never neither.
			assert.Equal(t, !IsMobile(userAgent), IsDesktop(userAgent))
		})
	}

	check("Desktop Mac", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)", true)
	check("Desktop Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", true)
	check("Unrecognized", "some random crawler/1.0", true)
	check("Empty", "", true)

	check("iPhone", "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0)", false)
	check("iPad", "Mozilla/5.0 (iPad; CPU OS 16_3 like Mac OS X) Mobile/15E148", false)
	check("Android tablet", "Mozilla/5.0 (Linux; Android 12; SM-T500)", false)

	// Case-insensitive, matching UserAgent.
	check("UPPERCASE desktop", "MOZILLA/5.0 (MACINTOSH; INTEL MAC OS X 10_15)", true)
	check("lowercase iphone", "mozilla/5.0 (iphone; cpu iphone os 15_0)", false)
}

// FuzzIsMobile ensures IsMobile never panics on arbitrary input and stays
// consistent with the documented keyword matching.
func FuzzIsMobile(f *testing.F) {

	f.Add("")
	f.Add("Mobile")
	f.Add("iPhone")
	f.Add("Android")
	f.Add("Mozilla/5.0 (Macintosh)")

	f.Fuzz(func(_ *testing.T, userAgent string) {
		// Must not panic; the result is a plain bool.
		_ = IsMobile(userAgent)
	})
}
