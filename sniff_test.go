package sniff

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestUserAgent_Devices verifies the OS/device-sniffing branches of UserAgent.
//
// Following the closure-driven style (https://medium.com/@cep21/628a41497e5e),
// each case is a small closure that runs an independent set of assertions. We
// use assert.* (not require.*) so every field mismatch is reported, since the
// checks within a case are independent of one another.
func TestUserAgent_Devices(t *testing.T) {

	check := func(name string, userAgent string, expected BrowserInfo) {
		t.Run(name, func(t *testing.T) {
			actual := UserAgent(userAgent)
			assert.Equal(t, expected, actual)
		})
	}

	check("Macintosh", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)", BrowserInfo{
		Device:      "desktop",
		IsDesktop:   true,
		IsMacintosh: true,
		Browser:     "Unknown",
		Description: "Macintosh PC",
	})

	check("Windows PC", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", BrowserInfo{
		Device:      "desktop",
		IsDesktop:   true,
		IsWindows:   true,
		Browser:     "Unknown",
		Description: "Windows PC",
	})

	check("Windows Phone", "Mozilla/5.0 (Windows Phone 10.0; Mobile)", BrowserInfo{
		Device:      "phone",
		IsPhone:     true,
		IsWindows:   true,
		Browser:     "Unknown",
		Description: "Windows Phone",
	})

	check("iPhone", "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)", BrowserInfo{
		Device:      "phone",
		IsPhone:     true,
		IsIOS:       true,
		Browser:     "Unknown",
		Description: "iPhone",
	})

	check("iPad", "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X)", BrowserInfo{
		Device:      "tablet",
		IsTablet:    true,
		IsIOS:       true,
		Browser:     "Unknown",
		Description: "iPad",
	})

	check("Android Phone", "Mozilla/5.0 (Linux; Android 12; Pixel 6 Mobile)", BrowserInfo{
		Device:      "phone",
		IsPhone:     true,
		IsAndroid:   true,
		Browser:     "Unknown",
		Description: "Android Phone",
	})

	check("Android Tablet", "Mozilla/5.0 (Linux; Android 12; SM-T500)", BrowserInfo{
		Device:      "tablet",
		IsTablet:    true,
		IsAndroid:   true,
		Browser:     "Unknown",
		Description: "Android Tablet",
	})

	check("Blackberry", "Mozilla/5.0 (BlackBerry; U; BlackBerry 9900)", BrowserInfo{
		Device:      "phone",
		IsPhone:     true,
		Browser:     "Unknown",
		Description: "Blackberry Phone",
	})

	check("Unrecognized", "some random crawler/1.0", BrowserInfo{
		Device:      "desktop",
		IsDesktop:   true,
		Browser:     "Unknown",
		Description: "Unrecognized Device",
	})

	check("Empty", "", BrowserInfo{
		Device:      "desktop",
		IsDesktop:   true,
		Browser:     "Unknown",
		Description: "Unrecognized Device",
	})
}

// TestUserAgent_MacintoshBeforeWindows confirms branch ordering: a string that
// contains both "macintosh" and "windows" is reported as a Macintosh, because
// the Macintosh check comes first. (Safari on Mac reports "Macintosh".)
func TestUserAgent_MacintoshWinsOverWindows(t *testing.T) {

	result := UserAgent("macintosh windows")

	assert.True(t, result.IsMacintosh)
	assert.False(t, result.IsWindows)
	assert.Equal(t, "desktop", result.Device)
}

// TestUserAgent_MobileFlagOverridesDesktop confirms the trailing "mobile" check
// at the end of UserAgent: any user agent containing "mobile" is forced to
// IsPhone = true even when the device branch decided it was a desktop.
func TestUserAgent_MobileFlagForcesPhone(t *testing.T) {

	// "mobile" present, but no recognized device keyword -> Unrecognized desktop,
	// then the trailing check sets IsPhone.
	result := UserAgent("unknown-device mobile")

	assert.Equal(t, "Unrecognized Device", result.Description)
	assert.Equal(t, "desktop", result.Device) // Device string is NOT updated, only IsPhone
	assert.True(t, result.IsPhone)
}

// TestUserAgent_Browser verifies the browser-sniffing branches. The input is
// lowercased before matching, so the keyword comparisons are case-insensitive
// and every named branch is reachable.
func TestUserAgent_Browser(t *testing.T) {

	check := func(name string, userAgent string, expectedBrowser string) {
		t.Run(name, func(t *testing.T) {
			result := UserAgent(userAgent)
			assert.Equal(t, expectedBrowser, result.Browser)
		})
	}

	check("Firefox", "Mozilla/5.0 Firefox/100.0", "Firefox")
	check("Safari", "Mozilla/5.0 (Macintosh) Version/15.0 Safari/605.1.15", "Safari")
	check("MSIE", "Mozilla/5.0 (Windows NT 6.1) MSIE 9.0", "MSIE")
	check("Opera", "Mozilla/5.0 Opera/12.16", "Opera")

	// Real Chrome user agents contain both "chrome" and "safari"; because the
	// Chrome branch is checked first, they are correctly reported as Chrome.
	check("Chrome", "Mozilla/5.0 (Windows NT 10.0) Chrome/100.0 Safari/537.36", "Chrome")

	// Matching is case-insensitive thanks to the lowercasing.
	check("Lowercase chrome", "mozilla/5.0 chrome/100.0", "Chrome")

	check("No browser keyword", "some random string", "Unknown")
}

// TestUserAgent_VersionUnset documents that the Version field is never
// populated by the current implementation.
func TestUserAgent_VersionUnset(t *testing.T) {
	result := UserAgent("Mozilla/5.0 (Macintosh) Firefox/100.0")
	assert.Equal(t, "", result.Version)
}

// FuzzUserAgent ensures UserAgent never panics on arbitrary input. UserAgent
// parses an externally-supplied string, so it is exactly the kind of function
// the checklist calls for fuzzing.
func FuzzUserAgent(f *testing.F) {

	f.Add("")
	f.Add("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)")
	f.Add("Mozilla/5.0 (iPhone; CPU iPhone OS 15_0)")
	f.Add("Mozilla/5.0 (Linux; Android 12; Mobile)")
	f.Add("windows mobile firefox")

	f.Fuzz(func(t *testing.T, userAgent string) {
		result := UserAgent(userAgent)

		// Device should always be one of the known values.
		switch result.Device {
		case "desktop", "tablet", "phone":
			// ok
		default:
			t.Errorf("unexpected Device value %q for input %q", result.Device, userAgent)
		}

		// Browser should always be non-empty (defaults to "Unknown").
		assert.NotEmpty(t, result.Browser)

		// Description should always be populated.
		assert.NotEmpty(t, result.Description)
	})
}
