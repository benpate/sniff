package sniff

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestUserAgent_Devices verifies the OS/device-sniffing branches of UserAgent.
func TestUserAgent_Devices(t *testing.T) {

	// Following the closure-driven style (https://medium.com/@cep21/628a41497e5e),
	// each case is a small closure that runs an independent set of assertions. We
	// use assert.* (not require.*) so every field mismatch is reported, since the
	// checks within a case are independent of one another.

	check := func(name string, userAgent string, expected BrowserInfo) {
		t.Run(name, func(t *testing.T) {
			actual := UserAgent(userAgent)
			assert.Equal(t, expected, actual)
		})
	}

	// All of the cases below use genuine, real-world user-agent strings so the
	// assertions reflect what the code will actually see in production (a fake
	// UA can "pass" while hiding real behavior, e.g. an Android UA reporting an
	// empty Browser even though real Android UAs always carry a browser token).

	check("Macintosh", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15", BrowserInfo{
		Device:      "desktop",
		IsDesktop:   true,
		IsMacintosh: true,
		Browser:     "Safari",
		Description: "Macintosh PC",
	})

	check("Windows PC", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36", BrowserInfo{
		Device:      "desktop",
		IsDesktop:   true,
		IsWindows:   true,
		Browser:     "Chrome",
		Description: "Windows PC",
	})

	check("Windows Phone", "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; Lumia 950) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254", BrowserInfo{
		Device:      "phone",
		IsPhone:     true,
		IsWindows:   true,
		Browser:     "Edge", // legacy EdgeHTML "Edge/..." token matches the "edg" keyword
		Description: "Windows Phone",
	})

	check("iPhone", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1", BrowserInfo{
		Device:      "phone",
		IsPhone:     true,
		IsIOS:       true,
		Browser:     "Safari",
		Description: "iPhone",
	})

	check("iPad", "Mozilla/5.0 (iPad; CPU OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1", BrowserInfo{
		Device:      "tablet",
		IsTablet:    true,
		IsIOS:       true,
		Browser:     "Safari",
		Description: "iPad",
	})

	check("Android Phone", "Mozilla/5.0 (Linux; Android 13; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36", BrowserInfo{
		Device:      "phone",
		IsPhone:     true,
		IsAndroid:   true,
		Browser:     "Chrome",
		Description: "Android Phone",
	})

	check("Android Tablet", "Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36", BrowserInfo{
		Device:      "tablet",
		IsTablet:    true,
		IsAndroid:   true,
		Browser:     "Chrome",
		Description: "Android Tablet",
	})

	// Blackberry is no longer detected (effectively 0% usage); its UA now falls
	// through to Unrecognized. The "Mobile" token does NOT force a phone, since
	// device classification is authoritative.
	check("Blackberry now unrecognized", "Mozilla/5.0 (BlackBerry; U; BlackBerry 9900; en) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.1.0.346 Mobile Safari/534.11+", BrowserInfo{
		Device:      "desktop",
		IsDesktop:   true,
		Browser:     "Safari",
		Description: "Unrecognized Device",
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

// TestUserAgent_MobileTokenDoesNotOverrideDevice guards against a regression:
// the device classification from sniffDevice is authoritative. A bare "mobile"
// token must NOT flip an already-classified device into a phone, and it must
// not corrupt a tablet into reporting both IsTablet and IsPhone.
func TestUserAgent_MobileTokenDoesNotOverrideDevice(t *testing.T) {

	// "mobile" present, but no recognized device keyword -> stays a plain,
	// non-phone Unrecognized desktop.
	unknown := UserAgent("unknown-device mobile")
	assert.Equal(t, "Unrecognized Device", unknown.Description)
	assert.Equal(t, "desktop", unknown.Device)
	assert.False(t, unknown.IsPhone, "a bare mobile token must not force IsPhone")

	// A real iPad UA contains "Mobile/15E148"; it must remain a tablet and must
	// NOT be marked as a phone.
	ipad := UserAgent("Mozilla/5.0 (iPad; CPU OS 16_3 like Mac OS X) AppleWebKit/605.1.15 Version/16.3 Mobile/15E148 Safari/604.1")
	assert.Equal(t, "tablet", ipad.Device)
	assert.True(t, ipad.IsTablet)
	assert.False(t, ipad.IsPhone, "an iPad must not be reported as a phone")
}

// TestUserAgent_CaseInsensitive verifies that detection is independent of the
// casing of the input: the same UA in lower, UPPER, and mixed case must all
// produce identical results. This is the contract IsMobile relies on.
func TestUserAgent_CaseInsensitive(t *testing.T) {

	const canonical = "Mozilla/5.0 (Linux; Android 13; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36"

	expected := UserAgent(canonical)

	check := func(name string, userAgent string) {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, expected, UserAgent(userAgent))
		})
	}

	check("lowercase", strings.ToLower(canonical))
	check("UPPERCASE", strings.ToUpper(canonical))
	check("MiXeD cAsE", "MoZiLlA/5.0 (LiNuX; AnDrOiD 13; PiXeL 6) AppleWebKit/537.36 (KHTML, like Gecko) ChRoMe/110.0.0.0 MoBiLe SaFaRi/537.36")

	// Sanity check: the canonical result is the Android-phone/Chrome we expect,
	// so the cases above are asserting against a meaningful value, not a zero one.
	assert.Equal(t, "Android Phone", expected.Description)
	assert.Equal(t, "Chrome", expected.Browser)
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

	// Genuine, real-world user-agent strings for each browser.
	check("Firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0", "Firefox")
	check("Safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15", "Safari")

	// Chromium-based browsers all carry "Chrome" (and "Safari") in their UA, so
	// each must be matched by its own more-specific token BEFORE Chrome.
	check("Chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36", "Chrome")
	check("Edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69", "Edge")
	check("Edge iOS", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 EdgiOS/110.0.1587.60 Mobile/15E148 Safari/604.1", "Edge")
	check("Samsung Internet", "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/20.0 Chrome/110.0.0.0 Mobile Safari/537.36", "Samsung Internet")
	check("Vivaldi", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Vivaldi/5.7.2921.63", "Vivaldi")

	// Modern Opera identifies itself with "OPR/"; legacy Presto Opera with "Opera".
	check("Opera modern (OPR)", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 OPR/96.0.0.0", "Opera")
	check("Opera legacy (Presto)", "Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14", "Opera")

	check("No browser keyword", "some random string", "Unknown")
}

// TestSniffDevice exercises the package-private sniffDevice helper directly.
// It expects an already-lowercased user agent (UserAgent lowercases before
// calling it), so the cases below are written in lowercase.
func TestSniffDevice(t *testing.T) {

	check := func(name string, userAgent string, expected BrowserInfo) {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, expected, sniffDevice(userAgent))
		})
	}

	check("Macintosh", "macintosh", BrowserInfo{
		IsMacintosh: true, IsDesktop: true, Device: "desktop", Description: "Macintosh PC",
	})
	check("Windows PC", "windows", BrowserInfo{
		IsWindows: true, IsDesktop: true, Device: "desktop", Description: "Windows PC",
	})
	check("Windows Phone", "windows mobile", BrowserInfo{
		IsWindows: true, IsPhone: true, Device: "phone", Description: "Windows Phone",
	})
	check("iPhone", "iphone", BrowserInfo{
		IsPhone: true, IsIOS: true, Device: "phone", Description: "iPhone",
	})
	check("iPad", "ipad", BrowserInfo{
		IsTablet: true, IsIOS: true, Device: "tablet", Description: "iPad",
	})
	check("Android Phone", "android mobile", BrowserInfo{
		IsAndroid: true, IsPhone: true, Device: "phone", Description: "Android Phone",
	})
	check("Android Tablet", "android", BrowserInfo{
		IsAndroid: true, IsTablet: true, Device: "tablet", Description: "Android Tablet",
	})
	check("Unrecognized", "unknown", BrowserInfo{
		IsDesktop: true, Device: "desktop", Description: "Unrecognized Device",
	})

	// Real-world round-trips (lowercased, as UserAgent would pass them). These
	// guard against branch-collision bugs that single-keyword stubs cannot catch
	// -- e.g. an iPad UA contains "mobile" but must NOT fall into a phone branch.
	check("Real iPad (contains 'mobile')", "mozilla/5.0 (ipad; cpu os 16_3 like mac os x) applewebkit/605.1.15 (khtml, like gecko) version/16.3 mobile/15e148 safari/604.1", BrowserInfo{
		IsTablet: true, IsIOS: true, Device: "tablet", Description: "iPad",
	})
	check("Real Android tablet (no 'mobile')", "mozilla/5.0 (linux; android 13; sm-x700) applewebkit/537.36 (khtml, like gecko) chrome/110.0.0.0 safari/537.36", BrowserInfo{
		IsAndroid: true, IsTablet: true, Device: "tablet", Description: "Android Tablet",
	})
	check("Real Android phone (contains 'mobile')", "mozilla/5.0 (linux; android 13; pixel 6) applewebkit/537.36 (khtml, like gecko) chrome/110.0.0.0 mobile safari/537.36", BrowserInfo{
		IsAndroid: true, IsPhone: true, Device: "phone", Description: "Android Phone",
	})
}

// TestSniffBrowser exercises the package-private sniffBrowser helper directly,
// including the Chrome-before-Safari priority ordering.
func TestSniffBrowser(t *testing.T) {

	check := func(name string, userAgent string, expected string) {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, expected, sniffBrowser(userAgent))
		})
	}

	// Genuine user-agent strings (lowercased, as UserAgent would pass them).
	check("Firefox", "mozilla/5.0 (windows nt 10.0; win64; x64; rv:109.0) gecko/20100101 firefox/115.0", "Firefox")
	check("Safari", "mozilla/5.0 (macintosh; intel mac os x 10_15_7) applewebkit/605.1.15 (khtml, like gecko) version/16.3 safari/605.1.15", "Safari")

	// Chromium-based browsers all carry "chrome" + "safari"; the more-specific
	// token must win. These cases guard the priority ordering of the table.
	check("Chrome", "mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/110.0.0.0 safari/537.36", "Chrome")
	check("Edge wins over Chrome", "mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/110.0.0.0 safari/537.36 edg/110.0.1587.69", "Edge")
	check("Samsung wins over Chrome", "mozilla/5.0 (linux; android 13; sm-s901b) applewebkit/537.36 (khtml, like gecko) samsungbrowser/20.0 chrome/110.0.0.0 mobile safari/537.36", "Samsung Internet")
	check("Vivaldi wins over Chrome", "mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/110.0.0.0 safari/537.36 vivaldi/5.7.2921.63", "Vivaldi")
	check("Opera OPR wins over Chrome", "mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/110.0.0.0 safari/537.36 opr/96.0.0.0", "Opera")
	check("Unknown", "some random string", "Unknown")
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
