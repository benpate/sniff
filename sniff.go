// Package sniff inspects browser User-Agent strings to guess the device and
// browser. User-Agent sniffing is unreliable by nature; prefer feature
// detection or client hints where you can.
package sniff

import "strings"

// browsers maps a user-agent keyword to its browser label, in priority order.
var browsers = []struct {
	keyword string
	name    string
}{
	{"edg", "Edge"},                        // Edg / EdgA / EdgiOS -- contains "Chrome" + "Safari"
	{"samsungbrowser", "Samsung Internet"}, // contains "Chrome" + "Safari"
	{"vivaldi", "Vivaldi"},                 // contains "Chrome" + "Safari"
	{"opera", "Opera"},                     // modern Opera also carries "OPR"
	{"opr", "Opera"},
	{"firefox", "Firefox"},
	{"chrome", "Chrome"},
	{"safari", "Safari"},
}

// UserAgent inspects a User-Agent string and returns the device and browser it identifies.
// Remember, kids: Browser sniffing = bad bad bad.  You should never do it.
func UserAgent(userAgent string) BrowserInfo {

	userAgent = strings.ToLower(userAgent)

	result := sniffDevice(userAgent)
	result.Browser = sniffBrowser(userAgent)

	return result
}

// sniffDevice determines the device/OS fields from a lowercased user agent.
func sniffDevice(userAgent string) BrowserInfo {

	switch isMobile := hasToken(userAgent, "mobile"); {

	case hasToken(userAgent, "macintosh"):
		return BrowserInfo{IsMacintosh: true, IsDesktop: true, Device: "desktop", Description: "Macintosh PC"}

	case hasToken(userAgent, "windows"):
		if isMobile {
			return BrowserInfo{IsWindows: true, IsPhone: true, Device: "phone", Description: "Windows Phone"}
		}
		return BrowserInfo{IsWindows: true, IsDesktop: true, Device: "desktop", Description: "Windows PC"}

	case hasToken(userAgent, "iphone"):
		return BrowserInfo{IsPhone: true, IsIOS: true, Device: "phone", Description: "iPhone"}

	case hasToken(userAgent, "ipad"):
		return BrowserInfo{IsTablet: true, IsIOS: true, Device: "tablet", Description: "iPad"}

	// ChromeOS UAs contain "CrOS"; check before "android" because both are
	// Linux-based, and before the generic "linux" branch below.
	case hasToken(userAgent, "cros"):
		return BrowserInfo{IsChromeOS: true, IsDesktop: true, Device: "desktop", Description: "ChromeOS"}

	case hasToken(userAgent, "android"):
		if isMobile {
			return BrowserInfo{IsAndroid: true, IsPhone: true, Device: "phone", Description: "Android Phone"}
		}
		return BrowserInfo{IsAndroid: true, IsTablet: true, Device: "tablet", Description: "Android Tablet"}

	// Generic desktop Linux. Must come AFTER android and cros, since those
	// platforms also carry "linux" in their user agents.
	case hasToken(userAgent, "linux"):
		return BrowserInfo{IsLinux: true, IsDesktop: true, Device: "desktop", Description: "Linux PC"}

	default:
		return BrowserInfo{IsDesktop: true, Device: "desktop", Description: "Unrecognized Device"}
	}
}

// sniffBrowser determines the browser name from a lowercased user agent.
func sniffBrowser(userAgent string) string {

	// Order matters: modern browsers impersonate each other in their user
	// agents, so the table runs most-specific to least-specific. Edge, Samsung
	// Internet, and Vivaldi all carry "chrome"/"safari" and must be matched
	// before chrome; chrome carries "safari" and is matched before safari.

	for _, browser := range browsers {
		if hasToken(userAgent, browser.keyword) {
			return browser.name
		}
	}

	return "Unknown"
}

// hasToken returns TRUE if the user agent contains the keyword at the start of a word.
func hasToken(userAgent string, keyword string) bool {

	// Only the character *before* a match is examined, never the one after, because
	// every keyword here is a prefix: "edg" must still match "edg/", "edge/", and
	// "edgios/", and "opr" must still match "opr/".

	for offset := 0; offset < len(userAgent); {

		// Find the next occurrence of the keyword.
		index := strings.Index(userAgent[offset:], keyword)

		if index < 0 {
			return false
		}

		start := offset + index

		// RULE: A keyword buried inside a longer word is not a match. Plain substring
		// matching misreads "Microsoft" as ChromeOS (mi-CROS-oft), "Knowledge" as
		// Edge, "Proprietary" as Opera, and "WikiPad" as an iPad.
		if (start == 0) || !isLetter(userAgent[start-1]) {
			return true
		}

		// Otherwise, resume the search just past this false match.
		offset = start + 1
	}

	return false
}

// isLetter returns TRUE if the character is an ASCII letter.
func isLetter(character byte) bool {

	// Both cases are tested because hasToken accepts any string; the sniffers
	// happen to lowercase their input first, but the helper does not require it.

	return ((character >= 'a') && (character <= 'z')) || ((character >= 'A') && (character <= 'Z'))
}
