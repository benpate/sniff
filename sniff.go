// Package sniff inspects browser User-Agent strings to guess the device and
// browser. User-Agent sniffing is unreliable by nature; prefer feature
// detection or client hints where you can.
package sniff

import "strings"

// browsers maps a user-agent keyword to its browser label, in priority order.
//
// Order matters: modern browsers impersonate each other in their user agents,
// so the table must run from most-specific to least-specific. For example,
// Edge, Samsung Internet, and Vivaldi all carry "Chrome" (and usually "Safari")
// in their UA, so they must be matched BEFORE Chrome; Chrome in turn carries
// "Safari" and must be matched before Safari.
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

// UserAgent scans the browser's useragent string.
// Remember, kids: Browser sniffing = bad bad bad.  You should never do it.
func UserAgent(userAgent string) BrowserInfo {

	userAgent = strings.ToLower(userAgent)

	result := sniffDevice(userAgent)
	result.Browser = sniffBrowser(userAgent)

	return result
}

// sniffDevice determines the device/OS fields from a lowercased user agent.
func sniffDevice(userAgent string) BrowserInfo {

	switch isMobile := strings.Contains(userAgent, "mobile"); {

	case strings.Contains(userAgent, "macintosh"):
		return BrowserInfo{IsMacintosh: true, IsDesktop: true, Device: "desktop", Description: "Macintosh PC"}

	case strings.Contains(userAgent, "windows"):
		if isMobile {
			return BrowserInfo{IsWindows: true, IsPhone: true, Device: "phone", Description: "Windows Phone"}
		}
		return BrowserInfo{IsWindows: true, IsDesktop: true, Device: "desktop", Description: "Windows PC"}

	case strings.Contains(userAgent, "iphone"):
		return BrowserInfo{IsPhone: true, IsIOS: true, Device: "phone", Description: "iPhone"}

	case strings.Contains(userAgent, "ipad"):
		return BrowserInfo{IsTablet: true, IsIOS: true, Device: "tablet", Description: "iPad"}

	case strings.Contains(userAgent, "android"):
		if isMobile {
			return BrowserInfo{IsAndroid: true, IsPhone: true, Device: "phone", Description: "Android Phone"}
		}
		return BrowserInfo{IsAndroid: true, IsTablet: true, Device: "tablet", Description: "Android Tablet"}

	default:
		return BrowserInfo{IsDesktop: true, Device: "desktop", Description: "Unrecognized Device"}
	}
}

// sniffBrowser determines the browser name from a lowercased user agent.
func sniffBrowser(userAgent string) string {

	for _, browser := range browsers {
		if strings.Contains(userAgent, browser.keyword) {
			return browser.name
		}
	}

	return "Unknown"
}
