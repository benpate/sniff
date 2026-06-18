package sniff

import "strings"

// browsers maps a user-agent keyword to its browser label, in priority order.
// Chrome must precede Safari because Chrome user agents contain both keywords.
var browsers = []struct {
	keyword string
	name    string
}{
	{"firefox", "Firefox"},
	{"chrome", "Chrome"},
	{"safari", "Safari"},
	{"msie", "MSIE"},
	{"opera", "Opera"},
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

	isMobile := strings.Contains(userAgent, "mobile")

	switch {

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

	case strings.Contains(userAgent, "blackberry"):
		return BrowserInfo{IsPhone: true, Device: "phone", Description: "Blackberry Phone"}

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
