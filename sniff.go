package sniff

import "strings"

// UserAgent scans the browser's useragent string.
// Remember, kids: Browser sniffing = bad bad bad.  You should never do it.
func UserAgent(userAgent string) BrowserInfo {

	var result BrowserInfo

	userAgent = strings.ToLower(userAgent)

	// Sniff Device OS
	if strings.Contains(userAgent, "macintosh") {
		result.IsMacintosh = true
		result.IsDesktop = true
		result.Device = "desktop"
		result.Description = "Macintosh PC"

	} else if strings.Contains(userAgent, "windows") {

		if strings.Contains(userAgent, "mobile") {
			result.IsWindows = true
			result.IsPhone = true
			result.Device = "phone"
			result.Description = "Windows Phone"

		} else {
			result.IsWindows = true
			result.IsDesktop = true
			result.Device = "desktop"
			result.Description = "Windows PC"
		}

	} else if strings.Contains(userAgent, "iphone") {
		result.IsPhone = true
		result.IsIOS = true
		result.Device = "phone"
		result.Description = "iPhone"

	} else if strings.Contains(userAgent, "ipad") {
		result.IsTablet = true
		result.IsIOS = true
		result.Device = "tablet"
		result.Description = "iPad"

	} else if strings.Contains(userAgent, "android") {

		if strings.Contains(userAgent, "mobile") {
			result.IsAndroid = true
			result.IsPhone = true
			result.Device = "phone"
			result.Description = "Android Phone"

		} else {
			result.IsAndroid = true
			result.IsTablet = true
			result.Device = "tablet"
			result.Description = "Android Tablet"
		}

	} else if strings.Contains(userAgent, "blackberry") {
		result.IsPhone = true
		result.Device = "phone"
		result.Description = "Blackberry Phone"
	} else {
		result.IsDesktop = true
		result.Device = "desktop"
		result.Description = "Unrecognized Device"
	}

	// Sniff Browser Info
	if strings.Contains(userAgent, "firefox") {
		result.Browser = "Firefox"
	} else if strings.Contains(userAgent, "Chrome") {
		result.Browser = "Chrome"
	} else if strings.Contains(userAgent, "Safari") {
		result.Browser = "Safari"
	} else if strings.Contains(userAgent, "MSIE") {
		result.Browser = "MSIE"
	} else if strings.Contains(userAgent, "Opera") {
		result.Browser = "Opera"
	} else {
		result.Browser = "Unknown"
	}

	if strings.Contains(userAgent, "mobile") {
		result.IsPhone = true
	}

	return result
}
