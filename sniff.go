package sniff

import "strings"

// UserAgent scans the browser's useragent string.
// Remember, kids: Browser sniffing = bad bad bad.  You should never do it.
func UserAgent(userAgent string) BrowserInfo {

	var result BrowserInfo

	// Sniff Device OS
	if strings.Contains(userAgent, "Macintosh") {
		result.IsMacintosh = true
		result.IsDesktop = true
		result.Device = "desktop"
		result.Description = "Macintosh PC"

	} else if strings.Contains(userAgent, "Windows") {

		if strings.Contains(userAgent, "Mobile") {
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

	} else if strings.Contains(userAgent, "iPhone") {
		result.IsPhone = true
		result.IsIOS = true
		result.Device = "phone"
		result.Description = "iPhone"

	} else if strings.Contains(userAgent, "iPad") {
		result.IsTablet = true
		result.IsIOS = true
		result.Device = "tablet"
		result.Description = "iPad"

	} else if strings.Contains(userAgent, "Android") {

		if strings.Contains(userAgent, "Mobile") {
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

	} else if strings.Contains(userAgent, "Blackberry") {
		result.IsPhone = true
		result.Device = "phone"
		result.Description = "Blackberry Phone"
	} else {
		result.IsDesktop = true
		result.Device = "desktop"
		result.Description = "Unrecognized Device"
	}

	// Sniff Browser Info
	if strings.Contains(userAgent, "Firefox") {
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

	return result
}
