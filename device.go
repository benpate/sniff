package sniff

// IsMobile returns TRUE if this User-Agent appears to be from a mobile device (a phone or a tablet)
func IsMobile(userAgent string) bool {

	// Uses the same case-insensitive matching as UserAgent so the two never disagree.

	info := UserAgent(userAgent)
	return info.IsPhone || info.IsTablet
}

// IsDesktop returns TRUE if this User-Agent appears to be from a desktop device
func IsDesktop(userAgent string) bool {

	// Uses the same case-insensitive matching as UserAgent so the two never disagree.

	return UserAgent(userAgent).IsDesktop
}
