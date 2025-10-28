package sniff

import (
	"github.com/cloudflare/ahocorasick"
)

var mobile = ahocorasick.NewStringMatcher([]string{"Mobile", "iPhone", "Android"})

// IsMobile returns TRUE if this User Agent appears to be from a mobile device
func IsMobile(userAgent string) bool {
	userAgentBytes := []byte(userAgent)
	return mobile.Contains(userAgentBytes)
}
