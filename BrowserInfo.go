package sniff

// BrowserInfo contains all of the information that  we can extract from the UserAgent string.
type BrowserInfo struct {
	Device      string
	IsDesktop   bool
	IsTablet    bool
	IsPhone     bool
	IsWindows   bool
	IsMacintosh bool
	IsIOS       bool
	IsAndroid   bool
	Browser     string
	Version     string
	Description string
}
