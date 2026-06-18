package sniff

// BrowserInfo contains the information we can extract from a User-Agent string.
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
	Description string
}
