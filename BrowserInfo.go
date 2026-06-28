package sniff

// BrowserInfo contains the information we can extract from a User-Agent string.
type BrowserInfo struct {
	Device      string // Device class: "desktop", "tablet", or "phone"
	IsDesktop   bool   // TRUE for desktop/laptop devices
	IsTablet    bool   // TRUE for tablet devices
	IsPhone     bool   // TRUE for phone devices
	IsWindows   bool   // TRUE for Microsoft Windows
	IsMacintosh bool   // TRUE for Apple macOS
	IsIOS       bool   // TRUE for Apple iOS (iPhone or iPad)
	IsAndroid   bool   // TRUE for Android
	Browser     string // Browser name (e.g. "Chrome"), or "Unknown"
	Description string // Human-friendly device summary (e.g. "iPhone")
}
