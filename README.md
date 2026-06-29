# sniff 🐽

[![Go Reference](https://pkg.go.dev/badge/github.com/benpate/sniff.svg)](https://pkg.go.dev/github.com/benpate/sniff)
[![Version](https://img.shields.io/github/v/release/benpate/sniff?include_prereleases&style=flat-square&color=brightgreen)](https://github.com/benpate/sniff/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/benpate/sniff/go.yml?branch=main)](https://github.com/benpate/sniff/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/benpate/sniff?style=flat-square)](https://goreportcard.com/report/github.com/benpate/sniff)
[![Codecov](https://img.shields.io/codecov/c/github/benpate/sniff.svg?style=flat-square)](https://codecov.io/gh/benpate/sniff)

## Best-Effort User-Agent Sniffing for Go

`sniff` inspects a browser `User-Agent` string and guesses the device, operating system, and browser. `UserAgent(ua)` returns a `BrowserInfo`; `IsMobile(ua)` and `IsDesktop(ua)` are convenience wrappers over it.

User-Agent sniffing is unreliable by nature — prefer feature detection or [client hints](https://developer.mozilla.org/en-US/docs/Web/HTTP/Client_hints) when you can. This library is a best-effort guess for the cases where you cannot.

```go
info := sniff.UserAgent(request.Header.Get("User-Agent"))
// info.Device == "phone", info.IsIOS == true, info.Browser == "Safari"
```

## Pull Requests Welcome

I'm trying to make sniff the best it can be, and your help is greatly appreciated. If you find a bug or have an idea for a new feature, please open an issue or submit a pull request. We're all in this together! 🐽
