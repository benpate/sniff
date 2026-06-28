# sniff 🐽

[![Go Reference](https://pkg.go.dev/badge/github.com/benpate/sniff.svg)](https://pkg.go.dev/github.com/benpate/sniff)
[![Version](https://img.shields.io/github/v/release/benpate/sniff?include_prereleases&style=flat-square&color=brightgreen)](https://github.com/benpate/sniff/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/benpate/sniff/go.yml?branch=main)](https://github.com/benpate/sniff/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/benpate/sniff?style=flat-square)](https://goreportcard.com/report/github.com/benpate/sniff)
[![Codecov](https://img.shields.io/codecov/c/github/benpate/sniff.svg?style=flat-square)](https://codecov.io/gh/benpate/sniff)

`sniff` inspects a browser `User-Agent` string and guesses the device, operating system, and browser. `UserAgent(ua)` returns a `BrowserInfo`; `IsMobile(ua)` and `IsDesktop(ua)` are convenience wrappers over it.

User-Agent sniffing is unreliable by nature — prefer feature detection or [client hints](https://developer.mozilla.org/en-US/docs/Web/HTTP/Client_hints) when you can. This library is a best-effort guess for the cases where you cannot.

```go
info := sniff.UserAgent(request.Header.Get("User-Agent"))
// info.Device == "phone", info.IsIOS == true, info.Browser == "Safari"
```

## What matters here

- **The browser table is priority-ordered, most-specific first.** Modern browsers impersonate each other: Edge, Samsung Internet, and Vivaldi all carry both `chrome` and `safari` tokens, and Chrome carries `safari`. `sniffBrowser` returns the *first* match, so the table in [sniff.go](sniff.go) must keep Edge/Samsung/Vivaldi/Opera ahead of `chrome`, and `chrome` ahead of `safari`. Reordering it silently mislabels browsers.

- **Device classification is authoritative; a bare `mobile` token never overrides it.** `sniffDevice` decides the device from the OS keyword (`ipad` → tablet, `iphone` → phone, etc.), *then* the browser is filled in. An iPad UA contains `Mobile/15E148` but must stay a tablet — don't add a top-level "contains mobile → phone" rule, it would corrupt tablets into phones.

- **Branch order in `sniffDevice` is load-bearing.** `macintosh` is checked before `windows` (Safari-on-Mac UAs can mention both); `windows`/`android` consult the `mobile` token only *within* their own branch to split phone vs. desktop/tablet.

- **Everything is matched against a lowercased UA.** `UserAgent` lowercases once up front, so every keyword in the tables is lowercase and matching is case-insensitive. `IsMobile`/`IsDesktop` route through `UserAgent`, so the three never disagree — a contract the tests pin explicitly.

- **No device keyword → desktop.** Unrecognized agents (crawlers, empty strings) fall through to a plain desktop with `Browser: "Unknown"`. Callers can rely on `Device` always being one of `desktop`/`tablet`/`phone` and `Browser`/`Description` always being non-empty.
