# sniff — Notes for AI Agents

- **The browser table is priority-ordered, most-specific first.** Modern browsers impersonate each other: Edge, Samsung Internet, and Vivaldi all carry both `chrome` and `safari` tokens, and Chrome carries `safari`. `sniffBrowser` returns the *first* match, so the table in [sniff.go](sniff.go) must keep Edge/Samsung/Vivaldi/Opera ahead of `chrome`, and `chrome` ahead of `safari`. Reordering it silently mislabels browsers.

- **Device classification is authoritative; a bare `mobile` token never overrides it.** `sniffDevice` decides the device from the OS keyword (`ipad` → tablet, `iphone` → phone, etc.), *then* the browser is filled in. An iPad UA contains `Mobile/15E148` but must stay a tablet — don't add a top-level "contains mobile → phone" rule, it would corrupt tablets into phones.

- **Branch order in `sniffDevice` is load-bearing.** `macintosh` is checked before `windows` (Safari-on-Mac UAs can mention both); `windows`/`android` consult the `mobile` token only *within* their own branch to split phone vs. desktop/tablet. Critically, **`cros` (ChromeOS) and `android` are matched before the generic `linux` branch**, because all three carry `linux` in their UA — reordering would misclassify ChromeOS and Android as plain Linux desktops.

- **`Description` is display-only, not an API value.** It is human-readable prose (e.g. "iPhone", "Linux PC") and may change. The stable contract callers should switch on is `Device` (`desktop`/`tablet`/`phone`) plus the `Is*` booleans.

- **Everything is matched against a lowercased UA.** `UserAgent` lowercases once up front, so every keyword in the tables is lowercase and matching is case-insensitive. `IsMobile`/`IsDesktop` route through `UserAgent`, so the three never disagree — a contract the tests pin explicitly.

- **No device keyword → desktop.** Unrecognized agents (crawlers, empty strings) fall through to a plain desktop with `Browser: "Unknown"`. Callers can rely on `Device` always being one of `desktop`/`tablet`/`phone` and `Browser`/`Description` always being non-empty.

- **Modern iPads are detected as a Mac — and cannot be fixed here.** Since iPadOS 13, Safari on iPad sends a Macintosh desktop User-Agent by default, byte-for-byte identical to a real Mac. UA-only sniffing (all this package can do) therefore reports such an iPad as a Macintosh desktop. To distinguish them you need a signal outside the UA string: `navigator.maxTouchPoints > 1` (client-side JS — a Mac reports 0) or the `Sec-CH-UA-Platform` client hint. This is an accepted limitation, not a bug; don't try to "fix" it with UA heuristics, as that would misclassify real Macs.
