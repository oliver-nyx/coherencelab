# Browser Profiles

Each YAML file defines expected identity signals for one browser + platform combination.

## Coverage matrix

| Browser | Windows | macOS | Linux | Android | iOS |
|---------|---------|-------|-------|---------|-----|
| Chrome 132 | ✓ | ✓ | ✓ | — | — |
| Chrome 131 | ✓ | ✓ | ✓ | ✓ | ✓ (CriOS) |
| Chrome 120 | ✓ | — | — | — | — |
| Firefox 133 | ✓ | ✓ | ✓ | — | — |
| Safari 18 | — | ✓ | — | — | ✓ |
| Edge 131 | ✓ | ✓ | — | — | — |
| Brave 131 | ✓ | — | — | — | — |
| Opera 116 | ✓ | — | — | — | — |

**18 profiles** covering the most common real-world combinations.

## Notable coherence cases

- **Chrome iOS (CriOS)** — UA brands as Chrome, but TLS/HTTP/2 must match Safari/WebKit. Spoofing desktop Chrome TLS with a CriOS UA is a critical fail.
- **Opera** — Chromium TLS with Opera Client Hints brands (`"Opera";v=…`).

## Validate all profiles

```bash
go test ./internal/scan/ -run TestAllProfilesCoherentLocally
# or
coherencelab profiles validate --profiles profiles
```

## Adding a profile

Copy an existing profile and adjust:

1. `user_agent.value` — full UA string your client sends
2. `user_agent.pattern` — substring used for validation
3. `client_hints` — must match browser family (Firefox/Safari/CriOS send none)
4. `tls.utls_client_id` — uTLS preset (`chrome_131`, `chrome_132`, `firefox_133`, `safari_ios_18`, etc.)
5. `http2` — SETTINGS must match browser family (Chromium vs Firefox vs WebKit)

Run `coherencelab scan -p <id> --profiles profiles` and confirm Grade **A**.
