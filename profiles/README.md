# Browser Profiles

Each YAML file defines expected identity signals for one browser + platform combination.

## Coverage matrix

| Browser | Windows | macOS | Linux | Android | iOS |
|---------|---------|-------|-------|---------|-----|
| Chrome 131 | ✓ | ✓ | ✓ | ✓ | — |
| Chrome 120 | ✓ | — | — | — | — |
| Firefox 133 | ✓ | ✓ | ✓ | — | — |
| Safari 18 | — | ✓ | — | — | ✓ |
| Edge 131 | ✓ | ✓ | — | — | — |
| Brave 131 | ✓ | — | — | — | — |

**13 profiles** covering the most common real-world combinations.

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
3. `client_hints` — must match browser family (Firefox/Safari send none)
4. `tls.utls_client_id` — uTLS preset (`chrome_131`, `firefox_133`, `safari_18`, etc.)
5. `http2` — SETTINGS must match browser family (Chromium vs Firefox vs WebKit)

Run `coherencelab scan -p <id> --profiles profiles` and confirm Grade **A**.
