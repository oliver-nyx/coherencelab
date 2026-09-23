# CoherenceLab

[![CI](https://github.com/oliver-nyx/coherencelab/actions/workflows/ci.yml/badge.svg)](https://github.com/oliver-nyx/coherencelab/actions/workflows/ci.yml)
[![Go Report](https://img.shields.io/badge/go-1.24+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/oliver-nyx/coherencelab)](https://github.com/oliver-nyx/coherencelab/releases)

**Open reverse-engineering lab for browser identity** â€” dissect real TLS ClientHellos and HTTP/2 frames, then validate cross-layer coherence.

This is not a bypass toolkit. It is a place to **read protocol bytes, understand what detectors can infer, and practice the same skills used in serious fingerprint RE**.

```
  Capture / synthesize          First-principles parse           Teach + score
  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”          â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”         â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
  â”‚ Real browser    â”‚          â”‚ ClientHello dissectorâ”‚         â”‚ Findings +  â”‚
  â”‚ uTLS impersonatorâ”‚ â”€â”€â”€â”€â”€â”€â–º â”‚ HTTP/2 frame parser  â”‚ â”€â”€â”€â”€â”€â”€â–º â”‚ labs + CI   â”‚
  â”‚ Session export  â”‚          â”‚ GREASE / order / ALPSâ”‚         â”‚ coherence   â”‚
  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜          â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜         â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

## Start with the hard labs

```bash
go build -o bin/coherencelab ./cmd/coherencelab

# Bundled fixtures â€” works on a cold clone
./bin/coherencelab lab fixtures
./bin/coherencelab lab clienthello --fixture chrome_131   # live-browser
./bin/coherencelab lab h2 --fixture h2_chrome             # live H2 first flight
./bin/coherencelab lab h2 --fixture h2_continuation       # teaching EPS/CONTINUATION
./bin/coherencelab lab h3 --fixture h3_chrome
./bin/coherencelab lab quic --fixture quic_initial_chrome # live QUIC Initial
./bin/coherencelab lab quic --fixture quic_vn
./bin/coherencelab lab golden
./bin/coherencelab lab corpus --fixture chrome_131 --utls firefox_133
```

Read the code while you run it:

- [`internal/dissect/`](internal/dissect/) â€” raw TLS + HTTP/2 + HTTP/3 + QUIC parsers with RE annotations
- [`testdata/corpus/`](testdata/corpus/) â€” checked-in wire samples (honestly labeled)
- [`docs/labs/01-clienthello.md`](docs/labs/01-clienthello.md)
- [`docs/labs/02-http2-wire.md`](docs/labs/02-http2-wire.md)
- [`docs/labs/03-hpack-pseudo.md`](docs/labs/03-hpack-pseudo.md)
- [`docs/labs/04-extension-permutation.md`](docs/labs/04-extension-permutation.md)
- [`docs/labs/05-continuation.md`](docs/labs/05-continuation.md)
- [`docs/labs/06-corpus-diff.md`](docs/labs/06-corpus-diff.md)
- [`docs/labs/07-priority.md`](docs/labs/07-priority.md)
- [`docs/labs/08-http3-priority.md`](docs/labs/08-http3-priority.md)
- [`docs/labs/09-quic-initial.md`](docs/labs/09-quic-initial.md)
- [`docs/labs/10-quic-vn-retry.md`](docs/labs/10-quic-vn-retry.md)

## Coherence scoring (supporting tool)

After you can read the wire, use the scorer to catch cross-layer contradictions in client configs:

### Install / scan

```bash
git clone https://github.com/oliver-nyx/coherencelab.git
cd coherencelab
go build -o bin/coherencelab ./cmd/coherencelab

./bin/coherencelab scan --profile chrome-131-win --profiles profiles
```

```bash
./bin/coherencelab profiles list --profiles profiles
```

### Demo: coherent vs mismatched identity

```bash
./bin/coherencelab demo --profiles profiles
```

### Live probe (real TLS handshake + H2 SETTINGS capture)

```bash
# Terminal 1 â€” start probe server
./bin/coherencelab serve --addr 127.0.0.1:8443

# Terminal 2 â€” scan against it (captures HTTP/2 SETTINGS from the wire)
./bin/coherencelab scan --profile chrome-131-win --mode live \
  --probe https://127.0.0.1:8443/probe --profiles profiles --insecure
```

Live mode captures the actual HTTP/2 SETTINGS frame sent on the wire and compares it to the profile. Local mode still validates configured SETTINGS offline.

### Capture a profile from a real browser

```bash
./bin/coherencelab serve --addr 127.0.0.1:8443 --capture-dir ./captured
# Open https://127.0.0.1:8443/capture in Chrome/Firefox/Safari
# Click "Capture & save profile" â†’ writes ./captured/<id>.yaml
```

See [docs/browser-capture.md](docs/browser-capture.md).

### Web UI report viewer

```bash
./bin/coherencelab ui --profiles profiles --addr 127.0.0.1:8080
# Open http://127.0.0.1:8080 â€” run scans or load a JSON report
```

### CI integration

```bash
./bin/coherencelab scan --profile chrome-131-win --ci --min-score 90 --profiles profiles
echo $?  # 0 = pass, 1 = critical failure or score below threshold
```

Or use the reusable GitHub Action:

```yaml
- uses: oliver-nyx/coherencelab@v1.9.1
  with:
    profile: chrome-131-win
    min-score: "90"
```

See [docs/github-action.md](docs/github-action.md).

### Import httpcloak session

```bash
coherencelab scan --import session.json --adapter httpcloak --profiles profiles
```

### Import Playwright / patchright session

```bash
coherencelab scan --import pw-export.json --adapter playwright --profiles profiles
```

### Import curl-impersonate session

```bash
coherencelab scan --import curl-export.json --adapter curl --profiles profiles
```

### Compare two exports

```bash
coherencelab compare --a examples/playwright-export.json --b examples/curl-export.json \
  --adapter-a playwright --adapter-b curl
```

### Capture new profile from JSON

```bash
coherencelab capture --input examples/capture-input.json --output profiles/my-client.yaml
coherencelab profiles validate --profiles profiles
```

## Scan Modes

| Mode | Description |
|------|-------------|
| `local` | Audit headers + profile config offline (default) |
| `live` | Send real HTTPS request with uTLS fingerprint to a probe URL |
| `mutate` | Intentionally break identity for testing (`--mutate wrong-platform`) |

### Mutation examples

```bash
# Platform mismatch: Chrome/Windows profile with Linux Client Hint
./bin/coherencelab scan -p chrome-131-win --mode mutate --mutate wrong-platform

# Browser mismatch: Chrome profile with Firefox User-Agent
./bin/coherencelab scan -p chrome-131-win --mode mutate --mutate wrong-browser

# Automation leak: forbidden header injected
./bin/coherencelab scan -p chrome-131-win --mode mutate --mutate automation-leak

# TLS mismatch: Chrome headers with Firefox TLS client
./bin/coherencelab scan -p chrome-131-win --mode mutate --mutate tls-mismatch

# JS automation leak: navigator.webdriver = true
./bin/coherencelab scan -p chrome-131-win --mode mutate --mutate js-webdriver
```

## Browser Profiles

**18 built-in profiles** in `profiles/` covering major browser Ã— platform combinations:

| ID | Browser | Platform |
|----|---------|----------|
| `chrome-132-win` | Chrome 132 | Windows |
| `chrome-132-mac` | Chrome 132 | macOS |
| `chrome-132-linux` | Chrome 132 | Linux |
| `chrome-131-win` | Chrome 131 | Windows |
| `chrome-131-mac` | Chrome 131 | macOS |
| `chrome-131-linux` | Chrome 131 | Linux |
| `chrome-131-android` | Chrome 131 | Android |
| `chrome-131-ios` | Chrome 131 (CriOS) | iOS |
| `chrome-120-win` | Chrome 120 | Windows |
| `firefox-133-win` | Firefox 133 | Windows |
| `firefox-133-mac` | Firefox 133 | macOS |
| `firefox-133-linux` | Firefox 133 | Linux |
| `safari-18-mac` | Safari 18 | macOS |
| `safari-18-ios` | Safari 18 | iOS |
| `edge-131-win` | Edge 131 | Windows |
| `edge-131-mac` | Edge 131 | macOS |
| `brave-131-win` | Brave 131 | Windows |
| `opera-116-win` | Opera 116 | Windows |

Validate the full library:

```bash
./bin/coherencelab profiles validate --profiles profiles
```

Each profile defines expected signals across:

- **User-Agent** + validation pattern
- **Client Hints** (`Sec-Ch-Ua`, platform, mobile)
- **Header order** and required `Sec-Fetch-*` headers
- **TLS** ALPN + uTLS client preset
- **HTTP/2 SETTINGS** frame values
- **Accept-Language** primary locale

### Custom profiles

Create `profiles/my-client.yaml`:

```yaml
id: my-client
name: My Custom Client
browser: chrome
version: "131"
platform: windows

user_agent:
  value: "Mozilla/5.0 ... Chrome/131.0.0.0 Safari/537.36"
  pattern: "Chrome/131.0.0.0"
  match_mode: contains
  major: 131

client_hints:
  sec_ch_ua: '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'
  sec_ch_ua_mobile: "?0"
  sec_ch_ua_platform: '"Windows"'

headers:
  order: [host, sec-ch-ua, user-agent, accept, accept-language]
  required:
    Sec-Fetch-Mode: navigate
  forbidden: [X-Selenium, X-Webdriver]
  accept: "text/html,application/xhtml+xml"
  accept_encoding: "gzip, deflate, br, zstd"

tls:
  alpn: [h2, http/1.1]
  utls_client_id: chrome_131

http2:
  header_table_size: 65536
  enable_push: 0
  max_concurrent_streams: 1000
  initial_window_size: 6291456
  max_frame_size: 16384
  max_header_list_size: 262144

accept_language:
  pattern: "en-US,en;q=0.9"
  primary: en-US
```

## Scoring

CoherenceLab runs **23 rules** across 8 categories:

| Category | Example checks |
|----------|----------------|
| `user_agent` | UA matches profile pattern |
| `client_hints` | Sec-Ch-Ua version, platform, mobile |
| `headers` | Required headers, forbidden automation leaks, header order |
| `tls` | ALPN negotiation, TLS version |
| `http2` | SETTINGS frame values |
| `js_runtime` | navigator.platform/vendor/webdriver, WebGL vendor/renderer |
| `accept_language` | Primary locale |
| `cross_layer` | UA â†” Client Hints â†” TLS â†” JS platform consistency |

**Grading:**

| Grade | Score | Condition |
|-------|-------|-----------|
| A | â‰¥ 95% | No critical failures |
| B | â‰¥ 85% | No critical failures |
| C | â‰¥ 70% | No critical failures |
| D | â‰¥ 55% | No critical failures |
| F | any | Any critical failure OR score < 55% |

Critical cross-layer failures (e.g. Firefox UA with Chrome Client Hints) automatically grade **F**.

## Go API

```go
import (
    "context"
    "github.com/oliver-nyx/coherencelab/pkg/coherencelab"
)

func main() {
    p, _ := coherencelab.LoadProfile("profiles/chrome-131-win.yaml")
    rep, _ := coherencelab.Scan(context.Background(), p, coherencelab.ScanLocal, "", "")
    println(rep.Result.Grade, rep.Result.Percentage)
}
```

## Architecture

```
coherencelab/
â”œâ”€â”€ cmd/coherencelab/       CLI entrypoint
â”œâ”€â”€ internal/
â”‚   â”œâ”€â”€ profile/            YAML profile loader + validation
â”‚   â”œâ”€â”€ signal/             Observed identity snapshot
â”‚   â”œâ”€â”€ dissect/            First-principles TLS ClientHello + HTTP/2 parsers
â”‚   â”œâ”€â”€ rules/              23 coherence rules engine
â”‚   â”œâ”€â”€ score/              Weighted scoring + grading
â”‚   â”œâ”€â”€ client/             uTLS HTTP client + header builder
â”‚   â”œâ”€â”€ h2wire/             HTTP/2 SETTINGS wire capture
â”‚   â”œâ”€â”€ probe/              Local TLS probe + browser capture server
â”‚   â”œâ”€â”€ scan/               Scan orchestration (local/live/mutate/import)
â”‚   â”œâ”€â”€ tlsfp/              JA3/JA4 helpers + uTLS preset mapping
â”‚   â”œâ”€â”€ adapters/           httpcloak / Playwright / curl import
â”‚   â”œâ”€â”€ compare/            Diff two session exports
â”‚   â”œâ”€â”€ capture/            Session JSON â†’ profile YAML
â”‚   â”œâ”€â”€ ui/                 Local Web UI report viewer
â”‚   â””â”€â”€ report/             Text + JSON report rendering
â”œâ”€â”€ docs/labs/              Reverse-engineering lab writeups
â”œâ”€â”€ action.yml              Reusable GitHub Action
â”œâ”€â”€ pkg/coherencelab/       Public Go API
â””â”€â”€ profiles/               Browser identity profiles
```

## What's complete vs planned

| Area | Status |
|------|--------|
| TLS ClientHello dissector (GREASE, order, ALPS, ECH) | âœ“ Complete |
| HTTP/2 frame dissector (SETTINGS / WINDOW_UPDATE / PRIORITY_UPDATE) | âœ“ Complete |
| HTTP/3 frame dissector (SETTINGS / GREASE / PRIORITY_UPDATE) | âœ“ Complete |
| QUIC Initial decrypt + transport parameters | âœ“ Complete |
| QUIC Version Negotiation + Retry integrity | âœ“ Complete |
| HPACK + pseudo-header order (Akamai field 4) | âœ“ Complete |
| ClientHello extension permutation entropy lab | âœ“ Complete |
| CONTINUATION merge before HPACK | âœ“ Complete |
| Capture vs uTLS corpus diff | âœ“ Complete |
| Bundled `testdata/corpus` fixtures + `--fixture` | âœ“ Complete |
| Live Chrome ClientHello fixture (probe capture) | ✓ Complete |
| Live Edge / Firefox ClientHello fixtures | ✓ Complete |
| Live Chrome/Edge HTTP/2 first-flight fixtures | ✓ Complete |
| Live Chrome QUICv1 Initial fixture | ✓ Complete |
| Wire-true JA3/JA4 from peeked ClientHello | ✓ Complete |
| QUICv1 Initial + TP GREASE lab | ✓ Complete |
| RFC 9218 PRIORITY_UPDATE + Akamai field 3 | âœ“ Complete |
| HTTP/3 PRIORITY_UPDATE (0xF0700/0xF0701) + GREASE | âœ“ Complete |
| RE labs (`lab â€¦` through H3 priority / fixtures) | âœ“ Complete |
| 23-rule coherence engine | âœ“ Complete |
| 18 browser profiles | âœ“ Complete |
| Local + mutate + live scan modes | âœ“ Complete |
| TLS probe server + uTLS client | âœ“ Complete |
| CLI, Go API, tests, docs | âœ“ Complete |
| Live HTTP/2 SETTINGS capture from wire | âœ“ Complete |
| httpcloak import adapter | âœ“ Complete |
| Profile capture command | âœ“ Complete |
| GitHub Actions CI | âœ“ Complete |
| Playwright / patchright import adapter | âœ“ Complete |
| curl-impersonate adapter | âœ“ Complete |
| Compare command (diff two exports) | âœ“ Complete |
| GitHub Action (reusable / marketplace-ready) | âœ“ Complete |
| Blog: identity coherence write-up | âœ“ Complete |
| JS runtime probes (WebGL, navigator) | âœ“ Complete |
| Profile auto-capture from real browser | âœ“ Complete |
| Web UI report viewer | âœ“ Complete |

## Roadmap

- [x] Adapter plugins for httpcloak, curl-impersonate, Playwright
- [x] GitHub Action for CI
- [x] Identity coherence blog write-up
- [x] JS runtime fingerprint probes (WebGL, navigator)
- [x] Profile sync from live browser capture
- [x] Web UI report viewer
- [x] First-principles TLS ClientHello + HTTP/2 dissectors (`lab`)
- [x] HPACK / pseudo-header order lab
- [x] Extension-permutation entropy lab
- [x] CONTINUATION merge + HPACK across fragments
- [x] Real-browser capture vs uTLS corpus diff
- [x] Packaged fixtures in `testdata/corpus/` + `--fixture`
- [x] PRIORITY_UPDATE / RFC 9218 (Akamai field 3)
- [x] HTTP/3 / QUIC PRIORITY_UPDATE lab
- [x] Replace uTLS-synth ClientHello fixtures with live browser pcaps
- [x] QUIC Initial / transport-parameter dissection lab
- [x] QUIC Retry / Version Negotiation lab
- [x] Live Edge ClientHello fixture (Chrome + Edge bundled)
- [x] Live Firefox ClientHello fixture (Windows; Safari still needs macOS/iOS)
- [x] QUIC/H3 golden fingerprints + cross-layer coherence (`lab golden`)
- [x] QPACK Encoded Field Section decode (Lab 12; static / RIC=0)
- [x] Live Chrome/Edge HTTP/2 first-flight fixtures + honest EPS timing notes
- [x] Live Chrome QUICv1 Initial fixture (wire-true TP golden; gq0 observed)
- [x] Wire-true JA3/JA4 from peeked ClientHello bytes
- [x] Live Firefox H2 first-flight fixture (enterprise_roots + probe Root CA)
- [x] Live Chrome H3 control-stream fixture via serve HTTP/3
- [ ] Live Safari ClientHello (requires macOS/iOS — deferred; skip on this host)

## Docs

- [Getting started](docs/getting-started.md)
- [Lab 01: ClientHello dissection](docs/labs/01-clienthello.md)
- [Lab 02: HTTP/2 wire](docs/labs/02-http2-wire.md)
- [Lab 03: HPACK / pseudo-header order](docs/labs/03-hpack-pseudo.md)
- [Lab 04: Extension permutation entropy](docs/labs/04-extension-permutation.md)
- [Lab 05: CONTINUATION merge](docs/labs/05-continuation.md)
- [Lab 06: Capture vs uTLS corpus diff](docs/labs/06-corpus-diff.md)
- [Lab 07: RFC 9218 PRIORITY_UPDATE](docs/labs/07-priority.md)
- [Lab 08: HTTP/3 PRIORITY_UPDATE](docs/labs/08-http3-priority.md)
- [Lab 09: QUIC Initial & transport parameters](docs/labs/09-quic-initial.md)
- [Lab 10: QUIC Version Negotiation & Retry](docs/labs/10-quic-vn-retry.md)
- [Lab 11: QUIC/H3 golden fingerprints](docs/labs/11-quic-h3-golden.md)
- [Lab 12: QPACK field sections](docs/labs/12-qpack.md)
- [GitHub Action](docs/github-action.md)
- [Blog: Why your HTTP client gets blocked](docs/blog/identity-coherence.md)
- [JS runtime probes](docs/adapters/js-runtime.md)
- [Browser profile capture](docs/browser-capture.md)
- [Web UI](docs/web-ui.md)
- Adapter docs under [`docs/adapters/`](docs/adapters/)

## License

MIT â€” see [LICENSE](LICENSE).

## Disclaimer

CoherenceLab is a **developer tool for building consistent HTTP clients** and auditing automation stacks. Use it to debug your own applications and research browser identity coherence. Respect website terms of service and applicable laws.
