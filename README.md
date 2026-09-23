# CoherenceLab

[![CI](https://github.com/oliver-nyx/coherencelab/actions/workflows/ci.yml/badge.svg)](https://github.com/oliver-nyx/coherencelab/actions/workflows/ci.yml)
[![Go Report](https://img.shields.io/badge/go-1.24+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/oliver-nyx/coherencelab)](https://github.com/oliver-nyx/coherencelab/releases)

**Browser identity consistency validator** — catch the mismatches that get HTTP clients and automation stacks blocked.

Most bot-detection failures are not a single bad fingerprint. They are **cross-layer contradictions**: Chrome TLS with Firefox headers, Windows `Sec-Ch-Ua-Platform` on a Linux User-Agent, HTTP/2 SETTINGS from Safari on a Chromium profile. CoherenceLab scores how well your identity signals align across layers.

```
  ┌─────────────┐     ┌──────────────┐     ┌─────────────┐
  │ TLS / JA3   │ ──► │ CoherenceLab │ ◄── │ Client Hints│
  └─────────────┘     │    Scorer    │     └─────────────┘
  ┌─────────────┐     │  23 rules    │     ┌─────────────┐
  │ HTTP/2      │ ──► │              │ ◄── │ Header Order│
  └─────────────┘     │              │     └─────────────┘
  ┌─────────────┐     │              │     ┌─────────────┐
  │ JS runtime  │ ──► │              │ ◄── │ User-Agent  │
  └─────────────┘     └──────────────┘     └─────────────┘
```

## Why CoherenceLab?

| Tool | What it does | Gap |
|------|--------------|-----|
| [httpcloak](https://github.com/sardanioss/httpcloak) | TLS/H2 fingerprinting | One layer only |
| [ShieldEye](https://github.com/diegopzz/ShieldEye) | Detects protections on pages | Doesn't validate *your* client |
| [pingly](https://github.com/0x676e67/pingly) | TLS/HTTP analysis server | No cross-layer scoring |

CoherenceLab fills the gap: **validate that every layer tells the same story**.

## Quick Start

### Install

```bash
git clone https://github.com/oliver-nyx/coherencelab.git
cd coherencelab
go build -o bin/coherencelab ./cmd/coherencelab
```

### Scan a profile (local — no network)

```bash
./bin/coherencelab scan --profile chrome-131-win --profiles profiles
```

### List available browser profiles

```bash
./bin/coherencelab profiles list --profiles profiles
```

### Demo: coherent vs mismatched identity

```bash
./bin/coherencelab demo --profiles profiles
```

### Live probe (real TLS handshake + H2 SETTINGS capture)

```bash
# Terminal 1 — start probe server
./bin/coherencelab serve --addr 127.0.0.1:8443

# Terminal 2 — scan against it (captures HTTP/2 SETTINGS from the wire)
./bin/coherencelab scan --profile chrome-131-win --mode live \
  --probe https://127.0.0.1:8443/probe --profiles profiles --insecure
```

Live mode captures the actual HTTP/2 SETTINGS frame sent on the wire and compares it to the profile. Local mode still validates configured SETTINGS offline.

### Capture a profile from a real browser

```bash
./bin/coherencelab serve --addr 127.0.0.1:8443 --capture-dir ./captured
# Open https://127.0.0.1:8443/capture in Chrome/Firefox/Safari
# Click "Capture & save profile" → writes ./captured/<id>.yaml
```

See [docs/browser-capture.md](docs/browser-capture.md).

### Web UI report viewer

```bash
./bin/coherencelab ui --profiles profiles --addr 127.0.0.1:8080
# Open http://127.0.0.1:8080 — run scans or load a JSON report
```

### CI integration

```bash
./bin/coherencelab scan --profile chrome-131-win --ci --min-score 90 --profiles profiles
echo $?  # 0 = pass, 1 = critical failure or score below threshold
```

Or use the reusable GitHub Action:

```yaml
- uses: oliver-nyx/coherencelab@v1.4.0
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

**18 built-in profiles** in `profiles/` covering major browser × platform combinations:

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
| `cross_layer` | UA ↔ Client Hints ↔ TLS ↔ JS platform consistency |

**Grading:**

| Grade | Score | Condition |
|-------|-------|-----------|
| A | ≥ 95% | No critical failures |
| B | ≥ 85% | No critical failures |
| C | ≥ 70% | No critical failures |
| D | ≥ 55% | No critical failures |
| F | any | Any critical failure OR score < 55% |

Critical cross-layer failures (e.g. Firefox UA with Chrome Client Hints) automatically grade **F**.

## Go API

```go
import (
    "context"
    "github.com/coherencelab/coherencelab/pkg/coherencelab"
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
├── cmd/coherencelab/       CLI entrypoint
├── internal/
│   ├── profile/            YAML profile loader + validation
│   ├── signal/             Observed identity snapshot
│   ├── rules/              18 coherence rules engine
│   ├── score/              Weighted scoring + grading
│   ├── client/             uTLS HTTP client + header builder
│   ├── h2wire/             HTTP/2 SETTINGS wire capture
│   ├── probe/              Local TLS probe server
│   ├── scan/               Scan orchestration (local/live/mutate/import)
│   ├── tlsfp/              JA3/JA4 + uTLS preset mapping
│   ├── adapters/           httpcloak / Playwright / curl import
│   ├── compare/            Diff two session exports
│   └── report/             Text + JSON report rendering
├── action.yml              Reusable GitHub Action
├── pkg/coherencelab/       Public Go API
└── profiles/               Browser identity profiles
```

## Output formats

```bash
# Human-readable (default)
./bin/coherencelab scan -p chrome-131-win --profiles profiles

# JSON report
./bin/coherencelab scan -p chrome-131-win -o report.json --format json --profiles profiles
```

## What's complete vs planned

| Area | Status |
|------|--------|
| 18-rule coherence engine | ✓ Complete → **23 rules** |
| 18 browser profiles | ✓ Complete |
| Local + mutate + live scan modes | ✓ Complete |
| TLS probe server + uTLS client | ✓ Complete |
| CLI, Go API, tests, docs | ✓ Complete |
| Live HTTP/2 SETTINGS capture from wire | ✓ Complete |
| httpcloak import adapter | ✓ Complete |
| Profile capture command | ✓ Complete |
| GitHub Actions CI | ✓ Complete |
| Playwright / patchright import adapter | ✓ Complete |
| curl-impersonate adapter | ✓ Complete |
| Compare command (diff two exports) | ✓ Complete |
| GitHub Action (reusable / marketplace-ready) | ✓ Complete |
| Blog: identity coherence write-up | ✓ Complete |
| JS runtime probes (WebGL, navigator) | ✓ Complete |
| Profile auto-capture from real browser | ✓ Complete |
| Web UI report viewer | ✓ Complete |

## Roadmap

- [x] Adapter plugins for httpcloak, curl-impersonate, Playwright
- [x] GitHub Action for CI
- [x] Identity coherence blog write-up
- [x] JS runtime fingerprint probes (WebGL, navigator)
- [x] Profile sync from live browser capture
- [x] Web UI report viewer

## Docs

- [Getting started](docs/getting-started.md)
- [GitHub Action](docs/github-action.md)
- [Blog: Why your HTTP client gets blocked](docs/blog/identity-coherence.md)
- [JS runtime probes](docs/adapters/js-runtime.md)
- [Browser profile capture](docs/browser-capture.md)
- [Web UI](docs/web-ui.md)
- Adapter docs under [`docs/adapters/`](docs/adapters/)

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

CoherenceLab is a **developer tool for building consistent HTTP clients** and auditing automation stacks. Use it to debug your own applications and research browser identity coherence. Respect website terms of service and applicable laws.
