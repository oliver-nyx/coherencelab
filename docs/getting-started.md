# Getting Started with CoherenceLab

## The problem

When a protected website blocks your HTTP client, the cause is often not "bad TLS" or "bad headers" alone. It is a **contradiction between layers**:

```
Layer 1 (TLS):     Chrome 131 JA3 fingerprint     âœ“
Layer 2 (HTTP/2):  Chrome SETTINGS frame        âœ“
Layer 3 (Headers): Firefox User-Agent           âœ—  â† mismatch
Layer 4 (Hints):   Sec-Ch-Ua-Platform: "Linux"  âœ—  â† mismatch (profile says Windows)
```

Anti-bot systems correlate signals across layers. CoherenceLab catches these mismatches before you hit production.

## Installation

Requires Go 1.24+.

```bash
cd coherencelab
go build -o bin/coherencelab ./cmd/coherencelab
```

## Your first scan

```bash
./bin/coherencelab scan --profile chrome-131-win --profiles profiles
```

Expected output for a coherent profile:

```
Score:    150+ / max  Grade: A
Checks:   N passed, 0 failed
âœ“ Identity signals are coherent for profile chrome-131-win
```

Some checks may be **skipped** in local mode (e.g. live TLS ALPN) â€” that is normal. Skipped checks do not count toward the score.

## Understanding failures

When a check fails, the report shows:

```
[CRITICAL] User-Agent platform matches Sec-Ch-Ua-Platform
  Expected: windows
  Actual:   mozilla/5.0 ... (linux x86_64) ...
```

| Severity | Meaning |
|----------|---------|
| CRITICAL | Automatic grade F â€” likely immediate block |
| HIGH | Strong detection signal |
| MEDIUM | Contributes to risk score |
| LOW | Minor inconsistency |

## Live mode

Local mode validates header configuration. Live mode performs a **real TLS handshake** using uTLS browser presets:

```bash
./bin/coherencelab serve --addr 127.0.0.1:8443
./bin/coherencelab scan --profile chrome-131-win --mode live \
  --probe https://127.0.0.1:8443/probe --insecure --profiles profiles
```

You can also probe public fingerprint endpoints (use responsibly):

```bash
./bin/coherencelab scan --profile chrome-131-win --mode live \
  --probe https://tls.peet.ws/api/all --profiles profiles
```

## CI pipeline

### Option A â€” marketplace-style composite action

```yaml
- uses: oliver-nyx/coherencelab@v1.9.7
  with:
    profile: chrome-131-win
    min-score: "90"
```

See [GitHub Action docs](github-action.md).

### Option B â€” build from source

```yaml
- name: Coherence check
  run: |
    go build -o coherencelab ./cmd/coherencelab
    ./coherencelab scan --profile chrome-131-win --ci --min-score 90 --profiles profiles
```

## Next steps

- Read [README](../README.md) for full CLI reference
- Read the [identity coherence blog post](blog/identity-coherence.md)
- Create custom profiles in `profiles/`
- Use `demo` command to see coherent vs mismatched examples
- Integrate via `pkg/coherencelab` Go API
