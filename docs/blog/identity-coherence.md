# Why Your HTTP Client Gets Blocked: Identity Coherence

*A technical write-up for [antibot.blog](https://antibot.blog) / [debug.cat](https://debug.cat) â€” suitable for republication with attribution.*

**Author:** oliver-nyx Â· **Tool:** [CoherenceLab](https://github.com/oliver-nyx/coherencelab) Â· **Date:** 2026-09

---

## The wrong diagnosis

When a protected site returns a challenge page or silent drop, teams often blame a single layer:

- â€œOur JA3 is wrong â€” swap the TLS client.â€
- â€œHeaders look outdated â€” refresh the User-Agent.â€
- â€œHTTP/2 SETTINGS donâ€™t match Chrome â€” tune the frame.â€

Those fixes sometimes help. More often they **move the contradiction**. You upgrade TLS to Chrome 131 while the User-Agent still says Firefox. You fix Client Hints for Windows while the UA string still contains `X11; Linux`. Anti-bot systems do not score layers in isolation. They ask whether every layer tells the **same story**.

That property is **identity coherence**.

## Four layers, one identity

A modern browser session exposes at least four correlated surfaces:

| Layer | What is observed | Example |
|-------|------------------|---------|
| TLS | ClientHello / JA3 / JA4 / ALPN | Chrome 131 uTLS preset |
| HTTP/2 | SETTINGS frame values | `HEADER_TABLE_SIZE=65536`, `INITIAL_WINDOW_SIZE=6291456` |
| Headers | UA, Accept-*, Sec-Fetch-*, order | `Chrome/131.0.0.0 Safari/537.36` |
| Client Hints | `Sec-Ch-Ua*` | `"Google Chrome";v="131"` + `"Windows"` |

None of these is sufficient alone. What gets clients blocked is **cross-layer contradiction**:

```
TLS:      Chrome 131          âœ“
HTTP/2:   Chromium SETTINGS   âœ“
UA:       Firefox/133         âœ—  â† critical
Hints:    "Google Chrome"     âœ—  â† critical (hints say Chrome, UA says Firefox)
```

A detector does not need perfect fingerprints. It needs evidence that you are not a consistent browser.

## Failures that actually show up in production

### 1. Platform split

```
User-Agent:           ... (X11; Linux x86_64) ... Chrome/131 ...
Sec-Ch-Ua-Platform:   "Windows"
```

Desktop Chromium always aligns platform in the UA with Client Hints. This mismatch is an automatic fail in CoherenceLab (`cross.ua_platform`, critical).

### 2. Browser family split

```
User-Agent:  Firefox/133
Sec-Ch-Ua:   "Google Chrome";v="131", "Chromium";v="131", ...
```

Firefox does not send Client Hints. Chromium does. Emitting both is a signature of a patched stack, not a browser.

### 3. The teaching case: Chrome on iOS (CriOS)

Chrome on iPhone is **not** Chromium networking. Apple requires WebKit for in-app browsers. So:

| Surface | Desktop Chrome | Chrome on iOS |
|---------|----------------|---------------|
| UA token | `Chrome/` | `CriOS/` |
| TLS | Chromium ClientHello | Safari / iOS TLS |
| HTTP/2 SETTINGS | Chromium defaults | WebKit defaults |
| Client Hints | Present | Typically absent |

Spoofing a CriOS User-Agent while dialing with a Chrome TLS parrot is a **critical coherence failure**. The correct pair is CriOS UA + Safari/iOS TLS + WebKit HTTP/2 SETTINGS.

CoherenceLab encodes this as an explicit rule: if the UA contains `CriOS/`, the TLS preset must be iOS/Safari â€” not `chrome_*`.

### 4. Opera brands on Chromium TLS

Opera is Chromium underneath. TLS looks like Chrome. Client Hints look like Opera:

```
Sec-Ch-Ua: "Opera";v="116", "Chromium";v="131", ...
User-Agent: ... Chrome/131 ... OPR/116.0.0.0
```

If you copy Chrome Client Hints onto an Opera UA (or the reverse), you invent a browser that does not exist.

## HTTP/2 SETTINGS are not optional

Browser families diverge on SETTINGS even when TLS looks similar:

| Family | `MAX_CONCURRENT_STREAMS` | `INITIAL_WINDOW_SIZE` | `HEADER_TABLE_SIZE` |
|--------|--------------------------|------------------------|---------------------|
| Chromium | 1000 | 6291456 | 65536 |
| Firefox | 100 | 131072 | 65536 |
| WebKit / Safari / CriOS | 100 | 2097152 | 4096 |

CoherenceLab v1.3+ can capture the **wire** SETTINGS frame during live scans, not just echo the profile YAML. That closes the gap where a client claimed Chrome SETTINGS in config while Goâ€™s default HTTP/2 transport sent something else.

## Scoring coherence (how CoherenceLab works)

CoherenceLab runs **23 weighted rules** across eight categories (`user_agent`, `client_hints`, `headers`, `tls`, `http2`, `accept_language`, `js_runtime`, `cross_layer`).

- Critical cross-layer failures force grade **F**, regardless of partial score.
- Local mode audits configured identity without network I/O.
- Live mode performs a real uTLS handshake and optional H2 wire capture.
- Import adapters normalize httpcloak / Playwright / curl-impersonate exports into the same snapshot schema.

Typical CI gate:

```bash
coherencelab scan --profile chrome-131-win --ci --min-score 90
```

Exit code `1` means either a critical failure or a score below the threshold.

## How to use this mentally

When debugging a block, ask in order:

1. **Do UA and Client Hints agree on browser and platform?**
2. **Does TLS family match that browser?** (CriOS â†’ WebKit; desktop Chrome â†’ Chromium; Firefox â†’ Firefox.)
3. **Do HTTP/2 SETTINGS match the same family?**
4. **Are automation leaks present?** (`X-Selenium`, odd header order, missing `Sec-Fetch-*` on navigate.)

Fixing TLS first is tempting because JA3 dashboards are pretty. Fixing coherence first is what actually reduces unexpected blocks.

## Try it

```bash
git clone https://github.com/oliver-nyx/coherencelab
cd coherencelab
go build -o bin/coherencelab ./cmd/coherencelab

# Coherent profile â†’ Grade A
./bin/coherencelab scan --profile chrome-131-win --profiles profiles

# Intentional mismatch â†’ Grade F
./bin/coherencelab scan --profile chrome-131-win --mode mutate --mutate wrong-platform --profiles profiles

# CriOS / WebKit coherence
./bin/coherencelab scan --profile chrome-131-ios --profiles profiles
```

GitHub Actions (marketplace-style composite action ships in the same repo):

```yaml
- uses: oliver-nyx/coherencelab@v1.9.6
  with:
    profile: chrome-131-win
    min-score: "90"
```

## Closing

Bot detection is often framed as an arms race of fingerprints. In practice, a large share of failures are simpler: **the layers disagree**. Identity coherence is the discipline of making TLS, HTTP/2, headers, and Client Hints describe one browser on one platform â€” including awkward but real cases like Chrome on iOS.

CoherenceLab exists to make that check mechanical, testable, and CI-friendly.

---

*License for this article text: MIT, same as the project. Republish freely with a link back to https://github.com/oliver-nyx/coherencelab.*
