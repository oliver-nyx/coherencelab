# Corpus fixtures

Checked-in wire samples so labs work on a cold clone — **no Wireshark required**.

## Honesty label

| File | Source |
|------|--------|
| `clienthello-chrome_131.bin` | **live-browser** — real Google Chrome via `coherencelab serve` (Windows) |
| `clienthello-edge_live.bin` | **live-browser** — real Microsoft Edge via `coherencelab serve` (Windows) |
| `clienthello-firefox_live.bin` | **live-browser** — real Mozilla Firefox via `coherencelab serve` (Windows; SNI via `network.dns.localDomains`) |
| `clienthello-chrome_131_utls.bin` | **utls-synth** — `HelloChrome_131` parrot baseline for Lab 06 |
| `clienthello-firefox_133.bin` | **utls-synth** — Firefox Auto parrot (compare with `firefox_live`) |
| `clienthello-safari_*.bin` | **utls-synth** (live Safari needs macOS/iOS) |
| `h2-chrome-like.bin` | Crafted Chromium-like H2 session (SETTINGS / WINDOW_UPDATE / PRIORITY_UPDATE / CONTINUATION) |
| `h2-firefox-like.bin` | Crafted Firefox-like H2 session |
| `h3-chrome-like.bin` / `h3-minimal.bin` | Crafted HTTP/3 control-stream frames (chrome includes QPACK HEADERS) |
| `qpack-chrome.bin` / `qpack-firefox.bin` / `qpack-safari.bin` | Crafted QPACK RIC=0 field sections (Lab 12) |
| `quic-initial-chrome-like.bin` | Crafted QUICv1 protected Initial (CRYPTO + TPs + GREASE), padded ≥1200 |
| `quic-tp-minimal.bin` | Raw transport_parameters without GREASE |
| `quic-vn-grease.bin` | Version Negotiation with QUICv1 + GREASE versions |
| `quic-retry.bin` | QUICv1 Retry with valid integrity tag |

## Regenerate synth fixtures

```bash
go run ./tools/gen_corpus.go
```

This **never overwrites** live bins (`chrome_131`, `edge_live`, `firefox_live`). It refreshes `*_utls` / `firefox_133` / Safari / H2 / H3 / QUIC crafted bins.

## Capture a live ClientHello

```bash
coherencelab serve --addr 127.0.0.1:8443 --capture-dir ./captured

# Real Chrome (map SNI to local probe):
chrome --ignore-certificate-errors \
  --host-resolver-rules="MAP example.com 127.0.0.1" \
  https://example.com:8443/probe

coherencelab lab ingest-hello --bin ./captured/probe-*.clienthello.bin --name chrome_131

# Firefox (no --ignore-certificate-errors; ClientHello is written on first peek):
# profile user.js: network.dns.localDomains = "example.com"
firefox -headless -profile /tmp/ff-lab "https://example.com:8443/probe"
coherencelab lab ingest-hello --bin ./captured/probe-*.clienthello.bin --name firefox_live
```

Also available: `GET /clienthello` downloads the last captured record.

## Use

```bash
coherencelab lab fixtures
coherencelab lab clienthello --fixture chrome_131          # live
coherencelab lab clienthello --fixture edge_live           # live Edge
coherencelab lab clienthello --fixture firefox_live        # live Firefox
coherencelab lab clienthello --fixture chrome_131_utls     # parrot
coherencelab lab corpus --fixture chrome_131 --utls chrome_131
coherencelab lab corpus --fixture firefox_live --utls firefox_133
coherencelab lab h2 --fixture h2_chrome
coherencelab lab h3 --fixture h3_chrome
coherencelab lab qpack --fixture qpack_chrome
coherencelab lab quic --fixture quic_initial_chrome
coherencelab lab quic --fixture quic_vn
coherencelab lab quic --fixture quic_retry
coherencelab lab quic --fixture quic_tp_minimal --tp
coherencelab lab golden
```
