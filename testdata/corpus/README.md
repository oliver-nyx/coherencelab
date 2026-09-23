# Corpus fixtures

Checked-in wire samples so labs work on a cold clone — **no Wireshark required**.

## Honesty label

| File | Source |
|------|--------|
| `clienthello-chrome_131.bin` | **live-browser** — real Google Chrome via `coherencelab serve` (Windows) |
| `clienthello-edge_live.bin` | **live-browser** — real Microsoft Edge via `coherencelab serve` (Windows) |
| `clienthello-chrome_131_utls.bin` | **utls-synth** — `HelloChrome_131` parrot baseline for Lab 06 |
| `clienthello-firefox_*.bin` / `safari_*.bin` | **utls-synth** (replace with live captures when you have those browsers) |
| `h2-chrome-like.bin` | Crafted Chromium-like H2 session (SETTINGS / WINDOW_UPDATE / PRIORITY_UPDATE / CONTINUATION) |
| `h2-firefox-like.bin` | Crafted Firefox-like H2 session |
| `h3-chrome-like.bin` / `h3-minimal.bin` | Crafted HTTP/3 control-stream frames |
| `quic-initial-chrome-like.bin` | Crafted QUICv1 protected Initial (CRYPTO + TPs + GREASE), padded ≥1200 |
| `quic-tp-minimal.bin` | Raw transport_parameters without GREASE |
| `quic-vn-grease.bin` | Version Negotiation with QUICv1 + GREASE versions |
| `quic-retry.bin` | QUICv1 Retry with valid integrity tag |

## Regenerate synth fixtures

```bash
go run ./tools/gen_corpus.go
```

This **never overwrites** `clienthello-chrome_131.bin` (live). It refreshes `*_utls` / Firefox / Safari / H2 / H3 / QUIC crafted bins.

## Capture a live ClientHello

```bash
coherencelab serve --addr 127.0.0.1:8443 --capture-dir ./captured

# Real Chrome (map SNI to local probe):
chrome --ignore-certificate-errors \
  --host-resolver-rules="MAP example.com 127.0.0.1" \
  https://example.com:8443/probe

coherencelab lab ingest-hello --bin ./captured/probe-*.clienthello.bin --name chrome_131
```

Also available: `GET /clienthello` downloads the last captured record.

## Use

```bash
coherencelab lab fixtures
coherencelab lab clienthello --fixture chrome_131          # live
coherencelab lab clienthello --fixture chrome_131_utls     # parrot
coherencelab lab corpus --fixture chrome_131 --utls chrome_131
coherencelab lab h2 --fixture h2_chrome
coherencelab lab h3 --fixture h3_chrome
coherencelab lab quic --fixture quic_initial_chrome
coherencelab lab quic --fixture quic_vn
coherencelab lab quic --fixture quic_retry
coherencelab lab quic --fixture quic_tp_minimal --tp
```
