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
| `h2-chrome-live.bin` | **live-browser** — Chrome H2 **request** flight (HEADERS + `priority: u=0, i`; Akamai `…\|hdr:u=0,i\|m,a,s,p`) |
| `h2-edge-live.bin` | **live-browser** — Edge H2 request flight (same Chromium Akamai shape) |
| `h2-chrome-like.bin` | **crafted** — teaching H2 (`h2_continuation`: EPS + CONTINUATION) |
| `h2-firefox-live.bin` | **live-browser** — Firefox H2 **request** flight (`priority: u=0, i`; Akamai `…\|hdr:u=0,i\|m,p,a,s`) |
| `h2-firefox-like.bin` | **crafted** — Firefox-like SETTINGS+HEADERS (`h2_firefox_crafted`) |
| `h3-chrome-live.bin` | **live-browser** — real Chrome H3 control stream (SETTINGS+GREASE+PRIORITY_UPDATE) |
| `h3-edge-live.bin` | **live-browser** — real Edge H3 control stream |
| `h3-firefox-live.bin` | **live-browser** — real Firefox H3 control stream (WT draft SETTINGS + GREASE; often no PRIORITY_UPDATE on first flight) |
| `h3-chrome-like.bin` / `h3-minimal.bin` | **crafted** — teaching H3 / naive contrast (`h3_chrome_crafted`) |
| `qpack-chrome.bin` / `qpack-firefox.bin` / `qpack-safari.bin` | **crafted** — QPACK RIC=0 field sections (Lab 12) |
| `quic-initial-chrome-live.bin` | **live-browser** — real Chrome QUICv1 Initial (decryptable; often `gq0`) |
| `quic-initial-edge-live.bin` | **live-browser** — real Edge QUICv1 Initial (Chromium-family; TP wire order ≠ Chrome) |
| `quic-initial-firefox-live.bin` | **live-browser** — real Firefox QUICv1 Initial **flight** (`CLQI` multi-datagram; CRYPTO fragmented) |
| `quic-initial-chrome-like.bin` | **crafted** — teaching Initial with `grease_quic_bit` (`gq1`) / Retry ODCID |
| `quic-tp-minimal.bin` | **crafted** — raw transport_parameters without GREASE |
| `quic-vn-grease.bin` | **crafted** — Version Negotiation with QUICv1 + GREASE versions |
| `quic-retry.bin` | **crafted** — QUICv1 Retry with valid integrity tag |

## Regenerate synth fixtures

```bash
go run ./tools/gen_corpus.go
```

This **never overwrites** live bins (`*-live.bin`, `clienthello-chrome_131.bin`).
It refreshes `*_utls` / `firefox_133` / Safari / crafted H2 / H3 / QUIC bins.

## Capture live wire (ClientHello / H2 / QUIC)

```bash
coherencelab serve --addr 127.0.0.1:8443 --capture-dir ./captured --h2 --quic

# Real Chrome (map SNI to local probe):
chrome --ignore-certificate-errors \
  --host-resolver-rules="MAP example.com 127.0.0.1" \
  --enable-quic --origin-to-force-quic-on=example.com:8443 \
  https://example.com:8443/probe

coherencelab lab ingest-hello --bin ./captured/probe-*.clienthello.bin --name chrome_131
# Copy H2/QUIC captures into testdata/corpus as *-live.bin (see catalog in fixtures.go)
```

Firefox H2/H3 on a self-signed probe needs a trusted local CA (ClientHello still
captures without trust). Live Safari needs macOS/iOS.

## Use

```bash
coherencelab lab fixtures
coherencelab lab clienthello --fixture chrome_131          # live
coherencelab lab clienthello --fixture edge_live           # live Edge
coherencelab lab clienthello --fixture firefox_live        # live Firefox
coherencelab lab clienthello --fixture chrome_131_utls     # parrot
coherencelab lab corpus --fixture chrome_131 --utls chrome_131
coherencelab lab corpus --fixture firefox_live --utls firefox_133
coherencelab lab h2 --fixture h2_chrome                    # live
coherencelab lab h2 --fixture h2_firefox                   # live Firefox
coherencelab lab h2 --fixture h2_firefox_crafted           # teaching headers order
coherencelab lab h3 --fixture h3_chrome                    # live
coherencelab lab h3 --fixture h3_edge                      # live Edge
coherencelab lab h3 --fixture h3_firefox                   # live Firefox (neqo)
coherencelab lab h3 --fixture h3_chrome_crafted            # teaching + QPACK HEADERS
coherencelab lab qpack --fixture qpack_chrome
coherencelab lab quic --fixture quic_initial_chrome        # live
coherencelab lab quic --fixture quic_initial_crafted       # teaching gq1
coherencelab lab quic --fixture quic_vn
coherencelab lab quic --fixture quic_retry
coherencelab lab quic --fixture quic_tp_minimal --tp
coherencelab lab golden
```
