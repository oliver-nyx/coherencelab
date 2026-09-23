# Corpus fixtures

Checked-in wire samples so labs work on a cold clone — **no Wireshark required**.

## Honesty label

| File | Source |
|------|--------|
| `clienthello-*.bin` | **uTLS-synthesized** via `SynthClientHello` (not a live browser pcap) |
| `h2-chrome-like.bin` | Crafted preface + Chromium-like SETTINGS/WINDOW_UPDATE + HEADERS/**CONTINUATION** |
| `h2-firefox-like.bin` | Crafted Firefox-like SETTINGS + `m,p,a,s` HEADERS |

Replace ClientHello bins with real browser captures when you have them; keep this README accurate.

## Regenerate

```bash
go run ./tools/gen_corpus.go
```

## Use

```bash
coherencelab lab fixtures
coherencelab lab clienthello --fixture chrome_131
coherencelab lab h2 --fixture h2_chrome
coherencelab lab corpus --fixture chrome_131 --utls chrome_131
coherencelab lab corpus --fixture chrome_131 --utls firefox_133
```
