# Lab 06 — Capture vs uTLS corpus diff

**Code:** [`internal/dissect/corpus.go`](../../internal/dissect/corpus.go)

The RE workflow that separates serious work from JA3 screenshots:

1. Capture a **real** ClientHello (browser → your probe / Wireshark).
2. Synthesize what your **claimed** stack emits (`--utls chrome_131`).
3. Diff weighted surfaces: skeleton, ALPS, ECH, ciphers, groups, JA3.

JA3 can match while the extension skeleton disagrees — the report calls that out.

## Exercise

```bash
# Synthesize a "capture" for the lab (replace with real pcap export):
./bin/coherencelab lab clienthello --utls chrome_131 > /tmp/report.txt
# Save raw bytes from Wireshark as chrome.bin, then:

./bin/coherencelab lab corpus --bin chrome.bin --utls chrome_131
./bin/coherencelab lab corpus --bin chrome.bin --utls firefox_133
```

Self-check without a pcap (parrot vs itself should score ~100%):

```bash
# In Go tests: TestCorpusSelfDiffHighScore / TestCorpusChromeVsFirefoxLowScore
go test ./internal/dissect/ -run Corpus -v
```

## Weighted surfaces

| Field | Severity | Why |
|-------|----------|-----|
| extension_skeleton | critical | GREASE-stripped order is a stable family anchor |
| alps | critical | Chromium tell |
| ja3 / ciphers / groups / alpn | high | Classic fingerprint dimensions |
| ech / session_id_len | medium | Generation / middlebox-compat tells |

## Questions

1. When is a JA3 match insufficient evidence of fidelity?
2. What does a critical ALPS miss imply for a “Chrome” curl-impersonate profile?
3. How would you build a CI gate: corpus folder of real hellos vs pinned uTLS ids?
