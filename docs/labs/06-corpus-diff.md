# Lab 06 — Capture vs uTLS corpus diff

**Code:** [`internal/dissect/corpus.go`](../../internal/dissect/corpus.go)

The RE workflow that separates serious work from JA3 screenshots:

1. Capture a **real** ClientHello (browser → `coherencelab serve`).
2. Synthesize what your **claimed** stack emits (`--utls chrome_131`).
3. Diff weighted surfaces: extension set, ALPS, ECH, ciphers, groups, JA3.

JA3 can match while the extension skeleton disagrees — the report calls that out.

## Exercise

Cold-clone path (bundled **live** Chrome vs parrot):

```bash
./bin/coherencelab lab fixtures
./bin/coherencelab lab corpus --fixture chrome_131 --utls chrome_131
./bin/coherencelab lab corpus --fixture chrome_131 --utls firefox_133
./bin/coherencelab lab corpus --fixture chrome_131_utls --utls chrome_131
./bin/coherencelab lab corpus --fixture firefox_live --utls firefox_133
./bin/coherencelab lab corpus --fixture edge_live --utls chrome_131
```

Expect: live Chrome vs `HelloChrome_131` often lands well below a self-diff.
The miss that matters is `extension_set` (ML-KEM hybrids, ALPS variant, extra
types) — **not** extension order. Chromium permutes order per handshake, so
`extension_order` is reported as info and does not move the score. A JA3 miss
with a matching set is permutation, not a different browser.
Parrot-vs-parrot (`chrome_131_utls`) should score much higher.
Live Firefox vs `firefox_133` should beat a Chrome parrot on the same capture.

Capture your own:

```bash
coherencelab serve --capture-dir ./captured
# Chrome → https://127.0.0.1:8443/probe
coherencelab lab ingest-hello --bin ./captured/probe-*.clienthello.bin --name chrome_131
coherencelab lab corpus --fixture chrome_131 --utls chrome_131
```

## Weighted surfaces

| Field | Severity | Why |
|-------|----------|-----|
| extension_set | high | GREASE-stripped type set — stable family anchor |
| extension_order | info | Chromium permutes this; not scored |
| alps | critical | Chromium tell |
| ja3 / ciphers / groups / alpn | high | Classic fingerprint dimensions; JA3 also moves when order is shuffled |
| ech / session_id_len | medium | Generation / middlebox-compat tells |

## Questions

1. When is a JA3 match insufficient evidence of fidelity?
2. What does a critical ALPS miss imply for a “Chrome” curl-impersonate profile?
3. How would you build a CI gate: corpus folder of real hellos vs pinned uTLS ids?
