# Lab 02 — HTTP/2 wire dissection

**Code to read:** [`internal/dissect/h2.go`](../../internal/dissect/h2.go)

HTTP/2 SETTINGS and the post-preface `WINDOW_UPDATE` are among the highest
signal-to-noise identity surfaces after ClientHello. Most “TLS impersonation”
stacks still leak here.

## Exercise

Craft or capture a client preface + SETTINGS (+ optional WINDOW_UPDATE) and run:

```bash
./bin/coherencelab lab h2 --bin capture.h2
```

Questions the report should help you answer:

1. Why is `ENABLE_PUSH=1` a smell on a desktop Chrome claim?
2. What is special about `INITIAL_WINDOW_SIZE=6291456`?
3. What does connection-level `WINDOW_UPDATE` increment `15663105` indicate?
4. Why does `PRIORITY_UPDATE` / `NO_RFC7540_PRIORITIES` matter after RFC 9218?
5. Why does this lab **not** fully decode HPACK — and what would a follow-up lab add (pseudo-header order)?

## What high-level RE looks for

- Frame header parsed by hand (`length:24 type:8 flags:8 stream:31`).
- SETTINGS as 6-byte entries with per-ID teaching notes.
- Findings that cite **known browser constants**, not vibes.
- Explicit boundary: HEADERS payload left opaque with a pointer to HPACK/pseudo-order as the next hard problem.

## Tie-in to coherence

After you can read ClientHello + H2 SETTINGS from bytes, `coherencelab scan` stops
feeling like a black box: the scorer is checking the same surfaces you just dissected.
