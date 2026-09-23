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
5. How do CONTINUATION frames interact with HPACK decode (Lab 05), and why does
   pseudo-header **order** after merge matter more than JA3?

## What high-level RE looks for

- Frame header parsed by hand (`length:24 type:8 flags:8 stream:31`).
- SETTINGS as 6-byte entries with per-ID teaching notes.
- Findings that cite **known browser constants**, not vibes.
- HEADERS/CONTINUATION assembled then HPACK-decoded when `END_HEADERS` lands
  (Labs 03/05 deepen pseudo-order and merge rules).

## Next

[Lab 03 — HPACK & pseudo-header order](03-hpack-pseudo.md)
