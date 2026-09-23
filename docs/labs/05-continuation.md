# Lab 05 — CONTINUATION merge

**Code:** [`internal/dissect/h2.go`](../../internal/dissect/h2.go) (`assembleHeaderBlocks`)

RFC 9113: if `HEADERS` does not have `END_HEADERS`, the next frames **must** be
`CONTINUATION` on the same stream, with no other frames interleaved. HPACK
state spans the merge. Tools that decode only the first HEADERS payload will:

- miss fields that landed in CONTINUATION
- invent truncated / invalid HPACK errors
- sometimes scramble perceived pseudo-header order

## Exercise

```bash
./bin/coherencelab lab h2 --fixture h2_continuation
```

The `h2_continuation` teaching fixture deliberately splits HPACK across
HEADERS + CONTINUATION. (Live `h2_chrome` is SETTINGS+WINDOW_UPDATE only.)

Look for:

- `continuations=N` on the HEADERS detail line
- finding: `Merged HEADERS + N CONTINUATION`
- correct `pseudo=m,a,s,p` (or Firefox/Safari) **after** the merge

## What high-level RE looks for

- Explicit RFC citation in notes
- Contiguity check (wrong next frame → protocol error note)
- Decode **after** merge, not before
- Teaching that fingerprinting stacks fail here in the wild

## Next

[Lab 07 — RFC 9218 PRIORITY_UPDATE](07-priority.md)
