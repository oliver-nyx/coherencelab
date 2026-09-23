# Lab 11 — QUIC / H3 golden fingerprints & cross-layer coherence

**Code:** [`internal/dissect/golden.go`](../../internal/dissect/golden.go)

Labs 07–10 taught you to *read* H2 PRIORITY_UPDATE, H3 GREASE, and QUIC
transport parameters. Lab 11 asks the RE question that actually catches
impersonators:

> Do the chrome-like fixtures tell **one family story** across layers — and
> how far does a naive stack fall when scored against those goldens?

## Fingerprints

| Layer | Golden string | Example (chrome-like) |
|-------|---------------|------------------------|
| QUIC TP | `ids\|gN\|gq0/1` | `1,3,4,5,6,7,8,9,a,b,e,f,2ab2\|g1\|gq1` |
| HTTP/3 | `settings\|gfN\|priority` | `1,6,7,g\|gf1\|request_stream:0:u=0,i` |
| HTTP/2 | Akamai (Labs 03/07) | `…\|u=0,i\|m,a,s,p` |

GREASE ids are collapsed (`g` / `gN`) so the golden stays stable across
random GREASE values while still requiring **presence**.

## Exercise

Default run (chrome vs naive on both layers + cross-layer):

```bash
./bin/coherencelab lab golden
```

Targeted diffs:

```bash
./bin/coherencelab lab golden --quic quic_initial_chrome --vs quic_tp_minimal
./bin/coherencelab lab golden --h3 h3_chrome --vs-h3 h3_minimal
./bin/coherencelab lab golden --cross
```

Confirm:

1. QUIC chrome-vs-minimal score is **low** (missing GREASE + `grease_quic_bit` + sparse ids)
2. H3 chrome-vs-minimal score is **low** (no GREASE frames / no PRIORITY_UPDATE)
3. Cross-layer report is **Coherent: true** for the bundled chrome fixtures
4. Self-diff (`h3_chrome` vs `h3_chrome`) would score ~100% — CI lock

Also visible on dissection:

```bash
./bin/coherencelab lab quic --fixture quic_initial_chrome   # prints TP golden
./bin/coherencelab lab h3 --fixture h3_chrome               # prints H3 golden
```

## CI gate idea

Pin `TransportFingerprint` / `H3Fingerprint` strings in tests (see
`golden_test.go`). A `gen_corpus` regression that drops GREASE fails the
lock — same workflow as Lab 06 ClientHello corpus diffs, one layer up.

## Questions

1. Why collapse GREASE *values* but still require GREASE *presence* in the golden?
2. What does “GREASE on H3 but not on QUIC TPs” imply about a claimed Chrome stack?
3. Why is PRIORITY_UPDATE consistency across H2 and H3 a stronger tell than JA3 alone?

## Next

[Lab 12 — QPACK field sections](12-qpack.md)
