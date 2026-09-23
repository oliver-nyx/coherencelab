# Lab 11 — QUIC / H3 golden fingerprints & cross-layer coherence

**Code:** [`internal/dissect/golden.go`](../../internal/dissect/golden.go)

Labs 07–10 taught you to *read* H2 PRIORITY_UPDATE, H3 GREASE, and QUIC
transport parameters. Lab 11 asks the RE question that actually catches
impersonators:

> Do the chrome-like fixtures tell **one family story** across layers — and
> how far does a naive stack fall when scored against those goldens?

## Fingerprints

| Layer | Golden string | Live Chrome (bundled) | Teaching / crafted |
|-------|---------------|------------------------|--------------------|
| QUIC TP | `ids\|gN\|gq0/1` | `3128,8,5,4,3,6,9,7,1,20,11,f\|g1\|gq0` | `1,3,4,5,6,7,8,9,a,b,e,f,2ab2\|g1\|gq1` |
| HTTP/3 | `settings\|gfN\|priority` | `1,6,7,33,g\|gf1\|request_stream:0:u=0,i` | `1,6,7,g\|gf1\|…` (`h3_chrome_crafted`) |
| HTTP/2 | Akamai | `…\|15663105\|0\|` first flight | `…\|u=0,i\|m,a,s,p` (`h2_continuation`) |

GREASE ids are collapsed (`g` / `gN`) so the golden stays stable across
random GREASE values while still requiring **presence**. Live Chrome often
omits `grease_quic_bit` (`gq0`) — do not treat `gq1` as universal.

## Exercise

Default run (live chrome vs naive + live/teaching cross-layer):

```bash
./bin/coherencelab lab golden
```

Targeted diffs:

```bash
./bin/coherencelab lab golden --quic quic_initial_chrome --vs quic_tp_minimal
./bin/coherencelab lab golden --quic quic_initial_crafted --vs quic_tp_minimal
./bin/coherencelab lab golden --h3 h3_chrome --vs-h3 h3_minimal
./bin/coherencelab lab golden --cross
```

Confirm:

1. Live QUIC vs minimal score is **low** (rich TP set + GREASE vs sparse)
2. H3 chrome-vs-minimal score is **low** (no GREASE frames / no PRIORITY_UPDATE)
3. Live cross-layer is **Coherent: true** with documented EPS/`gq` timing gaps as signals
4. Teaching cross-layer (`h2_continuation` + `quic_initial_crafted`) is coherent on EPS + `gq1`
5. Self-diff (`h3_chrome` vs `h3_chrome`) would score ~100% — CI lock

Also visible on dissection:

```bash
./bin/coherencelab lab quic --fixture quic_initial_chrome   # live TP golden
./bin/coherencelab lab quic --fixture quic_initial_crafted  # teaching gq1
./bin/coherencelab lab h3 --fixture h3_chrome               # H3 golden
```

## CI gate idea

Pin `TransportFingerprint` / `H3Fingerprint` / live H2 Akamai strings in tests
(see `golden_test.go`). A `gen_corpus` regression that drops GREASE fails the
lock — same workflow as Lab 06 ClientHello corpus diffs, one layer up.
`gen_corpus` never overwrites `*-live.bin`.

## Questions

1. Why collapse GREASE *values* but still require GREASE *presence* in the golden?
2. What does “GREASE on H3 but not on QUIC TPs” imply about a claimed Chrome stack?
3. Why can live H2 field 3=`0` still be a real Chrome capture?

## Next

[Lab 12 — QPACK field sections](12-qpack.md)
