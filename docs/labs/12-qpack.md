# Lab 12 — QPACK field sections (HTTP/3 HEADERS)

**Code:** [`internal/dissect/qpack.go`](../../internal/dissect/qpack.go),
[`qpack_static.go`](../../internal/dissect/qpack_static.go)

Lab 03 taught HPACK. HTTP/3 HEADERS use **QPACK** (RFC 9204) — same idea
(static table + literals + Huffman), different table and a field-section
**prefix** (`Required Insert Count` + `Base`).

## Why this is hard

1. **Static indices are not HPACK.** `:method GET` is HPACK index **2** and
   QPACK index **17**. Copy-pasting HPACK bytes into an H3 HEADERS frame is an
   instant tell.
2. **Prefix before fields.** Every Encoded Field Section starts with RIC +
   Delta Base. Chromium with `QPACK_MAX_TABLE_CAPACITY=0` emits `RIC=0`.
3. **Dynamic table is a separate stream.** `RIC>0` means inserts arrived on
   the QPACK encoder stream — this lab refuses that path on purpose so you
   learn the boundary.

## Exercise

```bash
./bin/coherencelab lab qpack --demo chrome
./bin/coherencelab lab qpack --demo firefox
./bin/coherencelab lab qpack --fixture qpack_chrome
./bin/coherencelab lab qpack --fixture qpack_safari

# H3 control stream now decodes HEADERS:
./bin/coherencelab lab h3 --fixture h3_chrome_crafted
```

Confirm:

1. Chrome demo → pseudo `m,a,s,p`
2. Firefox → `m,p,a,s`; Safari → `m,s,p,a` (same families as Lab 03)
3. `h3_chrome` prints QPACK fields with `family≈chrome`
4. Feeding `RIC=1` bytes errors with an explicit dynamic-table message

## Contrast with Lab 03

| | HPACK (H2) | QPACK (H3) |
|--|------------|------------|
| Spec | RFC 7541 | RFC 9204 |
| `:method GET` static idx | 2 | 17 |
| `:path /` | 4 | 2 |
| Section prefix | none | RIC + Base |
| Dynamic inserts | same connection table | encoder *stream* |

## Questions

1. Why does `QPACK_MAX_TABLE_CAPACITY=0` make RIC=0 the common browser case?
2. What fails if an impersonator reuses HPACK indexed bytes inside H3 HEADERS?
3. Why is refusing `RIC>0` without an encoder stream the correct RE lab boundary?

## Next

Curriculum complete on Windows. Optional follow-ons for contributors:
live Safari ClientHello (macOS/iOS), or full QPACK dynamic-table / encoder-stream lab.
