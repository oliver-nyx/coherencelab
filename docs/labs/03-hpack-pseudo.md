# Lab 03 — HPACK & pseudo-header order

**Code:** [`internal/dissect/hpack.go`](../../internal/dissect/hpack.go),
[`pseudo.go`](../../internal/dissect/pseudo.go),
[`hpack_static.go`](../../internal/dissect/hpack_static.go)

HPACK does **not** reorder fields. Whatever order the browser’s request encoder
inserted is the order that arrives after decompression. That makes
pseudo-header order a stable family fingerprint:

| Family | Order | Token |
|--------|-------|-------|
| Chrome / Edge | `:method, :authority, :scheme, :path` | `m,a,s,p` |
| Firefox | `:method, :path, :authority, :scheme` | `m,p,a,s` |
| Safari | `:method, :scheme, :path, :authority` | `m,s,p,a` |

This is field 4 of the classic Akamai HTTP/2 fingerprint:
`SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo`.

## Exercise

```bash
./bin/coherencelab lab headers --demo chrome
./bin/coherencelab lab headers --demo firefox
./bin/coherencelab lab headers --demo safari
```

Then craft a HEADERS frame (or capture one) and run:

```bash
./bin/coherencelab lab h2 --bin session.h2
```

You should see the decoded pseudo order and the Akamai-style fingerprint string.

## What to look for in the code

1. **Representation framing is ours** — indexed / literal / dyn-size parsed by hand.
2. **Huffman strings** — RFC 7541 App B alphabet via `hpack.HuffmanDecodeToString` (documented boundary).
3. **Dynamic table** — newest entry at dyn index 1; eviction by size.
4. **`analyzePseudo`** — maps names → `m,a,s,p` and guesses family; flags Client Hints on Firefox order as a cross-layer smell.
5. **END_HEADERS required** — CONTINUATION merge is an explicit next lab (difficulty ladder).

## Questions

1. Why can’t a detector “normalize” pseudo order away?
2. Why do SETTINGS-matching impersonators still fail Akamai’s fourth field?
3. Where in Chromium is `m,a,s,p` decided? (Hint: `CreateSpdyHeadersFromHttpRequest`.)

## Next

[Lab 05 — CONTINUATION merge](05-continuation.md)
