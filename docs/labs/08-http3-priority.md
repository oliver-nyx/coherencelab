# Lab 08 — HTTP/3 PRIORITY_UPDATE (RFC 9218)

**Code:** [`internal/dissect/h3.go`](../../internal/dissect/h3.go),
[`quicvarint.go`](../../internal/dissect/quicvarint.go)

Lab 07 covered HTTP/2 Extensible Prioritization. HTTP/3 is the same
*urgency model* (`u=` / `i`) on a different wire:

| | HTTP/2 (Lab 07) | HTTP/3 (this lab) |
|--|-----------------|-------------------|
| Frame type | `0x10` | **`0xF0700`** (request) / **`0xF0701`** (push) |
| Where | Any stream; header stream id **MUST be 0** | **Control stream only** |
| Target id | 31-bit Prioritized Stream ID | QUIC **varint** stream/push id |
| SETTINGS | `NO_RFC7540_PRIORITIES=9` | **Does not exist** (H3 never had 7540 trees) |
| Extra tell | — | **GREASE** frames / settings (`0x1f·N+0x21`) |

Draft residue: early docs used frame type `0x0f` with Element Type bits in the
varint. The **final RFC 9218** split request vs push into two frame types.
Seeing `0x0f` in a capture is a dated-stack smell — the dissector flags it.

## Layer honesty

```
QUIC UDP packet → decrypt → STREAM frames → HTTP/3 frames  ← this lab
```

We parse **post-decrypt stream payloads**. Full Initial/CRYPTO/packet-number
labs are deferred; feeding Wireshark “Decrypted QUIC” export or crafted
fixtures is enough to learn the PRIORITY_UPDATE surface.

## Exercise

```bash
./bin/coherencelab lab h3 --fixture h3_chrome
```

Confirm:

1. SETTINGS use QPACK ids (`0x1`, `0x6`, `0x7`) — not H2 `ENABLE_PUSH` / window
2. At least one **GREASE** frame (`type % 0x1f == 0x21` form)
3. `PRIORITY_UPDATE(request)` with `type=0xF0700`, stream id `0`, value `u=0, i`
4. Fingerprint field ≈ `request_stream:0:u=0,i`

Naive contrast:

```bash
./bin/coherencelab lab h3 --fixture h3_minimal
# Priority fingerprint field: 0
# Finding: No GREASE frames…
```

Side-by-side with H2:

```bash
./bin/coherencelab lab h2 --fixture h2_chrome
./bin/coherencelab lab h3 --fixture h3_chrome
```

## What high-level RE looks for

- Correct **final** frame types (`0xF0700` / `0xF0701`), not draft `0x0f`
- Request-stream ids that are client-bidi (`id % 4 == 0`)
- GREASE presence (frames **and** settings) vs sterile parrot SETTINGS
- Absence of H2-only settings on an H3 control stream

## Questions

1. Why can H3 omit `NO_RFC7540_PRIORITIES` entirely?
2. Why is `PRIORITY_UPDATE` on a request stream (not the control stream) an error?
3. What does a stack that speaks H3 SETTINGS but never GREASE imply?

## Next

Replace uTLS-synth ClientHello fixtures with live browser pcaps, or dig into
QUIC transport parameters / TLS-in-CRYPTO for the Initial flight.
