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
dissection is Labs 09–10 (`lab quic`); this lab assumes decrypted control-stream
bytes or crafted fixtures so you can focus on PRIORITY_UPDATE / GREASE.

## Exercise

```bash
./bin/coherencelab lab h3 --fixture h3_chrome
```

Live Chrome control stream (SETTINGS + GREASE + PRIORITY_UPDATE). For QPACK HEADERS on the same fixture surface, use the teaching bin:

```bash
./bin/coherencelab lab h3 --fixture h3_chrome_crafted
```

Firefox contrast (neqo — WebTransport draft SETTINGS, GREASE frame, **no**
PRIORITY_UPDATE on the live control stream in Windows lab captures — neither
first `/probe` nor tab-focus with
`network.http.http3.send_background_tabs_deprioritization=true`):

```bash
./bin/coherencelab lab h3 --fixture h3_firefox
# golden ≈ 1,7,2b603742,ffd277,33,8|gf1|0
./bin/coherencelab lab golden --h3 h3_firefox --vs-h3 h3_chrome
./bin/coherencelab lab golden --cross   # includes Firefox cross-layer + family contrast
```

That `|0` priority field is a **family signal**, not a capture failure:
Chromium paints `PRIORITY_UPDATE` early; Firefox's live control flight here does
not. (Gecko *can* emit focus-driven updates in tree — see
`Http3Stream::CurrentBrowserIdChanged` — but they do not show up on this probe.)

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

Side-by-side with H2 teaching fixture (EPS):

```bash
./bin/coherencelab lab h2 --fixture h2_continuation
./bin/coherencelab lab h3 --fixture h3_chrome
```

Live H2 first flight (no PRIORITY_UPDATE yet):

```bash
./bin/coherencelab lab h2 --fixture h2_chrome
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

[Lab 09 — QUIC Initial & transport parameters](09-quic-initial.md).
Live Safari ClientHello still needs macOS/iOS (Firefox live is bundled as `firefox_live`).
See also [Lab 11 — QUIC / H3 golden fingerprints](11-quic-h3-golden.md).
