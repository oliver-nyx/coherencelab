# Lab 09 — QUIC Initial & transport parameters

**Code:** [`internal/dissect/quic_header.go`](../../internal/dissect/quic_header.go),
[`quic_crypto.go`](../../internal/dissect/quic_crypto.go),
[`quic_tp.go`](../../internal/dissect/quic_tp.go),
[`quic_craft.go`](../../internal/dissect/quic_craft.go)

Labs 01–08 stayed on TCP/TLS and post-decrypt HTTP/3 frames. Real Chrome
HTTP/3 starts earlier — on **UDP**, with a protected **Initial** packet whose
CRYPTO frame carries a TLS ClientHello that embeds `quic_transport_parameters`
(extension `0x39`).

```
UDP datagram
 └─ QUIC long header (version, DCID, SCID, token, length)
     └─ header protection (HP mask from sample)
     └─ AEAD payload  ← RFC 9001 Initial salt + DCID
         └─ CRYPTO → TLS ClientHello
             └─ ext 0x39 → transport parameters (+ GREASE 31·N+27)
```

## Why this is hard (and interesting)

| Surface | Tell |
|---------|------|
| QUICv1 Initial salt | Fixed `0x38762cf7…`; wrong version → AEAD fail |
| DCID | IKM for Initial secrets — must match the packet you decrypt |
| Padding to ≥1200 | Anti-amplification; sterile stacks often skip |
| TP GREASE (`31·N+27`) | Chromium/quic-go paint these; naive stacks omit |
| `grease_quic_bit` | Separate flag TP — Fixed Bit may be cleared later |
| GREASE versions (`0x?a?a?a?a`) | Version negotiation grease (header-only path) |

## Exercise

```bash
./bin/coherencelab lab quic --fixture quic_initial_chrome
./bin/coherencelab lab quic --fixture quic_initial_crafted
./bin/coherencelab lab quic --fixture quic_tp_minimal --tp
./bin/coherencelab lab quic --fixture quic_initial_chrome --header-only
```

Confirm:

1. Live packet decrypts (PN printed, CRYPTO present, GREASE TPs)
2. Embedded ClientHello SNI = `example.com`
3. Live TP golden often ends `|g1|gq0` — `grease_quic_bit` is **not** universal on real Chrome
4. Crafted fixture locks `|g1|gq1` for Lab 10 Retry ODCID / teaching
5. Minimal TP fixture has **no** GREASE entries

## Capture your own

Export a UDP payload that starts with a long-header Initial (Wireshark:
“QUIC” → copy packet bytes as raw UDP payload), then:

```bash
coherencelab lab quic --bin initial.udp
```

Only **version 0x00000001** Initials decrypt in this lab. Other versions still
parse with `--header-only`.

## Questions

1. Why can anyone decrypt a client's first Initial without a handshake secret?
2. What does AEAD failure with a correct-looking header usually mean?
3. Why pad Initials to 1200 bytes if the CRYPTO frame is only a few hundred?

## Next

[Lab 10 — QUIC Version Negotiation & Retry](10-quic-vn-retry.md) ·
[Lab 11 — QUIC / H3 golden fingerprints](11-quic-h3-golden.md)
