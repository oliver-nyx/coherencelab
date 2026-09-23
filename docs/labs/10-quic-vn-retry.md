# Lab 10 — QUIC Version Negotiation & Retry

**Code:** [`internal/dissect/quic_vn_retry.go`](../../internal/dissect/quic_vn_retry.go),
[`quic_vn_retry_craft.go`](../../internal/dissect/quic_vn_retry_craft.go)

Lab 09 decrypted QUICv1 Initials. Two earlier/parallel control packets matter
just as much for RE:

| Packet | Version field | Auth | Job |
|--------|---------------|------|-----|
| **Version Negotiation** | `0x00000000` | none (forgeable) | “I don't speak your version; here are mine” |
| **Retry** | QUICv1 (etc.) | AES-GCM tag with **fixed** key | Address validation; forces token on next Initial |

## Version Negotiation

```
long header + version=0 + DCID + SCID + Supported Version × N
```

Chromium-style servers often include **GREASE versions** of the form
`0x?a?a?a?a` alongside `0x00000001`. A sterile VN that only lists v1 is a
naive-stack smell. VN is **unauthenticated** — clients must not treat it as
proof of a real server.

## Retry

```
long header (type=Retry) + DCID + SCID + Retry Token + 16-byte Integrity Tag
```

Tag = AEAD_AES_128_GCM with RFC 9001 fixed key/nonce over the **Retry
Pseudo-Packet** (`ODCID_len ‖ ODCID ‖ Retry_without_tag`). Only someone who
saw the client's first Initial DCID can mint a valid tag.

After Retry, the client:

1. Sets next Initial DCID = Retry SCID  
2. Echoes the Retry Token in the Initial token field  
3. Puts the original DCID in `original_destination_connection_id` TP  

## Exercise

```bash
./bin/coherencelab lab quic --fixture quic_vn
./bin/coherencelab lab quic --fixture quic_retry
# Tag check uses the chrome-like Initial DCID by default:
./bin/coherencelab lab quic --fixture quic_retry --odcid 8394c8f03e515708
```

Confirm:

1. VN lists QUICv1 **and** at least one GREASE version  
2. Retry tag reports **VALID** with the matching ODCID  
3. Wrong `--odcid` → **INVALID**

## Questions

1. Why can anyone forge a Version Negotiation packet, and what does that imply for clients?
2. What secret does Retry integrity actually prove the server knew?
3. How does Retry interact with Initial key derivation (DCID change)?

## Next

[Lab 11 — QUIC / H3 golden fingerprints](11-quic-h3-golden.md)

