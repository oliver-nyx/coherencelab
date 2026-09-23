# Lab 01 — TLS ClientHello dissection

**Audience:** engineers who already know TLS exists and want to reverse-engineer
*what browsers actually send* — not what a JA3 string summarizes away.

**Code to read:** [`internal/dissect/tls_hello.go`](../../internal/dissect/tls_hello.go),
[`grease.go`](../../internal/dissect/grease.go),
[`tls_ja.go`](../../internal/dissect/tls_ja.go),
[`tls_annotate.go`](../../internal/dissect/tls_annotate.go)

## Exercise

```bash
go build -o bin/coherencelab ./cmd/coherencelab
./bin/coherencelab lab clienthello --utls chrome_131
./bin/coherencelab lab clienthello --utls firefox_133
```

Compare the two reports. You should be able to answer, from the dump alone:

1. Why is `legacy_version` still `0x0303` on a TLS 1.3 client?
2. Which fields must be **stripped** before JA3, and which must be **kept** for Chrome permutation analysis?
3. What does a 32-byte `session_id` imply on a TLS 1.3 ClientHello?
4. Why is ALPS a Chromium tell?
5. What does ECH presence/absence buy a detector even when SNI is visible?

## What high-level RE looks for in this code

- **First-principles parse** — record layer → handshake header → body → extensions in wire order.
- **GREASE as a first-class citizen** — `IsGREASE16` follows draft-ietf-tls-grease; annotations explain the dual use (ignore for stable hashes, keep for entropy).
- **Extension order preserved** — order *is* the fingerprint for modern Chrome.
- **Honest JA4** — labeled JA4-inspired; the code comments warn against treating it as FoxIO-canonical without vector tests.
- **`supported_versions` length prefix** — 1-byte vector length per RFC 8446 (a common parser footgun).

## Capture your own

```bash
# Wireshark / tcpdump → export ClientHello record as raw bytes
./bin/coherencelab lab clienthello --bin clienthello.bin
```

Or paste hex:

```bash
./bin/coherencelab lab clienthello --hex 160301...
```

## Next

[Lab 02 — HTTP/2 wire dissection](02-http2-wire.md)
