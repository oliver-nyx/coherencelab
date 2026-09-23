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

# Live Chrome capture (bundled)
./bin/coherencelab lab clienthello --fixture chrome_131

# uTLS parrot baseline
./bin/coherencelab lab clienthello --fixture chrome_131_utls
./bin/coherencelab lab clienthello --utls firefox_133
```

Compare the two reports. You should be able to answer, from the dump alone:

1. Why is `legacy_version` still `0x0303` on a TLS 1.3 client?
2. Which fields must be **stripped** before JA3, and which must be **kept** for Chrome permutation analysis?
3. What does a 32-byte `session_id` imply on a TLS 1.3 ClientHello?
4. Why is ALPS a Chromium tell?
5. What does ECH presence/absence buy a detector even when SNI is visible?

## Capture your own

```bash
coherencelab serve --addr 127.0.0.1:8443 --capture-dir ./captured
# open https://127.0.0.1:8443/probe in Chrome (accept self-signed cert)
coherencelab lab ingest-hello --bin ./captured/probe-*.clienthello.bin --name chrome_131
coherencelab lab clienthello --fixture chrome_131
```

Or Wireshark / hex:

```bash
./bin/coherencelab lab clienthello --bin clienthello.bin
./bin/coherencelab lab clienthello --hex 160301...
```

## Next

[Lab 02 — HTTP/2 wire dissection](02-http2-wire.md) ·
[Lab 06 — Capture vs uTLS corpus diff](06-corpus-diff.md)
