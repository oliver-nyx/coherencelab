# Recapturing live corpus fixtures

Live bins under `testdata/corpus/*-live.bin` are real browser wire bytes.
`go run ./tools/gen_corpus.go` **never** overwrites them.

## One-time trust (Windows)

Probe PEMs are **machine-wide durable** under `%LOCALAPPDATA%\coherencelab\`
(override with `COHERENCELAB_CERT_DIR`). Switching `--capture-dir` no longer
mints a new Root CA — that used to break Firefox after the first capture.

```powershell
$env:COHERENCELAB_CERT_DIR = "$env:LOCALAPPDATA\coherencelab"
coherencelab serve --addr 127.0.0.1:8443 --capture-dir C:\clcap
# once per machine (or after deleting the durable PEMs):
certutil -addstore -f Root "$env:LOCALAPPDATA\coherencelab\probe-cert.pem"
```

Firefox also needs `security.enterprise_roots.enabled=true` in the profile
`user.js`, and/or a `distribution/policies.json` with
`Certificates.ImportEnterpriseRoots` + `Certificates.Install` pointing at the
durable PEM.

Chrome/Edge QUIC/H3 need the Root trust too — `--ignore-certificate-errors`
alone is not enough for HTTP/3.

## Capture recipes

```powershell
# Chrome / Edge H2 (force TCP)
chrome --ignore-certificate-errors --disable-quic `
  --host-resolver-rules="MAP example.com 127.0.0.1" `
  https://example.com:8443/probe

# Chrome / Edge H3
chrome --ignore-certificate-errors --enable-quic `
  --origin-to-force-quic-on=example.com:8443 `
  --host-resolver-rules="MAP example.com 127.0.0.1" `
  https://example.com:8443/probe

# Firefox H2 (profile with enterprise_roots + localDomains)
firefox -profile C:\clcap\ffprof https://example.com:8443/probe
```

Copy the newest `probe-*.h2.bin` / `probe-*.h3.bin` /
`probe-*.quic.bin` / `probe-*.quic-flight.bin` / `*.clienthello.bin` into
`testdata/corpus/` with the catalog names in `internal/dissect/fixtures.go`,
then update golden locks in `golden_test.go` if fingerprints drift.

Firefox often fragments the ClientHello CRYPTO stream across multiple
Initials — the probe writes `*.quic-flight.bin` (`CLQI` magic) once the
merged stream parses. Use that file for `quic_initial_firefox`.

## Honesty notes

| Fixture | Typical live shape |
|---------|-------------------|
| `h2_chrome` / `h2_edge` | request flight: SETTINGS + WINDOW_UPDATE + HEADERS; Akamai `…\|hdr:u=0,i\|m,a,s,p` |
| `h2_firefox` | request flight; Akamai `…\|hdr:u=0,i\|m,p,a,s` |
| `h3_chrome` / `h3_edge` | SETTINGS + GREASE + PRIORITY_UPDATE on control stream |
| `quic_initial_chrome` | decryptable Initial; often `gq0` (no grease_quic_bit) |
| `quic_initial_edge` | decryptable Initial; TP order differs from Chrome; `gq0` |
| `quic_initial_firefox` | `CLQI` flight (CRYPTO split across Initials); no Google `0x3128`; `gq0` |

Teaching fixtures (`h2_continuation`, `h3_chrome_crafted`, `quic_initial_crafted`)
keep the full EPS / `gq1` story for labs.
