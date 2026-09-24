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

**Firefox HTTP/3 with a local/enterprise CA** also requires:

```js
user_pref("network.http.http3.disable_when_third_party_roots_found", false);
```

Without that pref, neqo completes TLS (`Authenticated error=0x0`) then closes
with `NS_ERROR_NET_INADEQUATE_SECURITY` (`0x804b0014`) because
`hasThirdPartyRoots=1` — the probe sees `APPLICATION_ERROR (remote)` before
any H3 control frames. See Mozilla bugs 1925014 / 1929368.

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

# Firefox H2 + H3 (profile prefs above + localDomains)
# user.js must include disable_when_third_party_roots_found=false for H3
firefox -no-remote -profile C:\clcap\ffprof https://example.com:8443/probe
```

Copy the newest `probe-*.h2.bin` / `probe-*.h3.bin` /
`probe-*.quic.bin` / `probe-*.quic-flight.bin` / `*.clienthello.bin` into
`testdata/corpus/` with the catalog names in `internal/dissect/fixtures.go`,
then update golden locks in `golden_test.go` if fingerprints drift.

Firefox often fragments the ClientHello CRYPTO stream across multiple
Initials — the probe writes `*.quic-flight.bin` (`CLQI` magic) once the
merged stream parses. Use that file for `quic_initial_firefox`.

The H3 listener uses `quic.Transport.Listen` (handshake-complete Accept) with
an async Initial tee so multi-datagram Firefox flights are not starved.

## Honesty notes

| Fixture | Typical live shape |
|---------|-------------------|
| `h2_chrome` / `h2_edge` | request flight: SETTINGS + WINDOW_UPDATE + HEADERS; Akamai `…\|hdr:u=0,i\|m,a,s,p` |
| `h2_firefox` | request flight; Akamai `…\|hdr:u=0,i\|m,p,a,s` |
| `h3_chrome` / `h3_edge` | SETTINGS + GREASE + PRIORITY_UPDATE on control stream |
| `h3_firefox` | SETTINGS (`1,7` + WT draft `0x2b603742`/`0xffd277` + `0x33`/`0x8`) + GREASE frame; often **no** PRIORITY_UPDATE on first `/probe` control flight |
| `quic_initial_chrome` | decryptable Initial; often `gq0` (no grease_quic_bit) |
| `quic_initial_edge` | decryptable Initial; TP order differs from Chrome; `gq0` |
| `quic_initial_firefox` | `CLQI` flight (CRYPTO split across Initials); no Google `0x3128`; `gq0` |

Teaching fixtures (`h2_continuation`, `h3_chrome_crafted`, `quic_initial_crafted`)
keep the full EPS / `gq1` story for labs.
