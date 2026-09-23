# Browser profile auto-capture

Capture a draft CoherenceLab profile from a **real browser** (headers + JS runtime).

## Quick start

```bash
# Terminal 1 — start capture server
coherencelab serve --addr 127.0.0.1:8443 --capture-dir ./captured

# Terminal 2 / browser
# Open https://127.0.0.1:8443/capture
# Accept the self-signed certificate warning
# Click "Capture & save profile"
```

Files written to `./captured/`:

- `<id>-<timestamp>.json` — full capture input (for `coherencelab capture`)
- `<id>.yaml` — draft profile ready to review

Validate:

```bash
coherencelab scan --profile <id> --profiles ./captured
# or merge into the main library:
cp ./captured/<id>.yaml profiles/
coherencelab profiles validate --profiles profiles
```

## What is collected

| Layer | Source |
|-------|--------|
| User-Agent, Client Hints, Accept-* | HTTP request headers |
| HTTP/2 SETTINGS | Wire capture (when ALPN=h2) |
| TLS ALPN / version | Connection state |
| `navigator.*`, WebGL vendor/renderer | Page JavaScript |

TLS ClientHello (JA3 / uTLS preset) cannot be read from page JS. The draft profile **guesses** `utls_client_id` from the UA family (and forces `safari_ios_18` for CriOS). Review before production use.

## Offline path (unchanged)

```bash
coherencelab capture --input session.json --output profiles/my-client.yaml
```

## API

`POST /api/capture` with optional JSON body:

```json
{
  "id": "my-chrome-win",
  "name": "My Chrome",
  "js_runtime": {
    "navigator": { "platform": "Win32", "vendor": "Google Inc.", "webdriver": false },
    "webgl": { "vendor": "Google Inc.", "renderer": "ANGLE" }
  }
}
```

Headers from the POST itself are merged into the snapshot.
