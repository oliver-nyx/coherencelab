# Playwright Adapter

Scan Playwright / patchright browser context exports against CoherenceLab profiles.

## Export format

```json
{
  "browser": "chromium",
  "channel": "chrome",
  "user_agent": "Mozilla/5.0 ... Chrome/131.0.0.0 Safari/537.36",
  "locale": "en-US",
  "extra_http_headers": {
    "sec-ch-ua": "\"Google Chrome\";v=\"131\"...",
    "sec-ch-ua-platform": "\"Windows\""
  },
  "header_order": ["sec-ch-ua", "user-agent", "accept"]
}
```

## Scan

```bash
coherencelab scan --import pw-export.json --adapter playwright --profiles profiles
coherencelab scan --import pw-export.json --profile chrome-131-win --profiles profiles
```

Profile resolution order: `--profile` override → `profile` field → `channel` → `browser` → User-Agent inference.
