# httpcloak Adapter

Scan session exports from [httpcloak](https://github.com/sardanioss/httpcloak) against CoherenceLab profiles.

## Export format

Save a JSON file from your httpcloak session:

```json
{
  "browser": "chrome131",
  "user_agent": "Mozilla/5.0 ... Chrome/131.0.0.0 Safari/537.36",
  "headers": {
    "sec-ch-ua": "\"Google Chrome\";v=\"131\"...",
    "sec-ch-ua-platform": "\"Windows\"",
    "accept-language": "en-US,en;q=0.9"
  },
  "header_order": ["host", "sec-ch-ua", "user-agent", "accept"],
  "tls": {
    "ja3": "...",
    "alpn": "h2",
    "utls_client_id": "chrome_131"
  }
}
```

## Scan

```bash
coherencelab scan --import session.json --adapter httpcloak --profiles profiles
coherencelab scan --import session.json --profile chrome-131-win --profiles profiles
```

Preset `browser` values auto-map to profiles (`chrome131` → `chrome-131-win`, etc.).
