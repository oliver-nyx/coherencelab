# curl-impersonate Adapter

Scan [curl-impersonate](https://github.com/lwthiker/curl-impersonate) or curl_cffi session exports.

## Export format

```json
{
  "impersonate": "chrome131_windows",
  "user_agent": "Mozilla/5.0 ... Chrome/131.0.0.0 Safari/537.36",
  "headers": {
    "sec-ch-ua-platform": "\"Windows\""
  },
  "ja3": "...",
  "alpn": "h2"
}
```

## Scan

```bash
coherencelab scan --import curl-export.json --adapter curl --profiles profiles
```

## Compare

```bash
coherencelab compare --a httpcloak.json --adapter-a httpcloak \
  --b curl-export.json --adapter-b curl
```
