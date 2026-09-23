# Web UI

Local report viewer for CoherenceLab scans.

## Start

```bash
coherencelab ui --profiles profiles --addr 127.0.0.1:8080
```

Open http://127.0.0.1:8080

## Features

- List built-in / custom profiles from `--profiles`
- Run **local** or **mutate** scans from the browser
- Category score bars + pass/fail table
- Load an existing JSON report (`scan -o report.json --format json`)

## API

| Endpoint | Description |
|----------|-------------|
| `GET /` | UI |
| `GET /api/profiles` | Profile list |
| `POST /api/scan` | `{ "profile", "mode", "mutate?" }` → scan report JSON |
