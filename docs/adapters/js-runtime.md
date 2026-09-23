# JS runtime probes

CoherenceLab can score **navigator** and **WebGL** signals for identity coherence — without embedding a browser.

## How it works

| Mode | Behavior |
|------|----------|
| `local` | Copies `js_runtime` from the profile into the snapshot (`source=profile`) |
| `live` | Same as local for JS (HTTP probe does not execute scripts) |
| `import` | Playwright/patchright exports can include a `js_runtime` block (`source=export`) |
| `mutate` | `js-webdriver` / `js-wrong-platform` for intentional failures |

Rules **skip** when the profile has no `js_runtime` — existing profiles stay Grade A.

## Profile YAML

```yaml
js_runtime:
  navigator:
    platform: Win32
    vendor: Google Inc.
    language: en-US
    webdriver: false
    max_touch_points: 0
  webgl:
    vendor: Google Inc.
    renderer: ANGLE
    match_mode: contains   # exact | contains (default)
```

## Playwright export

```json
{
  "browser": "chromium",
  "user_agent": "...",
  "js_runtime": {
    "navigator": {
      "platform": "Win32",
      "vendor": "Google Inc.",
      "webdriver": false
    },
    "webgl": {
      "vendor": "Google Inc. (NVIDIA)",
      "renderer": "ANGLE (NVIDIA, ...)"
    }
  }
}
```

Collector snippet (run in page context):

```js
({
  navigator: {
    platform: navigator.platform,
    vendor: navigator.vendor,
    language: navigator.language,
    languages: [...navigator.languages],
    hardware_concurrency: navigator.hardwareConcurrency,
    device_memory: navigator.deviceMemory,
    max_touch_points: navigator.maxTouchPoints,
    webdriver: navigator.webdriver === true
  },
  webgl: (() => {
    const c = document.createElement('canvas');
    const gl = c.getContext('webgl');
    if (!gl) return null;
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    return ext ? {
      vendor: gl.getParameter(ext.UNMASKED_VENDOR_WEBGL),
      renderer: gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)
    } : null;
  })()
})
```

## Rules

| ID | Severity | Checks |
|----|----------|--------|
| `js.navigator_platform` | high | Exact platform string |
| `js.navigator_vendor` | medium | Vendor (Firefox expects empty) |
| `js.navigator_webdriver` | critical | Automation leak |
| `js.webgl_vendor_renderer` | medium | Contains/exact match |
| `cross.js_ua_platform` | critical | navigator.platform ↔ UA / Client Hints |

Canvas hashes are **observe-only** (not scored) — too machine-specific for shared profiles.

## Demo

```bash
# Profile with js_runtime → Grade A
coherencelab scan -p chrome-131-win --profiles profiles

# Automation leak
coherencelab scan -p chrome-131-win --mode mutate --mutate js-webdriver --profiles profiles

# Import Playwright export with webdriver:true → critical fail
coherencelab scan --import examples/playwright-export-js.json --adapter playwright --profiles profiles
```
