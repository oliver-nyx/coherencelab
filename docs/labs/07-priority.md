# Lab 07 — RFC 9218 PRIORITY_UPDATE

**Code:** [`internal/dissect/priority.go`](../../internal/dissect/priority.go),
[`h2.go`](../../internal/dissect/h2.go)

The classic Akamai HTTP/2 fingerprint is four fields:

```
SETTINGS | WINDOW_UPDATE | PRIORITY | pseudo-header-order
```

Labs 02–06 covered fields 1, 2, and 4. Field 3 is where modern Chrome diverges
from legacy stacks:

| Era | Signal |
|-----|--------|
| RFC 7540 | `PRIORITY` frames / dependency tree → Akamai often `"0"` or a tree hash |
| RFC 9218 | `SETTINGS_NO_RFC7540_PRIORITIES=1` + `PRIORITY_UPDATE` with ASCII `u=` / `i` |

Chrome commonly signals RFC 9218 priority via the **`priority` HTTP header**
(`u=0, i`) on real navigations (Chrome 124+). Older teaching material and some
impersonators still emit hop-by-hop `PRIORITY_UPDATE` frames instead. A probe that
only captures the connection preface (SETTINGS+WINDOW_UPDATE) will see field 3=`0`
— that is honest preface-only data, not a broken Chrome.

## Wire format (HTTP/2)

```
header stream id = 0 (REQUIRED for PRIORITY_UPDATE)
payload:
  prioritized_stream_id : u31
  priority_field_value  : ASCII Structured Fields (e.g. "u=0, i")
```

Live Chrome also (or instead) places the same structured fields in a request
header: `priority: u=0, i`.

## Exercise

Teaching fixture (EPS frame + CONTINUATION):

```bash
./bin/coherencelab lab h2 --fixture h2_continuation
```

Confirm:

1. SETTINGS includes `NO_RFC7540_PRIORITIES = 1`
2. A `PRIORITY_UPDATE` frame with `stream=1 value="u=0, i"`
3. Akamai field 3 is `u=0,i` (frame form)
4. Full token contains `9:1|…|u=0,i|m,a,s,p`

Live request-flight contrast (Priority **header**, not frame):

```bash
./bin/coherencelab lab h2 --fixture h2_chrome
# Akamai: …|15663105|hdr:u=0,i|m,a,s,p
./bin/coherencelab lab h2 --fixture h2_edge
# same Chromium-family Akamai shape
```

Compare live Firefox request flight:

```bash
./bin/coherencelab lab h2 --fixture h2_firefox
# Akamai: 1:65536;2:0;4:131072;5:16384|12517377|hdr:u=0,i|m,p,a,s
```

## What high-level RE looks for

- Strict check that header stream id is 0
- Structured-field parse of `u` / `i` (with an honest “minimal parser” note)
- Fingerprint field that carries the **value**, not a boolean
- Cross-check with `NO_RFC7540_PRIORITIES`
- Honesty about capture timing (first flight vs request)

## Questions

1. Why did Chrome send PRIORITY_UPDATE before HEADERS, and what must servers do?
2. Why is Akamai field 3=`1` a lossy encoding of RFC 9218?
3. What does BOTH legacy PRIORITY and PRIORITY_UPDATE in one session imply?

## Next

[Lab 08 — HTTP/3 PRIORITY_UPDATE](08-http3-priority.md)
