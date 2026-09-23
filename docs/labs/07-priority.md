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

Chrome commonly sends `PRIORITY_UPDATE` **before** `HEADERS` (servers must buffer).

## Wire format (HTTP/2)

```
header stream id = 0 (REQUIRED)
payload:
  prioritized_stream_id : u31
  priority_field_value  : ASCII Structured Fields (e.g. "u=0, i")
```

## Exercise

```bash
./bin/coherencelab lab h2 --fixture h2_chrome
```

Confirm:

1. SETTINGS includes `NO_RFC7540_PRIORITIES = 1`
2. A `PRIORITY_UPDATE` frame with `stream=1 value="u=0, i"`
3. Akamai field 3 is `u=0,i` (not bare `0` or `1`)
4. Full token contains `9:1|…|u=0,i|m,a,s,p`

Compare Firefox fixture (no EPS frames):

```bash
./bin/coherencelab lab h2 --fixture h2_firefox
# Priority fingerprint field: 0
```

## What high-level RE looks for

- Strict check that header stream id is 0
- Structured-field parse of `u` / `i` (with an honest “minimal parser” note)
- Fingerprint field that carries the **value**, not a boolean
- Cross-check with `NO_RFC7540_PRIORITIES`

## Questions

1. Why did Chrome send PRIORITY_UPDATE before HEADERS, and what must servers do?
2. Why is Akamai field 3=`1` a lossy encoding of RFC 9218?
3. What does BOTH legacy PRIORITY and PRIORITY_UPDATE in one session imply?

## Next

[Lab 08 — HTTP/3 PRIORITY_UPDATE](08-http3-priority.md)

