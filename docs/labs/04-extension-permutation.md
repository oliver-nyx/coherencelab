# Lab 04 — ClientHello extension permutation entropy

**Code:** [`internal/dissect/entropy.go`](../../internal/dissect/entropy.go)

JA3 strips GREASE and collapses many Chrome hellos into one hash. Real Chrome
still **permutes** GREASE placement and some extension order. If your
impersonator emits one frozen order across N handshakes, JA3 may match while
a smarter detector still clusters you as a parrot.

## Exercise

```bash
./bin/coherencelab lab permute --utls chrome_131 --samples 8
./bin/coherencelab lab permute --utls firefox_133 --samples 8
```

Compare:

- unique extension orders (with GREASE markers)
- whether the GREASE-stripped **skeleton** is stable
- JA3 collapse (almost always 1)

## What high-level RE looks for

- Measuring **entropy**, not a single hello dump
- Separating GREASE noise from the stable skeleton
- Calling out frozen Chrome-class orders as an impersonation smell
- Honesty when uTLS’s parrot itself is low-entropy (the lab teaches that too)

## Questions

1. If JA3 is identical but order histogram has 5 buckets, what did JA3 lose?
2. Why keep a GREASE-stripped skeleton as a secondary anchor?
3. How would you diff a real Chrome pcap corpus against this uTLS histogram?
