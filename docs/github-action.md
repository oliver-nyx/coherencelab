# GitHub Action

Reusable composite action that installs CoherenceLab and runs a coherence scan in CI.

## Marketplace-style usage

```yaml
name: Coherence

on:
  push:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: oliver-nyx/coherencelab@v1.4.0
        with:
          profile: chrome-131-win
          min-score: "90"
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `profile` | yes | — | Profile ID (`chrome-131-win`, `chrome-131-ios`, …) |
| `min-score` | no | `90` | Minimum percentage to pass |
| `mode` | no | `local` | `local`, `mutate`, or `live` |
| `mutate` | no | — | Mutation when `mode=mutate` |
| `probe` | no | — | Probe URL when `mode=live` |
| `insecure` | no | `false` | Skip TLS verify for live probes |
| `version` | no | `v1.4.0` | Release tag/branch to clone (ignored if `local-source` set) |
| `local-source` | no | — | Path to local checkout (use `.` when dogfooding this repo) |
| `working-directory` | no | `.` | Directory to run from |
| `go-version` | no | `1.24` | Go toolchain for the build |

## Outputs

| Output | Description |
|--------|-------------|
| `grade` | Letter grade `A`–`F` |
| `score` | Score percentage |

```yaml
- id: coherence
  uses: oliver-nyx/coherencelab@v1.4.0
  with:
    profile: chrome-132-win

- run: echo "grade=${{ steps.coherence.outputs.grade }} score=${{ steps.coherence.outputs.score }}"
```

## Mutation smoke test

Fail the job if a known-bad identity somehow scores as coherent:

```yaml
- uses: oliver-nyx/coherencelab@v1.4.0
  with:
    profile: chrome-131-win
    mode: mutate
    mutate: wrong-platform
    min-score: "100"
  continue-on-error: true
  id: bad
- name: Expect mutation failure
  if: steps.bad.outcome == 'success'
  run: |
    echo "mutated identity should not pass"
    exit 1
```

## Publishing notes

This repository is the action (`action.yml` at root). Tag releases (`v1.4.0`) so consumers can pin `@v1.4.0` or `@v1`.

To list on the GitHub Marketplace: repository Settings → Actions → publish with the branding in `action.yml`.
