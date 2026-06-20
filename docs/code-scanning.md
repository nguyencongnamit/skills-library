# GitHub Code Scanning

The `gate` command emits **SARIF 2.1.0**, so vibe-guard findings can land
directly in a repository's **Security → Code scanning** tab. The composite
GitHub Action does the upload for you: set the `sarif-file` input and it writes
the report, publishes it (even when the gate fails, so the findings stay
visible), and then fails the pull request when anything meets the severity
floor.

## Workflow

```yaml
name: secure-code gate

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # required for the SARIF upload

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: namncqualgo/skills-library@v0.4.0
        with:
          files: Dockerfile package-lock.json .github/workflows/ci.yml
          severity-floor: high
          sarif-file: secure-code.sarif   # turns on Code Scanning upload
```

A copy-paste version lives at
[`examples/github-code-scanning.yml`](https://github.com/namncqualgo/skills-library/blob/main/examples/github-code-scanning.yml).

## Action inputs

| Input | Default | Purpose |
|---|---|---|
| `files` | _(required)_ | Space-separated files to gate. |
| `severity-floor` | `high` | Lowest severity that fails the gate. |
| `sarif-file` | _(empty)_ | When set, write SARIF here and upload it. Empty keeps the default text mode. |
| `upload-sarif` | `true` | Upload the SARIF to Code Scanning. Set `false` to produce the artifact without uploading. |
| `version` | `latest` | npm version / dist-tag of `@namncqualgo/secure-code-mcp` to run. Pin for reproducible CI. |

## Generating SARIF locally

Every file scanner — plus `gate` itself — accepts `--format sarif`:

```bash
skills-check gate Dockerfile package-lock.json \
  --severity-floor high --format sarif > secure-code.sarif
```

`gate` writes the SARIF **before** its non-zero exit, so a failing gate still
produces a valid, uploadable artifact. Exit codes: `0` clean, `1` findings at or
above the floor, `2` an operational error (no SARIF written).
