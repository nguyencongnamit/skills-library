# `evals/fixtures/cicd-hardening`

GitHub Actions workflow files with known anti-patterns. The P3 MCP
tool `scan_github_actions` is run against each file and the SARIF
output is compared to `expected.json`.

Anti-patterns covered, with citation:

| Fixture | Anti-pattern | Rules expected to fire |
| --- | --- | --- |
| `unpinned-action.yml` | `uses: actions/checkout@v4` (tag, not SHA) | `gha-default-permissions-read`, `gha-ast-unpinned-action` |
| `pull-request-target-checkout.yml` | `pull_request_target` + checkout of PR head | `gha-default-permissions-read`, `gha-pr-target-no-untrusted-checkout`, `gha-ast-pwn-request` |
| `curl-pipe-sh.yml` | `curl … \| sh` in a `run:` step | `gha-default-permissions-read`, `gha-no-curl-pipe-bash` |
| `expression-injection.yml` | `${{ github.event.* }}` interpolated into `run:` | `gha-default-permissions-read`, `gha-no-untrusted-script-injection`, `gha-ast-expression-injection` |
| `stored-credentials.yml` | `secrets.AWS_SECRET_ACCESS_KEY` instead of OIDC | `gha-default-permissions-read`, `gha-oidc-cloud-credentials` |
| `multiple-issues.yml` | four anti-patterns stacked in one workflow | five findings: `gha-default-permissions-read`, `gha-no-untrusted-script-injection`, `gha-no-curl-pipe-bash`, `gha-ast-unpinned-action`, `gha-ast-expression-injection` |
| `pinned-clean.yml` | control (every rule must clear) | zero findings |
| `self-hosted-runner.yml` | baseline for future self-hosted-runner rule | zero findings (no rule yet) |

The source checklist for every rule above is
`skills/cicd-security/checklists/github_actions_hardening.yaml`, plus
the Go-side AST checks in
`cmd/skills-mcp/internal/tools/library_scanners.go::appendAstWorkflowFindings`.

Layout: one `.yml` per fixture + an `expected.json` per file.
