# Contributing to secure-code

Thanks for your interest in contributing to **secure-code**. This document
describes the kinds of changes we welcome, the local workflow, and the rules
that keep the project's data and tooling trustworthy.

secure-code is released under the [MIT license](./LICENSE) and maintained by
[ShieldNet360](https://www.shieldnet360.com).

> [!IMPORTANT]
> **AI-assisted contributions:** this project does *not* accept pull
> requests that are fully or predominantly AI-generated. AI tools may
> be used solely in an assistive capacity, and all AI usage must be
> disclosed in the PR description. Please read
> [AGENTS.md](./AGENTS.md) before submitting any PR.

## Where to contribute

| Kind of change | Where it lives | Notes |
|----------------|----------------|-------|
| **New skill** | `skills/<id>/SKILL.md` plus rule files in `skills/<id>/rules/` or `checklists/` | Use [`skills/secret-detection/`](./skills/secret-detection) as the reference implementation. Add a `tests/corpus.json` if the rules are regex-driven. |
| **Vulnerability entry** | `vulnerabilities/supply-chain/malicious-packages/<ecosystem>.json`, `typosquat-db/known_typosquats.json`, `cve/code-relevant/cve_patterns.json` | Every entry needs at least one external reference (CVE ID, vendor advisory URL, or a reputable disclosure write-up). No anonymous "trust me" entries. |
| **DLP pattern** | `skills/secret-detection/rules/dlp_patterns.json` and matching test in `skills/secret-detection/tests/corpus.json` | Provide a regex, severity, hotwords, and at least one valid + one invalid (false-positive) test fixture. |
| **False-positive fix** | The relevant `*_exclusions.json` or a skill-specific exclusion file | These PRs are merged quickly. |
| **Detection rule** | `rules/{cloud,endpoint,container,saas}/<platform>/<name>.yml` | Follow the Sigma format. Include `schema_version: "1.0"` so the validator picks it up. |
| **Compliance mapping** | `skills/compliance-awareness/frameworks/{cwe,owasp}_mapping.yaml` or `compliance/*_mapping.yaml` | Every skill ID must be present in both `cwe_mapping.yaml` and `owasp_mapping.yaml`. |
| **CLI / SDK / compiler code** | `cmd/skills-check/`, `cmd/skills-mcp/`, `internal/`, `sdk/{go,python,typescript}/` | Add or update Go tests (`*_test.go`) for behaviour changes. |
| **Docs** | `*.md` files at the repo root, in `docs/`, in `skills/*/`, or in `packaging/*/` | Prose changes are welcome — keep the brand `secure-code` and preserve technical identifiers (`skills-check`, the Go module path). |

## Local setup

```bash
# Clone
git clone https://github.com/kennguy3n/skills-library.git
cd skills-library

# Build the CLI (Go 1.22+)
go build -trimpath -ldflags "-s -w" -o skills-check ./cmd/skills-check
go build -trimpath -ldflags "-s -w" -o skills-mcp   ./cmd/skills-mcp

# Validate every skill + rule file
./skills-check validate

# Run the full Go test suite
go test ./...

# Rebuild dist/ files (every PR must commit the regenerated files)
./skills-check regenerate
```

## PR checklist

Before opening a pull request, please run these in order:

1. `./skills-check validate` — passes on every committed `SKILL.md`, rule file,
   and checklist.
2. `go test ./...` — every package green, no skipped tests.
3. `./skills-check regenerate` — `dist/` re-rendered with no uncommitted drift.
4. `./skills-check manifest compute --path . --write` — manifest checksums are
   in sync. CI re-runs `./skills-check manifest verify --checksums-only` and
   rejects drift.
5. `last_updated` bumped on any modified `SKILL.md`. CI enforces this.
6. New / updated entries include at least one external reference URL.
7. Commit messages follow the convention used in `git log` (no force-pushing to
   `main`; do not amend other contributors' commits).

CI runs the same checks plus `go vet`, `gofmt`, `staticcheck`, the markdown
link checker, and the token-budget enforcer.

## Token budgets

Every `SKILL.md` declares `token_budget: { minimal, compact, full }`. The
`compiler` rebuilds each tier and fails the build if the rendered output
exceeds the declared budget. When you grow a skill's prose:

- Keep `minimal` strictly within 500 tokens (bullets only — ALWAYS / NEVER /
  KFP).
- Keep `compact` within 2000 tokens (full Rules + KFP + References, no
  examples or rationale).
- `full` may grow to 5000 tokens; use it for examples, rationale, and CWE
  links.

If you find yourself bumping the budget, consider splitting the skill rather
than enlarging the existing tier.

## Style

- **Brand:** the project is **secure-code**. The Go module path remains
  `github.com/kennguy3n/skills-library` and the CLI binary remains
  `skills-check` — these are stable technical identifiers. Use the brand name
  in prose, the technical identifiers in code/import paths.
- **Voice:** direct, neutral, factual. No marketing language in `SKILL.md` or
  vulnerability data. Authoritative sources are linked, not paraphrased.
- **No PII:** no researcher names, no reporter contact info, no internal
  ticket IDs — public advisory references only.

## Reporting a security issue

Please **do not** open a public issue for a security vulnerability in
secure-code itself. Follow the process in [SECURITY.md](./SECURITY.md).

## Code of conduct

Contributors are expected to interact professionally and respectfully. We
follow the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Report unacceptable behaviour to the maintainers listed in
[SECURITY.md](./SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the
MIT License — the same license that covers the rest of the project.
