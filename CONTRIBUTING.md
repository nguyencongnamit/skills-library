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
| **DLP pattern** | `skills/secret-detection/checklists/secret_detection.yaml` (`checks:` block, `type: secret_pattern`) and matching test in `skills/secret-detection/tests/corpus.json` | Provide a regex, severity, hotwords, and at least one valid + one invalid (false-positive) test fixture. PR-B1 unified the legacy `rules/dlp_patterns.json` + `rules/dlp_exclusions.json` into this single YAML; the i18n locale sidecar was dropped. |
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
4. `./skills-check derive-checklists <skill-id>` for any skill whose `SKILL.md`
   you changed and whose bullets carry pattern markers (see "Pattern markers"
   below). CI re-runs the command with `--check` and rejects drift.
5. `./skills-check manifest compute --path . --write` — manifest checksums are
   in sync. CI re-runs `./skills-check manifest verify --checksums-only` and
   rejects drift.
6. `last_updated` bumped on any modified `SKILL.md`. CI enforces this.
7. New / updated entries include at least one external reference URL.
8. Commit messages follow the convention used in `git log` (no force-pushing to
   `main`; do not amend other contributors' commits).

CI runs the same checks plus `go vet`, `gofmt`, `staticcheck`, the markdown
link checker, and the token-budget enforcer.

## Pattern markers (linking SKILL.md to `checklists/*.yaml`)

Bullets in a `SKILL.md` ALWAYS / NEVER / KNOWN FALSE POSITIVES section may
declare themselves as a structured rule by appending an HTML comment marker:

```markdown
### NEVER
- Use end-of-life base images. As of mid-2026 this includes ...
  <!-- pattern: { id: dkr-eol-base-image, severity: critical, cwe: 1104, framework: dockerfile_hardening } -->
```

`skills-check derive-checklists <skill-id>` reads every tagged bullet and
**merges** it into the matching `checklists/<framework>.yaml`. Existing
YAML entries whose `id` is not in a marker are preserved verbatim — the
human maintainer still owns those rows. CI runs the same command with
`--check` and fails when SKILL.md and YAML are out of sync, so the two
files stay in lock-step without any manual diffing.

Marker payload (YAML flow style):

| field       | required? | meaning |
|-------------|-----------|---------|
| `id`        | yes       | kebab-case identifier; unique within the skill |
| `severity`  | no        | `critical` / `high` / `medium` / `low` / `info`. Defaults: ALWAYS → `high`, NEVER → `critical`, KFP → `info` |
| `cwe`       | no        | CWE identifier (integer) |
| `framework` | no\*      | YAML file basename under `checklists/`. Required when the skill has more than one checklist file; inferred from the single file otherwise |

Bullets without a marker are ignored — they remain prose-only knowledge that
the AI assistant consults at code-generation time, deliberately not promoted
to an automated rule.

## Engine markers (declaring scanner engines in `SKILL.md`)

Skills that document a scannable artifact — Dockerfile, GitHub Actions
workflow, lockfile, source file with secrets — can declare which
scanner engines the MCP server should expose for that artifact. Engine
declarations live in the SKILL.md itself, parallel to the **Pattern
markers** above, so a single source of truth covers both "what rules
to apply" and "what tools can run them".

Place engine markers under a `## Scanner engines` H2 section (or any
H2 you prefer — the parser looks at marker syntax, not section
position). Each marker is an HTML comment carrying a YAML flow payload:

```markdown
## Scanner engines

- **Internal** — built-in regex rules; always available, offline.
  <!-- engine: {
    name: internal,
    type: builtin,
    scanner: dockerfile,
    output_format: dockerfile_finding
  } -->

- **Hadolint** — industry-standard Dockerfile linter, ~50 rules.
  <!-- engine: {
    name: hadolint,
    type: external,
    scanner: dockerfile,
    binary: hadolint,
    detect: [hadolint, --version],
    execute: [hadolint, --format, sarif, "{file_path}"],
    output_format: sarif,
    install_hint: "brew install hadolint",
    upstream: "https://github.com/hadolint/hadolint"
  } -->
```

The MCP server harvests markers at startup and exposes them two ways:

1. **Discovery** — `scan_<scanner>_engines` (e.g. `scan_dockerfile_engines`)
   lists the declared engines decorated with per-host availability
   (binary on PATH? resolved path? install hint when missing). How the
   choice is surfaced to a human is the host/agent's concern — the
   SKILL.md only declares what exists, never how to prompt.
2. **Execution** — the scan tool accepts an `engine` argument. For
   Dockerfiles, `scan_dockerfile(file_path, engine="hadolint")` runs the
   declared external engine and returns its parsed findings; an empty or
   `"internal"` engine runs the in-process builtin. Execution is gated:
   only registry-declared `external` engines run, only when their binary
   resolves on PATH, only on a `{file_path}` that passes the same
   `--allowed-roots` / sensitive-directory guard as the builtin scanners,
   always as an argv array (no shell), and under a 30s timeout. Engines
   whose `output_format` is `sarif` are parsed generically; other formats
   need a parser registered against the value before they can execute.

Marker payload reference:

| field           | required | meaning |
|-----------------|----------|---------|
| `name`          | yes      | kebab-case engine identifier; unique within a (skill, scanner) pair |
| `type`          | yes      | `builtin` (ships in-process with secure-code) or `external` (CLI on PATH) |
| `scanner`       | yes      | which scanner bucket — `dockerfile`, `github_actions`, `secrets`, `dependencies` |
| `description`   | no       | one-line summary shown in the discovery menu |
| `binary`        | required for `external` | command name to look up on PATH |
| `detect`        | no       | argv to verify the engine is functional; defaults to `[binary, --version]` for external |
| `execute`       | required for `external` | argv template; `{file_path}` is substituted at scan time |
| `output_format` | no       | `sarif` (generic parser), `dockerfile_finding` (builtin shape), or empty |
| `install_hint`  | no       | shell command shown when the binary is missing |
| `upstream`      | no       | URL of the upstream project (for reviewer audit) |

Bullets without an `<!-- engine: ... -->` marker are ignored — they
remain prose-only knowledge the AI consults at code-generation time.

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
