# secure-code

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Skills](https://img.shields.io/badge/skills-28-blue)](#skill-catalogue)
[![Vulnerabilities](https://img.shields.io/badge/CVE%20patterns-58-orange)](./vulnerabilities/cve/code-relevant/cve_patterns.json)
[![Ecosystems](https://img.shields.io/badge/supply--chain%20ecosystems-9-purple)](./vulnerabilities/supply-chain/malicious-packages)
[![DLP patterns](https://img.shields.io/badge/DLP%20patterns-74-red)](./skills/secret-detection/rules/dlp_patterns.json)
[![Platforms](https://img.shields.io/badge/platforms-win%20%7C%20mac%20%7C%20linux-green)](#platform-support)

**secure-code** is a structured, machine-readable library of security skills and
supply-chain vulnerability intelligence designed to be embedded directly into AI
coding assistants — Claude Code, Cursor, GitHub Copilot, Codex, Windsurf,
Cline / OpenCode, Antigravity, and Devin. It ships bundled rules offline and
supports incremental, Ed25519-signed remote updates. See
[SIGNING.md](./SIGNING.md) for the signing model.

Maintained by **[ShieldNet360](https://www.shieldnet360.com)** and released under
the [MIT license](./LICENSE) — free to fork, embed, and ship in commercial products.

---

## Table of contents

- [Why secure-code](#why-secure-code)
- [What's inside](#whats-inside)
- [Quick start — embed in your IDE](#quick-start--embed-in-your-ide)
- [CLI install and routine updates](#cli-install-and-routine-updates)
- [Vulnerability database — repo sample vs full upstream](#vulnerability-database--repo-sample-vs-full-upstream)
- [Token efficiency](#token-efficiency)
- [Project layout](#project-layout)
- [Documentation](#documentation)
- [CLI package layout](#cli-package-layout)
- [MCP server](#mcp-server)
- [Building and running tests](#building-and-running-tests)
- [Signing model](#signing-model)
- [Platform support](#platform-support)
- [Skill catalogue](#skill-catalogue)
- [Enterprise profiles](#enterprise-profiles)
- [Compliance evidence](#compliance-evidence)
- [Private repositories](#private-repositories)
- [SDKs](#sdks)
- [Localization](#localization)
- [Contributing](#contributing)
- [License and attribution](#license-and-attribution)

---

## Why secure-code

- **AI coding assistants don't ship with current security knowledge.** Training
  data is months or years stale: a package compromised yesterday is happily
  imported by the model today.
- **Security review is an afterthought** in the "vibe coding" workflow. Hardcoded
  secrets, vulnerable dependencies, typosquat imports, and unsafe deserialization
  all land in production routinely.
- **No standardized way to inject security context** into AI tools today — every
  team writes its own `CLAUDE.md`, `.cursorrules`, or `copilot-instructions.md`,
  and most contain only style rules.
- **Existing answers are proprietary, expensive, or infra-heavy.** secure-code is
  MIT-licensed, runs entirely offline, and ships as plain files in a Git repo plus
  a single static Go binary.

secure-code closes the loop by shipping security knowledge *at the point of code
generation*, before the diff ever touches your repo.

## What's inside

| Area | Path | Description |
|------|------|-------------|
| **Skills** | [`skills/`](./skills) | 28 self-contained `SKILL.md` manifests with rules, patterns, and checklists. Each skill is a security capability the AI tool consults at generation time. |
| **Vulnerability database** | [`vulnerabilities/`](./vulnerabilities) | Curated supply-chain corpus (malicious packages, typosquats, CVE detection patterns, dependency-confusion rules) plus an offline OSV cache. Delta-updatable. See the [Vulnerability database](#vulnerability-database--repo-sample-vs-full-upstream) section below for ecosystem coverage and counts. |
| **Detection rules** | [`rules/`](./rules) | Sigma-format detection rules for AWS, GCP, Azure, K8s, Linux, macOS, Windows, O365, Google Workspace, Salesforce, and Slack — designed to complement the prevention-time rules in `skills/`. |
| **Compliance maps** | [`compliance/`](./compliance) | OWASP Top 10, CWE Top 25, SANS Top 25 framework mappings plus developer-facing compliance coverage maps (SOC 2, HIPAA, PCI-DSS, FedRAMP). |
| **Dictionaries** | [`dictionaries/`](./dictionaries) | Security term definitions, CWE catalogue, MITRE ATT&CK technique references — context the AI needs to reason about security. |
| **Pre-compiled IDE files** | [`dist/`](./dist) | Ready-to-drop-in `CLAUDE.md`, `.cursorrules`, `copilot-instructions.md`, `AGENTS.md`, `.windsurfrules`, `devin.md`, `.clinerules`, and a universal `SECURITY-SKILLS.md`. |
| **CLI** | [`cmd/skills-check/`](./cmd/skills-check) | Single static Go binary for installing, updating, and validating skills across every supported IDE. |
| **MCP server** | [`cmd/skills-mcp/`](./cmd/skills-mcp) | JSON-RPC 2.0 Model Context Protocol server for on-demand skill / vulnerability lookups. |

## Quick start — embed in your IDE

The fastest path is to copy the pre-compiled file for your tool from
[`dist/`](./dist) into your project root. Three patterns are available for every
tool:

1. **Copy once** — fastest, no live updates.
2. **Symlink** — auto-updates whenever you run `skills-check update` or `git pull`.
3. **CLI-generated** — `skills-check init` writes a project-specific file with only
   the skills you care about, at the token budget you specify.

### Claude Code (`CLAUDE.md`)

```bash
# Option 1: Copy the universal skill loader
cp secure-code/dist/CLAUDE.md /your-project/CLAUDE.md

# Option 2: Symlink for auto-updates
ln -s /path/to/secure-code/dist/CLAUDE.md /your-project/CLAUDE.md

# Option 3: Generate a project-specific CLAUDE.md
skills-check init --tool claude --skills secret-detection,dependency-audit,secure-code-review
```

### Cursor (`.cursorrules`)

```bash
cp secure-code/dist/.cursorrules /your-project/.cursorrules
# or
skills-check init --tool cursor --skills secret-detection,dependency-audit
```

### GitHub Copilot (`.github/copilot-instructions.md`)

```bash
cp secure-code/dist/copilot-instructions.md /your-project/.github/copilot-instructions.md
```

### Codex / OpenAI (`AGENTS.md`)

```bash
cp secure-code/dist/AGENTS.md /your-project/AGENTS.md
```

### Windsurf (`.windsurfrules`)

```bash
cp secure-code/dist/.windsurfrules /your-project/.windsurfrules
```

### Devin (`devin.md`)

```bash
cp secure-code/dist/devin.md /your-project/devin.md
```

### Cline / OpenCode (`.clinerules`)

```bash
cp secure-code/dist/.clinerules /your-project/.clinerules
```

### Universal (any tool that reads project-root markdown)

```bash
cp secure-code/dist/SECURITY-SKILLS.md /your-project/SECURITY-SKILLS.md
```

## CLI install and routine updates

Vulnerability data and detection patterns change weekly. The CLI keeps your
local copy current with incremental, signature-verified remote updates.

### Install (all platforms)

```bash
# From source (requires Go 1.22+)
go install github.com/kennguy3n/skills-library/cmd/skills-check@latest

# macOS via Homebrew
brew install kennguy3n/tap/skills-check

# Windows via winget
winget install kennguy3n.skills-check

# Linux via .deb / .rpm — see docs/install-linux.md
```

### Pull latest rules

```bash
# Pull latest rules, vulnerabilities, and skills
skills-check update

# Pull and regenerate IDE files in one step
skills-check update --regenerate

# Check for updates without applying
skills-check update --check-only

# Revert to the previous version
skills-check update --rollback

# Use a custom source (HTTP URL, local directory, or tarball)
skills-check update --source https://cdn.example.com/secure-code/
skills-check update --source /mnt/airgap/secure-code-v2.tar.gz
```

### Scheduled updates

| Platform | Mechanism | Example |
|----------|-----------|---------|
| macOS | `launchd` LaunchAgent | `skills-check scheduler install --interval 6h` |
| Linux | `systemd` user timer | `skills-check scheduler install --interval 6h` |
| Windows | Task Scheduler | `skills-check scheduler install --interval 6h` |

The scheduled task issues anonymous `GET` requests for public release artifacts and
writes them to disk. **No device identifier, hostname, IP, or user information is
transmitted.** The update server cannot distinguish a fresh install from its
hundredth recurring check.

### Manual / Git-based

```bash
cd /path/to/secure-code
git pull origin main
skills-check regenerate    # rebuild dist/ files from the latest skills
```

### Vulnerability database — repo sample vs full upstream

The committed `vulnerabilities/osv/` directory is a **small latest-first
sample** of the upstream OSV archives at
`osv-vulnerabilities.storage.googleapis.com`, generated by
`scripts/ingest-osv.py`. It exists as an offline fallback so a fresh
`git clone` can scan without network access. Sample size is controlled
by `--per-ecosystem` (default 100); per-ecosystem advisory counts are
published in [DATA_QUALITY.md](./DATA_QUALITY.md), regenerated on every
ingest.

The sample is **not a complete mirror**. Upstream npm alone has ~80,000
advisories. To get full coverage at scan time, populate the user-local cache.
Two sources are supported:

```bash
# Option 1: pull the full upstream catalogue from osv.dev directly.
# ~250 MB, ~5–10 minutes on a typical connection.
skills-check fetch-vulns

# Option 2: pull the pre-built osv-cache.tar.gz from the latest GitHub
# release. Single HTTPS download, no per-ecosystem fan-out; recommended
# for production / air-gapped deployments and CI that cannot hit
# osv.dev directly.
skills-check fetch-vulns --from-release

# Verify the cache is present and fresh (exit 1 if missing or >7d old;
# suitable for cron / CI)
skills-check fetch-vulns --check

# Pull only specific ecosystems (e.g. JS/Python only). Applies to
# osv.dev mode; the release-asset tarball is a single bundle.
skills-check fetch-vulns --only npm,pypi
```

The cache lives at `$SKILLS_MCP_CACHE` (falling back to
`$XDG_CACHE_HOME/skills-mcp/vulns` and then `~/.cache/skills-mcp/vulns`).
`skills-mcp` and `skills-check validate` prefer the user cache and only
fall back to the repo-bundled sample when the cache is missing or
incomplete — so populating it is purely additive and does not require
changes to skill content. Re-run weekly (or wire up the
`skills-check scheduler` to do it for you) to stay current with osv.dev.

## Token efficiency

AI coding tools have finite context windows, and every byte of instructions you
inject costs either tokens (for API tools) or working memory (for IDE tools).
secure-code is designed around three principles:

- **Skills are loaded on demand, not all at once.** The CLI lets you pick exactly
  which skills your project needs.
- **Every `SKILL.md` declares a `token_budget` block** with three pre-counted
  variants: `minimal`, `compact`, and `full`.
- **The `dist/` files are pre-compiled to a budget tier.** Generated output is
  checked at build time and the build fails if a variant exceeds its budget.

| Tier | Approx. tokens | Contents | Recommended for |
|------|----------------|----------|-----------------|
| `minimal` | < 500 | ALWAYS / NEVER bullet rules only | Expensive API-based tools, very small context budgets |
| `compact` | < 2000 | Full rules + known false positives + references; no examples or rationale | Default for most IDE integrations |
| `full` | < 5000 | Rules + examples + rationale + related CWEs | Local models with large context, Devin-style agents |

Select your tier with `skills-check init --budget compact`. Compact is the default.

## Project layout

```
secure-code/
├── README.md  PROPOSAL.md  ARCHITECTURE.md  SIGNING.md  LICENSE
├── skills/                              # 28 skill definitions (the core product)
│   ├── secret-detection/                #   74 DLP patterns + exclusions + test corpus
│   ├── dependency-audit/                #   known-malicious package corpus
│   ├── supply-chain-security/           #   typosquat + dependency-confusion rules
│   ├── secure-code-review/              #   OWASP Top 10 checklists + injection patterns
│   ├── infrastructure-security/         #   K8s / Docker / Terraform hardening
│   ├── api-security/                    #   auth + input validation patterns
│   ├── compliance-awareness/            #   CWE + OWASP framework mappings
│   ├── iac-security/                    #   Terraform / CloudFormation / Pulumi
│   ├── container-security/              #   Dockerfile / K8s / Helm
│   ├── frontend-security/               #   XSS, CSP, CORS, SRI, trusted types
│   ├── database-security/               #   SQL injection, ORM safety, RLS
│   ├── crypto-misuse/                   #   weak ciphers, bad RNG, KDF
│   ├── auth-security/                   #   JWT, OAuth, sessions, MFA
│   ├── iam-best-practices/              #   least-privilege roles + policies
│   ├── serverless-security/             #   Lambda / Cloud Functions IAM
│   ├── mobile-security/                 #   Android exported components, iOS ATS
│   ├── ml-security/                     #   prompt injection, model poisoning
│   ├── protocol-security/               #   TLS 1.2+, mTLS, HSTS, gRPC
│   ├── error-handling-security/         #   information disclosure
│   ├── logging-security/                #   secrets / PII in logs, log injection
│   ├── cors-security/                   #   origin allowlists, preflight
│   ├── cicd-security/                   #   GitHub Actions / GitLab CI hardening
│   ├── ssrf-prevention/                 #   cloud-metadata + DNS-rebinding sinks
│   ├── deserialization-security/        #   unsafe deserializers + safe alternatives
│   ├── graphql-security/                #   depth / cost limits, introspection
│   ├── file-upload-security/            #   MIME + magic-byte validation
│   ├── websocket-security/              #   origin check, auth, rate limits
│   └── saas-security/                   #   GWS / Atlassian / Slack / Salesforce / 14 services
├── vulnerabilities/                     # Supply-chain vulnerability database
│   ├── manifest.json                    #   versioned, checksummed, delta-updatable
│   ├── supply-chain/
│   │   ├── malicious-packages/          #   ~1,900 entries across 9 ecosystems
│   │   │                                #   (npm/pypi/crates/go/rubygems/maven/nuget/
│   │   │                                #   github-actions/docker)
│   │   ├── typosquat-db/                #   ~270 known typosquats (curated + derived)
│   │   └── dependency-confusion/        #   internal-namespace patterns
│   ├── osv/                             #   per-ecosystem OSV.dev cache —
│   │                                    #   stride-sampled subset across 10
│   │                                    #   ecosystems (composer, crates, go,
│   │                                    #   maven, npm, nuget, pub, pypi,
│   │                                    #   rubygems, swift) for offline
│   │                                    #   lookups, not comprehensive
│   │                                    #   vulnerability intelligence;
│   │                                    #   refresh via scripts/ingest-osv.py
│   │                                    #   (see DATA_QUALITY.md for counts)
│   └── cve/
│       └── code-relevant/               #   58 CVE → code-pattern mappings (2015-2025)
├── rules/                               # Sigma detection rules
│   ├── cloud/aws,gcp,azure/             #   CloudTrail / Cloud Audit Logs / Azure AD
│   ├── endpoint/linux,macos,windows/    #   auditd / UnifiedLog / Sysmon
│   ├── container/k8s/                   #   API audit / privileged pod / exec
│   └── saas/o365,gws,salesforce,slack/  #   Mailbox forwarding / admin roles / GWS delegation / SF exports / Slack app scopes
├── dictionaries/                        # Reference data for AI context
│   ├── security_terms.yaml
│   ├── cwe_top25.yaml
│   ├── owasp_top10_2025.yaml
│   └── attack_techniques.yaml           #   MITRE ATT&CK subset
├── dist/                                # Pre-compiled IDE-specific files
│   ├── CLAUDE.md   .cursorrules   copilot-instructions.md   AGENTS.md
│   ├── .windsurfrules   devin.md   .clinerules
│   └── SECURITY-SKILLS.md               #   universal format
├── cmd/
│   ├── skills-check/                    # CLI (Go, single binary)
│   └── skills-mcp/                      # MCP server over JSON-RPC stdio
├── packaging/                           # OS installers / package manager manifests
│   ├── macos/ windows/ linux/           #   pkgbuild + MSI + nfpm .deb/.rpm
│   ├── homebrew/ winget/ scoop/         #   tap formula + winget + scoop
│   ├── apt-yum/                         #   GitHub Pages-hosted APT / YUM repos
│   └── codesign/                        #   notarization + Authenticode docs
├── docs/                                # Install + admin docs + locale audit
│   ├── install-{macos,linux,windows}.md
│   ├── admin-team-rollout.md
│   ├── air-gapped-install.md
│   └── LOCALE_AUDIT.md
├── profiles/                            # Enterprise --profile mappings
│   ├── financial-services.yaml
│   ├── healthcare.yaml
│   └── government.yaml
├── compliance/                          # Framework control mappings
│   ├── soc2_mapping.yaml
│   ├── hipaa_mapping.yaml
│   └── pci_dss_mapping.yaml
├── sdk/                                 # Programmatic access
│   ├── go/                              #   Re-exports of internal/skill
│   ├── python/                          #   skillslib Python package
│   └── typescript/                      #   skillslib npm package
├── locales/                             # Translated SKILL.md (informational)
│   ├── es/ fr/ de/ ar/ zh-Hans/ pt-BR/  #   28 SKILL.md per locale; the 3 flagship
│   │                                    #   skills (secret-detection, supply-chain,
│   │                                    #   infrastructure) under es/ fr/ de/ are
│   │                                    #   translated; the remaining 25 + every
│   │                                    #   ar/ zh-Hans/ pt-BR/ cell is a stub with
│   │                                    #   a TRANSLATION PENDING banner over the
│   │                                    #   English original (regenerate via
│   │                                    #   scripts/generate-locale-stubs.py)
│   └── README.md                        #   translation policy + locale audit reference
├── manifest.json                        # Root manifest for signed remote updates
└── .github/workflows/
    ├── validate.yml                     # CI: validate all skills, rules, manifests
    └── release.yml                      # CI: build CLI, tag release, publish manifests
```

## Documentation

- [PROPOSAL.md](./PROPOSAL.md) — problem statement, design principles, target
  audience, scope boundaries, and the canonical `SKILL.md` format specification.
- [ARCHITECTURE.md](./ARCHITECTURE.md) — system diagrams, compiler architecture,
  update protocol, CLI layout, scheduler implementation, and signing model.
- [SIGNING.md](./SIGNING.md) — Ed25519 release signing procedure and key
  management policy.
- [docs/](./docs/) — install guides (macOS / Linux / Windows / air-gapped), the
  team rollout admin guide, and a locale audit covering top-10 languages + GCC
  + Southeast Asia + Germany.
- [packaging/codesign/README.md](./packaging/codesign/README.md) — macOS
  notarization and Windows Authenticode signing in the release workflow.

## CLI package layout

```
cmd/skills-check/
├── main.go                    # Cobra root command
├── cmd/                       # init / update / validate / list / regenerate
│                              # / version / manifest / scheduler / self-update
│                              # / configure / evidence / new / test
└── internal/
    ├── token/                 # tiktoken-go counter + 1.3x Claude multiplier
    ├── compiler/              # 8 IDE-specific formatters + core compile loop
    ├── manifest/              # manifest.json: load, checksum, Ed25519 sign /
    │                          # verify, delta, atomic write
    ├── updater/               # Remote update: HTTP / dir / tarball sources,
    │                          # verify-before-replace, rollback
    └── scheduler/             # Cross-platform scheduled updates
                               # (launchd / systemd / Task Scheduler)

cmd/skills-mcp/                # Model Context Protocol server (JSON-RPC 2.0 over stdio)
├── main.go
└── internal/
    ├── mcp/                   # JSON-RPC dispatch + tool definitions
    └── tools/                 # lookup_vulnerability, check_secret_pattern,
                               # get_skill, search_skills

internal/skill/                # SKILL.md parser (shared by skills-check and skills-mcp)
```

## MCP server

`skills-mcp` exposes secure-code to AI tools that speak the
[Model Context Protocol](https://modelcontextprotocol.io). It runs as a
short-lived child process spoken to over stdio:

```bash
go build -o skills-mcp ./cmd/skills-mcp
skills-mcp --path /path/to/secure-code
```

The server registers fifteen tools on `tools/list`:

- `lookup_vulnerability(package, ecosystem?, version?)` — search the supply-chain
  malicious-packages database, the typosquat DB, AND the local OSV cache
  (vulnerabilities/osv/) for known CVE / GHSA / OSV-ID advisories.
- `check_secret_pattern(text)` — run the secret-detection regex rules against
  `text`, returning matches with severity and whether they are known false
  positives.
- `get_skill(skill_id, budget?)` — return the requested skill at the requested
  tier (`minimal` / `compact` / `full`).
- `search_skills(query)` — substring match across skill metadata.
- `scan_secrets(text | file_path, format?)` — DLP scan of inline text or a path
  under the configured allowed roots; supports the `sarif` output format.
- `check_dependency(package, version?, ecosystem, format?)` — check a dependency
  against the malicious-packages corpus, the typosquat DB, the CVE-pattern list,
  and the local OSV cache; ecosystem-native semver matching (node-semver, PEP 440,
  Go module pseudo-versions) is used when both sides parse. Optional SARIF output.
- `check_typosquat(package, ecosystem?)` — flag candidate typosquats from the
  curated typosquat database.
- `map_compliance_control(skill_id | query, framework?)` — map an installed
  skill (or free-text query) to controls in SOC 2, HIPAA, or PCI-DSS.
- `get_sigma_rule(rule_id | query, category?)` — fetch a Sigma detection rule
  from `rules/` by ID, free-text query, or category.
- `version_status()` — report data version, manifest signature state, and
  whether the loaded library is the canonical signed release.
- `scan_dependencies(file_path, format?)` — parse a project lockfile
  (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`,
  `Pipfile.lock`, `poetry.lock`, `go.sum`, `Cargo.lock`, `pom.xml`,
  `gradle.lockfile` / `build.gradle.lockfile`, `packages.lock.json`,
  `*.csproj` / `*.fsproj` / `*.vbproj`, and `Gemfile.lock`) and report
  every dependency that matches the malicious-packages, typosquat, or
  CVE databases. Parsers exist for all nine vulnerability-database
  ecosystems (npm, PyPI, crates, Go, RubyGems, Maven, NuGet — plus
  GitHub Actions and Docker, which are surfaced via
  `scan_github_actions` and `scan_dockerfile` respectively). Supports
  the `sarif` output format.
- `scan_github_actions(file_path, format?)` — run the
  `skills/cicd-security/checklists/github_actions_hardening.yaml` rules
  against a workflow file: unpinned actions, missing `permissions:` defaults,
  `pull_request_target` checkout, untrusted-input script injection,
  `curl | sh`, and stored cloud credentials. Supports the `sarif` format.
- `scan_dockerfile(file_path, format?)` — hardening pass over a
  Dockerfile: untagged / `:latest` base images, `USER root`, secrets in
  `ENV`/`ARG`, `ADD https://…`, `curl | sh`, and `apt-get install`
  without version pins. Supports the `sarif` format.
- `explain_finding(query)` — map a CWE / CVE ID or free-text finding
  description to the relevant skills and CVE-pattern entries, so a SAST/SCA
  finding from another scanner can be paired with remediation guidance.
- `policy_check(file_path, severity_floor?)` — dispatch the appropriate
  scanner for `file_path` and return a CI-friendly `pass` flag plus
  `exit_code` (0 on pass, 1 on fail). Findings at or above
  `severity_floor` (default `high`) fail the check; counts are returned
  per severity so a wrapper can produce a one-line summary.

The library root is resolved from `--path`, then `$SKILLS_LIBRARY_PATH`, then the
directory containing the binary.

## Building and running tests

```bash
go build -trimpath -ldflags "-s -w" -o skills-check ./cmd/skills-check
go build -trimpath -ldflags "-s -w" -o skills-mcp   ./cmd/skills-mcp
go test ./...                                       # covers CLI + MCP server
./skills-check validate                             # check SKILL.md frontmatter + budgets
./skills-check list                                 # enumerate skills with token counts
./skills-check regenerate                           # rebuild dist/ files
./skills-check manifest compute --path . --write    # recompute SHA-256 checksums
./skills-check manifest verify  --path . --checksums-only  # verify committed checksums
```

The same commands run in CI on every PR. `skills-check validate` enforces the
per-skill token budgets declared in each `SKILL.md` frontmatter; `skills-check
regenerate` rebuilds every file in `dist/` and CI fails if the committed copy
differs from the regenerated output.

## Signing model

Release manifests are signed with **Ed25519**. The public key is embedded in the
CLI binary at build time via `-ldflags -X`. See [SIGNING.md](./SIGNING.md) for the
out-of-band YubiKey-backed signing procedure and key management policy.

## Platform support

| OS | Architectures | CLI install | Scheduled updates |
|----|---------------|-------------|-------------------|
| macOS | `amd64`, `arm64` | `brew install kennguy3n/tap/skills-check`, `go install` | `launchd` |
| Linux | `amd64`, `arm64` | `.deb`, `.rpm`, `go install`, `apt`, `yum` | `systemd` user timer |
| Windows | `amd64` | MSI, `winget`, `scoop`, `go install` | Task Scheduler |

## Skill catalogue

All 28 skills are language-agnostic unless otherwise noted.

| Skill | Category | Severity | Languages |
|-------|----------|----------|-----------|
| `secret-detection` | prevention | critical | * |
| `dependency-audit` | supply-chain | high | * |
| `secure-code-review` | prevention | high | * |
| `supply-chain-security` | supply-chain | critical | * |
| `infrastructure-security` | hardening | high | yaml, hcl, dockerfile |
| `api-security` | prevention | high | * |
| `compliance-awareness` | compliance | medium | * |
| `iac-security` | hardening | high | hcl, yaml, json |
| `container-security` | hardening | high | dockerfile, yaml |
| `frontend-security` | prevention | high | javascript, typescript, html |
| `database-security` | prevention | high | sql, javascript, typescript, python, java, go |
| `crypto-misuse` | prevention | high | * |
| `auth-security` | prevention | critical | * |
| `iam-best-practices` | hardening | high | * |
| `serverless-security` | hardening | high | python, javascript, typescript, java, yaml |
| `mobile-security` | hardening | high | java, kotlin, swift, objective-c |
| `ml-security` | prevention | high | python, jupyter |
| `protocol-security` | hardening | high | * |
| `error-handling-security` | prevention | medium | * |
| `logging-security` | prevention | high | * |
| `cors-security` | hardening | medium | javascript, typescript, python, go, java |
| `cicd-security` | prevention | critical | yaml, shell, * |
| `ssrf-prevention` | prevention | critical | * |
| `deserialization-security` | prevention | critical | java, python, csharp, php, ruby, javascript, typescript |
| `graphql-security` | prevention | high | javascript, typescript, python, go, java, kotlin, csharp, ruby |
| `file-upload-security` | prevention | high | * |
| `websocket-security` | prevention | high | javascript, typescript, python, go, java, csharp, ruby, elixir |
| `saas-security` | prevention | critical | * |

## Enterprise profiles

`skills-check init` and `skills-check regenerate` accept `--profile <name>` to
select a curated, compliance-aligned subset of skills:

| Profile | Frameworks | Use case |
|---------|-----------|----------|
| `financial-services` | PCI-DSS v4.0, SOC 2 | Banks, fintech, payment processors |
| `healthcare` | HIPAA Security Rule | Hospitals, telehealth, claims processing |
| `government` | FedRAMP, NIST SP 800-53 Rev. 5 | Public-sector workloads |

Profile definitions live under [`profiles/`](./profiles).

## Compliance evidence

```bash
skills-check evidence --framework SOC2    --format markdown --out evidence.md
skills-check evidence --framework HIPAA   --format json
skills-check evidence --framework PCI-DSS --format markdown
```

The command maps controls to installed skills using YAML files in
[`compliance/`](./compliance) and emits a timestamped compliance coverage report
mapping installed skills to framework controls. The report is a developer-facing
coverage map, not a substitute for a real audit — which still requires runtime
evidence, change-management records, access reviews, and so on.

## Private repositories

For air-gapped or internal deployments, point the CLI at your own signed bundle:

```bash
skills-check configure \
  --source https://skills.internal.example.com \
  --bearer-token-env SKILLS_TOKEN \
  --trusted-key /etc/skills/orgkey.pem \
  --profile financial-services
```

This writes `.skills-check.yaml` next to the repo. The updater accepts multiple
trusted Ed25519 keys (`VerifyAny`) and authenticated HTTPS pulls.

## SDKs

Minimal Go, Python, and TypeScript SDKs live under [`sdk/`](./sdk).

```go
import skillslib "github.com/kennguy3n/skills-library/sdk/go"

s, _ := skillslib.LoadSkill("skills/secret-detection/SKILL.md")
fmt.Println(skillslib.Extract(s, skillslib.TierCompact))
```

```python
import skillslib
s = skillslib.load_skill("skills/secret-detection/SKILL.md")
print(skillslib.extract(s, "compact"))
```

```ts
import { loadSkill, extract } from "@skills-library/skillslib";
const s = loadSkill("skills/secret-detection/SKILL.md");
console.log(extract(s, "compact"));
```

## Localization

Translated copies of the SKILL.md files live under [`locales/`](./locales).
Tier 1 coverage today: **6 locales** (`es`, `fr`, `de`, `ar`, `zh-Hans`,
`pt-BR`) × **28 skills**, of which 9 cells are real translations (the three
flagship skills `secret-detection`, `supply-chain-security`,
`infrastructure-security` under `es/`, `fr/`, `de/`) and the remaining 159
cells are stubs that prepend a `> ⚠️ TRANSLATION PENDING` banner over the
untranslated English body. Run [`scripts/generate-locale-stubs.py`](./scripts/generate-locale-stubs.py)
to regenerate the stubs after adding a skill or a locale.

For the secret-detection scanner there is also a multilingual hotword
sidecar at [`skills/secret-detection/rules/dlp_patterns.locales.json`](./skills/secret-detection/rules/dlp_patterns.locales.json)
that the loader merges into the live hotword set at compile time so the
scoring path can match locale-language variable names (e.g. `contraseña`,
`passwort`) in non-English codebases.

Translations remain informational — the canonical English file under
`skills/<id>/SKILL.md` is the source of truth for the validator and the IDE
config generators. A full audit of language coverage gaps for top-10 world
languages, the GCC region, Southeast Asia, and Germany is in
[`docs/LOCALE_AUDIT.md`](./docs/LOCALE_AUDIT.md).

## Contributing

We welcome contributions from the community. Please see
[CONTRIBUTING.md](./CONTRIBUTING.md) for the full guide and
[AGENTS.md](./AGENTS.md) for the project's AI-assisted-contribution
policy (TL;DR: AI tools may be used to assist, but fully or
predominantly AI-generated pull requests are not accepted). In brief:

- **Skill contributions** — add a new directory under `skills/` with a `SKILL.md`
  and associated rules. Use [`skills/secret-detection/`](./skills/secret-detection)
  as the reference implementation.
- **Vulnerability data** — add entries to `vulnerabilities/supply-chain/` JSON
  files via PR. Every entry must include at least one external reference (CVE
  ID, advisory URL, or reputable disclosure write-up).
- **Detection rules** — add Sigma YAML files to `rules/`. Follow the existing
  taxonomy (`cloud/`, `endpoint/`, `container/`, `saas/`).
- **False positive fixes** — update the relevant `dlp_exclusions.json` (or a
  skill-specific exclusion file). False-positive PRs are merged quickly.
- **IDE integration** — improve the templates in the `dist/` compiler for
  specific tools.
- Run `skills-check validate` and `go test ./...` before submitting a PR. CI
  runs the same checks and rejects PRs that fail.

To report a security issue privately, see [SECURITY.md](./SECURITY.md).

## License and attribution

secure-code is released under the [MIT License](./LICENSE).

> Copyright (c) 2024-2026 **ShieldNet360** — https://www.shieldnet360.com

The project is maintained by [ShieldNet360](https://www.shieldnet360.com) and is
free to fork, embed, and ship in commercial products. We ask only that the MIT
copyright notice and the attribution above are preserved in derivative works.
