---
hide:
  - toc
---

# Changelog

Release history for SecureVibe. Every version is an Ed25519-signed release
(see [Signing](https://github.com/nguyencongnamit/skills-library/blob/main/SIGNING.md)); full
notes on [GitHub Releases](https://github.com/nguyencongnamit/skills-library/releases).

## Unreleased

- 🚀 Public launch: repository open-sourced and the docs site live on GitHub Pages.
- brand: completed the SecureVibe rename across docs, packaging, and surfaces (technical identifiers — binary, Go module, npm packages, signing key — kept stable).
- docs: premium site polish — logo + favicon, auto social/OG cards, an animated hero demo of the real `gate`, and self-hosted fonts.
- docs: **in-browser [Playground](playground.md)** — the real scanners compiled to WebAssembly; scan dependencies and secrets client-side with nothing uploaded.
- docs: AI-consumable `llms.txt` / `llms-full.txt` and a per-page "Open in Claude".

## v1.0.0 — 2026-06-20

- fix(scanner): reconcile dockerfile rule IDs with the skill + drift guard (+migration plan) (#43)

## v0.5.1 — 2026-06-17

- feat(gate): add --report-dir for an aggregated HTML + PDF report (#42)
- refactor(scan): unify the three directory walkers into tools.WalkScanFiles (#41)
- feat(gate): secret-scan ordinary files during a directory walk too (#40)
- fix(doc): change windsurf doc to devin
- feat(agent): change windsurf to devin
- feat(report): Support export html/pdf report for scanning
- feat(scan-dependencies): auto look for lockfile to scan in a folder
- feat(build): add a Makefile wrapping the build/test/validate
- feat(secret): allow to scan folder
- feat(gate): accept directory arguments (walk for config files) (#39)

## v0.5.0 — 2026-06-10

- Fix GitHub Pages deploy + refresh docs for v0.4.0 (#35)

## v0.4.0 — 2026-06-04


## v0.3.1 — 2026-06-03


## v0.3.0 — 2026-06-03

- feat: Windsurf scoped rules + secure-code-skill `init --tool` (#26)

## v0.2.0 — 2026-06-03


## v0.1.0 — 2026-06-03

- feat: external-tool discovery via skill frontmatter (follow-up to #14) (#15)
- refactor: remove the MCP scanner-engine layer
- feat(skills): add electron-security skill
- fix(check-dependency): stop appliance CVEs leaking onto code packages
- refactor(skills): deprecate infrastructure-security, salvage unique rules
- feat(secret-detection): import 9 patterns from secrets-patterns-db (Lane 1)
- feat(secret-detection): migrate secret rules to YAML checklist
- feat(mcp): engine markers in SKILL.md + scan_dockerfile_engines discovery tool
- feat(cli): expose the 8 skills-mcp tools as `skills-check` subcommands
- feat(cli): add `skills-check derive-checklists` + first knowledge bullets in container-security

