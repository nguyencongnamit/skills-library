# vibe-guard — Backlog

The prioritized, concrete task list behind [ROADMAP.md](./ROADMAP.md). The roadmap
sets horizons and *why*; this file is the ordered *what* — small enough that each
item is a PR or two. Tags: **`FREE`** (open framework), **`PAID`** (control plane),
**`REP`** (trust/credibility). Priority: **P0** (do next), **P1** (this quarter),
**P2** (next).

---

## P0 — do next

| # | Task | Role | Done when |
|---|---|---|---|
| 1 | **Commit the framework work** — VISION.md, ROADMAP/BACKLOG, eval harness (`eval.go`+tests), corpora + `evals.json`, AGENTS/CONTRIBUTING rewrites, `preflight.sh`, manifest. Split into logical commits. | — | Pushed on a branch; preflight green in CI. |
| 2 | **Branding unification** — sweep README, PROPOSAL, `mkdocs.yml`, `landing/`, docs for the ShieldNet360-umbrella hierarchy (vibe-guard = OSS member; vibe-guard Cloud = commercial). Keep technical IDs (`skills-check`, module path) stable. | REP | No surface contradicts VISION §1; brand name consistent in prose. |
| 3 | ✅ **DONE** — **Backfill eval corpora**. `eval --all` now covers **8 skills** (added crypto-misuse, ssrf-prevention, deserialization-security, cors-security via the `signature` oracle — 12 new cases). 25 cases total, 100pt lift; `evals.json` written + manifest re-checksummed. | FREE | ≥8 skills ship `evals/cases.json` with positive lift. |

## P1 — this quarter (H1 Reach)

| # | Task | Role | Done when |
|---|---|---|---|
| 4 | ✅ **DONE** — **`eval --enforce` as a hard CI gate**. `skills-check eval --all --enforce` now runs in `validate.yml` *and* `preflight.sh` (no more `\|\| true`), so a skill below its `min_lift` reds both CI and the local gate. | FREE | CI red on a skill whose lift drops below floor. |
| 5 | ✅ **DONE** — **SARIF output from `gate`** — emits schema-valid SARIF 2.1.0 *before* the fail-exit; `internal/tools/sarif.go`. (Extended `gate`, did not fork a `scan` cmd.) Branch `build/sarif-from-gate`. | FREE | SARIF artifact validates + appears in Code Scanning. |
| 6 | ✅ **DONE** — **Reusable GitHub Action** wrapping `gate → SARIF → upload`. `action.yml` gained `sarif-file` + `upload-sarif` inputs; uploads via `codeql-action/upload-sarif` even on a failing gate, then fails the PR. Sample `examples/github-code-scanning.yml` + `docs/code-scanning.md`. `main.go` now exits **1=findings / 2=error** so CI can tell them apart. The action passes inputs via `env:` (not inline `${{ }}`) to foreclose shell injection. | FREE | One-block `uses:` works in a sample repo. |
| 7 | ◐ **`go install` verified; Homebrew stamping wired.** `go install …/cmd/skills-check@latest` builds (module path correct); `release.yml` now stamps the formula's version + per-arch sha256 and publishes `skills-check.rb` as a release asset (was a hollow claim before). Remaining: push the asset to the tap repo (needs tap repo + token), and the `curl \| sh` tool-installer. | FREE | brew/go install works on macOS + Linux, < 30s to first run. |
| 8 | ✅ **DONE** — **`init` UX polish**. All 9 targets (claude/cursor/copilot/codex/agents/windsurf/devin/cline/universal) verified end-to-end: each writes its correct config file, `rc=0`, and re-runs are byte-identical (idempotent). | FREE | Each target verified end-to-end. |

## P2 — next (H2 Moat / H3 Trust groundwork)

| # | Task | Role | Done when |
|---|---|---|---|
| 9 | **`skills-check eval gen`** — live-model baseline/with_skill generation (opt-in, offline-respecting) so lift becomes measured, not authored. | FREE→REP | Reproducible lift from a live model on ≥1 skill. |
| 10 | **Freshness pipeline** — automate OSV/GHSA/Socket/Phylum ingestion → signed release; track advisory→ship latency. | FREE | Latency metric published. |
| 11 | **`skills-check status`** — per-source staleness ("knowledge is N days old"). | FREE | Command reports per-source freshness. |
| 12 | **`evidence` → signed attestation** — extend into a signed, timestamped artifact mapped to SOC2/HIPAA/PCI/FedRAMP, using `evals.json` as proof substrate. | FREE→PAID | Verifiable signed artifact an auditor accepts. |
| 13 | **Leaderboard publish** — turn `eval` output (ideally live-model from #9) into a published, reproducible AI-coding-security leaderboard. | REP | Page published + externally citable. |
| 14 | **Standards crosswalk** — map `SKILL.md` + `evals.json` to agentskills.io / Codex Skills / Cisco taxonomy; publish as an open spec. | REP | Crosswalk published; ≥1 external adopter. |
| 15 | **Gallery governance doc** — key-rotation + root-of-trust policy *before* the signed community gallery opens. | REP | Policy written + linked from VISION §8. |

## PAID (control plane — H2, gated on a design partner)

| # | Task | Done when |
|---|---|---|
| 16 | **Central policy & fleet management** (vibe-guard Cloud MVP). | 1+ org governed centrally. |
| 17 | **Private rule distribution** via a private trust root (VerifyAny); air-gap option. | Private signed bundle delivered + verified. |
| 18 | **Premium freshness SLA.** | Contracted SLA met for a design partner. |
| 19 | **Governance dashboards** (self-hostable / opt-in, no-telemetry-safe). | Design partner uses it for audit reporting. |

---

## Notes

- **Strategy steer (2026-06-19): grow both axes + stand up the engine.** Push **horizontal breadth** (more ecosystems/IaC/frameworks — items #10, #14, and the Detection-breadth roadmap track) and **vertical depth** (reachability + verified reproduction — item #9 and the Detection-depth track) *together*, while building the **contribution loop** (item #16's free precursor: `contribute --local`/`--submit` → candidate queue → signed canon → delta `update`; the LEARN engine, today UPCOMING). Depth stays scoped to the verified signed DB — never rebuild generic static analysis. See CLAUDE.md "Coverage strategy" for the full model. The contribution-loop's *free* personal+candidate half is OSS; only fleet/private-registry/SLA around it is PAID.
- **Sequencing:** P0 unblocks everything (committed + consistent + measurable).
  The P1 H1 bundle (#4–#8) is the highest-leverage adoption work. PAID items
  (#16–#19) should not start before a design partner exists — building the
  control plane speculatively burns runway with no validation.
- **Guardrails apply to every item** — see ROADMAP "what we will NOT build."
  Nothing here adds a cloud LLM to the tool, an auto-fixer, or paywalls a fix.
