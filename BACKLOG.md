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
| 3 | **Backfill eval corpora** for the remaining high-value skills so `eval --all` covers more than 4 skills. Prioritize skills whose vulns a `gate` scanner can judge. | FREE | ≥8 skills ship `evals/cases.json` with positive lift. |

## P1 — this quarter (H1 Reach)

| # | Task | Role | Done when |
|---|---|---|---|
| 4 | **`eval --enforce` as a hard CI gate** — wire the prevention-lift floor into CI so a regression below `min_lift` fails the build (today preflight runs it informationally). | FREE | CI red on a skill whose lift drops below floor. |
| 5 | **SARIF output from `gate`** — emit SARIF that uploads to GitHub Code Scanning; honor `--fail-on-severity`. (See ROADMAP open-question #2: extend `gate`, don't fork a new `scan` cmd.) | FREE | SARIF artifact validates + appears in Code Scanning. |
| 6 | **Reusable GitHub Action** wrapping `gate → SARIF → upload`. | FREE | One-block `uses:` works in a sample repo. |
| 7 | **Homebrew tap + `go install`** + harden `landing/install.sh` into `curl \| sh`. | FREE | brew/go install works on macOS + Linux, < 30s to first run. |
| 8 | **`init` UX polish** across all IDE targets + MCP. | FREE | Each target verified end-to-end. |

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

- **Sequencing:** P0 unblocks everything (committed + consistent + measurable).
  The P1 H1 bundle (#4–#8) is the highest-leverage adoption work. PAID items
  (#16–#19) should not start before a design partner exists — building the
  control plane speculatively burns runway with no validation.
- **Guardrails apply to every item** — see ROADMAP "what we will NOT build."
  Nothing here adds a cloud LLM to the tool, an auto-fixer, or paywalls a fix.
