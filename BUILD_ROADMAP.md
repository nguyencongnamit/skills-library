# vibe-guard — Build Roadmap

> The presentation view of the near-term build. Companion to
> [BUILD_PLAN.md](./BUILD_PLAN.md) (the engineering how — file touch-points and
> acceptance criteria), [ROADMAP.md](./ROADMAP.md) (horizons / why), and
> [BACKLOG.md](./BACKLOG.md) (ordered what). Current as of 2026-06-10.
>
> Focus: the **H1 "Reach" bundle** — v0.9 RC (week of 16 Jun) → v1.0 GA (30 Jun).
> Cheap, high-leverage, identity-preserving.

---

## 01 · Where we are — shipped foundation → the build ahead

The measurable, contributable core exists. Two near-term items turned out to be
**wiring, not green-field** — only one piece of net-new code gates the whole H1
bundle.

**✓ Already shipped**
- Two enforcement points — `gate` (CI block) + generation-time skills
- Eval prevention-lift harness — `eval` with gate + signature oracles
- 29 signed skills · MIT · deterministic · offline · Ed25519
- `action.yml` composite Action + pre-commit hook (wrap `gate`)
- `eval --enforce` + `--min-lift` flags already in the CLI
- `preflight.sh` one-shot local CI signal

**★ The build ahead — H1**
- **New code:** SARIF output from `gate` (the only green-field piece) — _shipped on this branch_
- **Wire:** Action → upload SARIF to GitHub Code Scanning
- **Wire:** `eval --enforce` into a hard CI job
- **Verify:** brew / `go install` / `curl | sh` end-to-end
- **Verify:** `init` UX across every IDE + MCP target
- **Backfill:** eval corpora from 4 → ≥8 skills

> **The leverage:** because `gate` already flattens every scanner into one
> homogeneous result, SARIF is a clean transform — and once it lands,
> Code-Scanning visibility and the turnkey Action follow for almost free.

---

## 02 · The critical path — what blocks what

```
P0-1 commit framework work ─┐
P0-3 backfill eval corpora  ├─► P1-5 SARIF from `gate` ─► P1-6 Action → Code Scanning
P1-4 wire eval --enforce ───┘                         └─► P1-7 brew/go/curl   (parallel)
                                                       └─► P1-8 init UX polish (parallel)
```

Do the three left-column unblockers → build SARIF once → the Action upload falls
out of it. Install & `init` need nothing from SARIF, so they run in parallel from
day one.

---

## 03 · v0.9 RC — turn the adoption engine on  ·  week of 16 Jun 2026

Remove install friction and make findings legible to every CI buyer. Highest-
leverage adoption work; costs no moat.

| # | Ships | Build tasks (file touch-points) | Done when |
|---|---|---|---|
| **P1-5** ★NEW | **SARIF from `gate`** | New `PolicyCheckSARIF()` in `internal/tools/sarif.go`; flip `addFormatFlag(gate,true)`; add `case "sarif"` in `tools_cli.go`; emit SARIF *before* the fail-exit; tests. | schema-valid SARIF 2.1.0; planted finding appears; still exits non-zero on fail |
| **P1-6** | **Action → Code Scanning** | Add `sarif-file` input to `action.yml`; add `upload-sarif` step; sample workflow; README snippet. | SARIF appears in Code Scanning; gate fails a PR on a planted finding |
| **P1-7** | **brew / go / curl** | Verify `packaging/homebrew/skills-check.rb` + tap; verify `go install …/cmd/skills-check@latest`; harden `landing/install.sh` → `curl \| sh` (arch detect + checksum). | install works macOS + Linux; < 30s to first run |
| **P1-8** | **`init` UX polish** | Walk each IDE + MCP target zero→active in `cmd/skills-check/cmd/init.go`; idempotent re-runs; clear next-step output. | every target verified end-to-end |

> **Theme:** be everywhere a developer already is — terminal, CI, IDE — for free.
> Determinism is the CI *advantage*: no API keys, fast, reproducible.

---

## 04 · v1.0 GA — a complete free product  ·  30 Jun 2026

Stabilise the surface and make the prevention-lift bar a hard gate. After GA,
bottoms-up growth begins in earnest on a product complete for one team forever.

- **P1-4 · the hard gate — `eval --enforce` in CI.** Flag already exists
  (`eval.go:188`). Add a dedicated CI job running `skills-check eval --all
  --enforce`; calibrate per-skill `min_lift` so current corpora pass before
  turning it red. Keep `preflight.sh` the fast local signal.
- **P0-3 · feed the gate — corpora 4 → ≥8 skills.** Author
  `skills/<id>/evals/cases.json` for skills a `gate` oracle can judge;
  `eval --write` to regenerate `evals.json` and confirm positive lift.
- **Stability** — stable CLI / MCP / Action; no breaking flag changes after GA.
- **Onboarding** — < 5-min quickstart from a cold `git clone` / install.
- **Freshness** — signed delta channel so knowledge refreshes between releases.

> **Exit criteria:** `gate --format sarif` in Code Scanning, CI hard-gating lift,
> install < 30s, `init` verified everywhere — and `preflight` green throughout,
> with zero `.go` branding churn.

---

## 05 · Beyond H1 — what comes after the adoption engine

H1 buys reach. The Moat and Category horizons convert it — but the build there is
mostly **scale** (more corpora, live-model generation, publishing), not
invention. The measurement engine already exists.

**H2 · Moat & monetization — Q3 2026 (where the funnel converts)**
- Freshness pipeline — OSV/GHSA/Socket/Phylum → signed release; track advisory→ship latency
- `skills-check status` — "your AI's security knowledge is N days old"
- Live-model eval gen — lift becomes *measured*, not authored
- Signed attestation — SOC2 / HIPAA / PCI mapping (free local; managed = **PAID**)
- vibe-guard Cloud MVP — fleet policy · private signed registry · SLA (**PAID**)

**H3 · Trust & category — H2 2026+ (the air cover that makes enterprises buy)**
- AI Coding Security Leaderboard — reproducible, citable; our "Top 10" moment
- Standards crosswalk — map `SKILL.md` + `evals.json` to agentskills.io / Cisco taxonomy
- Detector interop — our bundles pass third-party scanners clean
- Signed community gallery — publish→verify; governance + key-rotation policy lands first
- Governance dashboards — self-hostable, no-telemetry-safe (**PAID**)

> **Gate on validation, not the calendar:** PAID items (Cloud, private rules, SLA)
> do not start before a design partner exists — building the control plane
> speculatively burns runway with no signal.

---

## 06 · Definition of done — H1 done means all of this is true

- **SARIF** — `gate --format sarif` ships, tested, schema-valid 2.1.0
- **Code Scan** — Action uploads SARIF + fails the PR on a planted finding
- **Hard gate** — CI red when prevention-lift drops below a skill's floor
- **< 30s** — brew · go · `curl | sh` all reach first run fast

**Guardrails held throughout**

| Guardrail | Why it matters |
|---|---|
| No cloud LLM / AST in-tool | Preserves offline · no-API-key · no-telemetry — the trust posture the funnel depends on. |
| No auto-fix · no paywalled fix | Detection + guidance only; the free framework stays complete for one team forever. |
| Functional identifiers frozen | Go module path, `skills-check`, repo/pages URLs, winget id untouched until the org rename. Marketing prose only. |
| preflight green · eval-gated | Every change passes the one-shot CI signal; contributions merge on green gates + a real source. |

> **Next action after SARIF:** wire the Action to upload SARIF to Code Scanning
> (P1-6), which the SARIF work now unblocks.
