# vibe-guard — Build Plan (engineering)

> The executable companion to [ROADMAP.md](./ROADMAP.md) (horizons / why) and
> [BACKLOG.md](./BACKLOG.md) (ordered what). This file is the **how**: each
> near-term item broken into concrete tasks, the exact files they touch, and the
> acceptance bar that says "done." Grounded in the code as of 2026-06-10.
>
> Scope: the **H1 "Reach" bundle** (v0.9 RC → v1.0 GA) plus the P0 unblockers.
> Moat / Category items stay in ROADMAP/BACKLOG until a design partner exists.

Functional-identifier guardrail (from CLAUDE.md): never rename the Go module
`github.com/namncqualgo/skills-library`, the CLI `skills-check`, the repo/pages
URLs, or the winget id while building. Those are load-bearing until the GitHub
org is renamed at the platform level.

---

## Critical path (one glance)

```
P0-1 commit framework work ─┐
P0-3 backfill eval corpora  ├─► P1-5 SARIF from `gate` ─► P1-6 Action → Code Scanning
P1-4 wire eval --enforce ───┘                         └─► P1-7 brew/go/curl   (independent)
                                                       └─► P1-8 init UX polish (independent)
```

`eval --enforce` and `action.yml` **already exist** — those items are *wiring*,
not green-field. The one genuinely new piece of code is **SARIF output from
`gate`** (P1-5); everything in H1 keys off it.

---

## P0 — unblockers

### P0-1 · Commit the framework work
**State:** 39 uncommitted/untracked entries (eval harness, corpora, VISION/
ROADMAP/BACKLOG/BUSINESS_PLAN, CLAUDE.md, preflight.sh, landing/). Nothing is on
a branch.
**Tasks**
- Split into logical commits: (a) eval harness `cmd/skills-check/cmd/eval.go` +
  `eval_test.go`; (b) corpora `skills/*/evals/` + `evals.json`; (c) docs/strategy
  prose; (d) `scripts/preflight.sh` + manifest; (e) `landing/` collateral.
- Keep `.go` branding untouched (functional identifiers).
**Acceptance:** branch pushed; `scripts/preflight.sh` green in CI.
**Guardrail:** committing framework work requires `gh auth switch --user
namncqualgo` + explicit go-ahead (CLAUDE.md). Do not push without it.

### P0-3 · Backfill eval corpora (≥8 skills)
**State:** only **4 of 29** skills ship `evals/cases.json` (secret-detection,
container-security, cicd-security, database-security). Target ≥8 with positive
lift.
**Tasks**
- Pick the next 4+ skills whose vulns a `gate` scanner can *judge* (so the `gate`
  oracle works, not only the `signature` regex oracle). Candidates: any skill
  whose insecure output is a dependency/Dockerfile/workflow/secret pattern.
- Author `skills/<id>/evals/cases.json` (baseline vs with_skill pairs) following
  the existing four as templates.
- Run `skills-check eval <id> --write` to regenerate `evals.json`; confirm lift.
**Acceptance:** `skills-check eval --all` covers ≥8 skills, each with positive lift.

---

## P1 — H1 Reach bundle

### P1-5 · SARIF output from `gate`  ⭐ (the new code)
**Why first:** `gate` is the canonical CI "fail the build" entry point. It
already flattens every scanner into a homogeneous `PolicyCheckResult`
(`internal/tools/library_scanners.go:958`), so SARIF is a clean transform. P1-6
(Action upload) and Code-Scanning visibility both depend on this.

**Current state (verified):**
- `gate` (`cmd/skills-check/cmd/tools_cli.go:545`) calls
  `addFormatFlag(c, &format, false)` — SARIF is **disabled** for gate.
- SARIF infra exists in `internal/tools/sarif.go` + `sarif_scanners.go`, but the
  transformers are **per-scanner** (`ScanSecretsSARIF`, `CheckDependencySARIF`,
  `ScanDependenciesSARIF`, `ScanGitHubActionsSARIF`, and a dockerfile one).
  There is **no aggregator** over `PolicyCheckResult`.
- `PolicyCheckFinding` already carries `RuleID, Severity, Confidence, Title,
  Line, Snippet, Package, Version` — everything SARIF needs.

**Tasks**
1. **New transformer** in `internal/tools/sarif.go`:
   `func PolicyCheckSARIF(results []*PolicyCheckResult) *SARIFLog`
   - One SARIF `Run` aggregating all files (a `gate a b c` call passes many).
   - Build `driver.rules` from the distinct `RuleID` across all findings;
     `DefaultConfiguration.Level = sarifLevel(severity)` (reuse existing helper).
   - One `SARIFResult` per `PolicyCheckFinding`: `ruleId`, `ruleIndex`, `level`,
     message = `Title`, location = `fileURI(res.FilePath)` with
     `region.startLine = Finding.Line` when > 0.
   - Reuse `fileURI`, `sarifLevel`, `emptyLog`. Use `make([]…, 0)` everywhere so
     empty runs serialise `[]` not `null` (the repo's established invariant —
     GitHub AS rejects `null`).
   - Keep `SARIFToolName = "skills-mcp"`? **Decision:** add a `gate`-specific
     driver name constant `SARIFGateToolName = "vibe-guard-gate"` so Code
     Scanning can filter gate findings distinctly. (Open question — see below.)
2. **Flip the flag**: `gate` → `addFormatFlag(c, &format, true)`
   (`tools_cli.go:633`) and `validateFormat(format, true)` (`:563`).
3. **Wire the case**: in the `switch format` block (`tools_cli.go:590`) add
   `case "sarif": return emitJSON(c.OutOrStdout(), tools.PolicyCheckSARIF(results))`.
   - **Important:** SARIF must emit even on failure. Today gate returns the
     `policyFailureError` sentinel *after* printing. Ensure SARIF is written
     **before** the `if failures > 0 { return … }` so a failing gate still
     produces an uploadable artifact (Code Scanning needs the SARIF *and* the
     non-zero exit).
4. **Tests** `internal/tools/sarif_test.go` (+ a CLI test in
   `tools_cli_test.go`): valid SARIF for (a) clean multi-file run → empty
   results, (b) a planted secret, (c) a planted dependency finding, (d) mixed
   files in one invocation → single run, deduped rules, correct `ruleIndex`
   after sort.
5. **Validate** against the SARIF 2.1.0 schema (the repo already pins
   `SARIFSchema`); optionally add a smoke check that `gate --format sarif` output
   parses as the `SARIFLog` struct round-trip.

**Acceptance:** `skills-check gate <files> --format sarif` emits schema-valid
SARIF 2.1.0; a planted finding appears as a `result` with the right `level`; the
command still exits non-zero on a failing gate while writing the SARIF.

### P1-6 · GitHub Action → Code Scanning
**State:** `action.yml` (repo root) is a **composite Action** that npx-runs the
published package and calls `gate <files>` with `severity-floor`. It does **not**
emit or upload SARIF.
**Tasks (depends on P1-5)**
- Add an optional `sarif-file:` input; when set, run `gate … --format sarif >
  $sarif-file`.
- Add a `github/codeql-action/upload-sarif@v3` step (or document it in the
  consuming workflow) gated on `sarif-file` being present.
- Ensure the Action's gate step still surfaces the non-zero exit (fail the PR)
  *and* uploads SARIF — order: capture SARIF, upload, then fail.
- Update README's Action snippet + add a sample workflow under
  `.github/workflows/` (or an `examples/` repo snippet) proving one-block `uses:`.
**Acceptance:** SARIF artifact validates and appears in GitHub Code Scanning on a
sample repo; gate fails the PR on a planted finding.

### P1-4 · `eval --enforce` as a hard CI gate
**State:** the flag **already exists** — `eval.go:188` (`--enforce`), `:185`
(`--min-lift`, default 0.25), `:175` (non-zero exit when any skill below floor).
`scripts/preflight.sh:84` runs `eval --all || true` (**informational**).
**Tasks**
- Decide the enforcement surface: flip preflight's eval step from `|| true` to a
  hard `--enforce` (and remove the swallow), **or** add a dedicated CI job in
  `.github/workflows/validate.yml` that runs `skills-check eval --all --enforce`.
  Recommend a **separate CI job** so preflight stays a fast local signal and CI
  owns the hard gate.
- Calibrate per-skill `min_lift` (the corpora carry `min_lift` in `evals.json`,
  `eval.go:57`). Confirm the 4 existing skills pass at the chosen floor before
  turning the gate red, so we don't ship CI red.
**Acceptance:** CI goes red when a skill's measured lift drops below its floor;
green on current corpora.
**Depends on:** P0-3 (more corpora = more meaningful gate), but can land with 4.

### P1-7 · Package-manager install (brew / go / curl)
**State:** `packaging/homebrew/skills-check.rb` and `landing/install.sh` exist;
not verified end-to-end. `go install` path should already work via the module.
**Tasks**
- Verify `brew install` from the formula on macOS (Intel + Apple Silicon) and
  Linuxbrew; confirm the tap publish flow.
- Verify `go install github.com/namncqualgo/skills-library/cmd/skills-check@latest`.
- Harden `landing/install.sh` into a `curl … | sh` one-liner (OS/arch detect,
  checksum verify against the signed release, `$PATH` hint). Keep it auditable.
**Acceptance:** brew + go install work on macOS + Linux; `curl | sh` < 30s to
first `skills-check` run.

### P1-8 · `init` UX polish
**State:** `cmd/skills-check/cmd/init.go` exists across IDE targets + MCP;
unverified end-to-end.
**Tasks**
- Walk each target (Claude/Cursor/Windsurf/VS Code/MCP) zero→active; fix the
  rough edges; make `skills-check init` the obvious first command (clear next-
  step output, idempotent re-runs).
**Acceptance:** each target verified zero→skills-active in < 5 minutes.

---

## Open questions (resolve while building)

1. **SARIF driver name for gate.** Reuse `skills-mcp` (consistent rule IDs,
   `skills-mcp.*`) or introduce `vibe-guard-gate` so Code Scanning can filter
   gate vs MCP findings? Leaning `vibe-guard-gate` for the driver `name` while
   **keeping** existing `skills-mcp.*` rule IDs (don't churn rule identity).
2. **`startLine` only, or full region?** `PolicyCheckFinding` has `Line` but not
   column/byte offsets for the project scanners. Emit `region.startLine` when
   present; omit region otherwise (valid SARIF). Don't fabricate byte offsets.
3. **Enforcement surface for `eval --enforce`** (preflight vs dedicated CI job) —
   recommend dedicated job; confirm before flipping.

## Definition of done for H1
- `gate --format sarif` ships, tested, schema-valid.
- The Action uploads SARIF to Code Scanning and fails the PR on a planted finding.
- CI hard-gates prevention-lift via `eval --enforce`.
- brew + go + `curl | sh` all reach first run in < 30s.
- `init` verified across every target.
- preflight stays green throughout; no `.go` branding churn.
