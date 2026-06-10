# vibe-guard — Roadmap

> **North star:** own *generation-time security* — the prevention + governance
> layer that lives inside every AI coding assistant, plus the CI gate that blocks
> what slips through. Don't chase detection depth; own freshness, verifiability,
> governance, and the **framework rail** others build on.

**Ecosystem:** ShieldNet360 (umbrella) ⊃ **vibe-guard** (this repo, OSS/MIT) →
**vibe-guard Cloud** (commercial control plane).
**v1.0 public launch:** 2026-05-31 (shipped) · **Last updated:** 2026-06-09

See [VISION.md](./VISION.md) for the framework thesis and the open ↔ commercial
boundary; this file is the time-ordered plan to get there.

---

## How to read this

Work is grouped into horizons. Every item is tagged by funnel role:

- **`FREE`** — ships in the open-source framework; drives adoption + reputation.
- **`PAID`** — vibe-guard Cloud; org-scale value capture (born *above* the
  value line, never taken from below it — see VISION §3).
- **`REP`** — reputation / trust; not monetized directly, buys credibility.

Guardrails (identity is the asset) are at the bottom — the things we deliberately
will **not** build. The companion [BACKLOG.md](./BACKLOG.md) breaks the active
horizons into concrete, prioritized tasks.

---

## Recently shipped (since 2026-05-28)

The roadmap's framing changed under us: we are now positioned as an **open,
batteries-included framework**, not a single-purpose tool. These landed and are
reflected throughout the horizons below.

| Shipped | Role | What |
|---|---|---|
| **Framework positioning** | REP | [VISION.md](./VISION.md): two enforcement points (gen-time prevention + CI gate), 5 extension points, the open ↔ commercial value line. |
| **Eval / prevention-lift harness** | FREE | `skills-check eval [<id>\|--all] [--write] [--enforce]`. Two oracles: `gate` (run real scanners as an independent judge) and `signature` (regex for code-level vulns). Emits NVIDIA/skills-compatible `evals.json`. This is the objective bar that makes contribution **eval-gated, not taste-gated**. |
| **Eval corpora seeded** | FREE | `evals/cases.json` for secret-detection (4), container-security (3), cicd-security (3), database-security (3) — 13 cases, gate + signature oracles. |
| **"Gate, don't gatekeep" contribution model** | REP | AGENTS.md + CONTRIBUTING.md rewritten: AI-authored PRs welcome, trust comes from green gates + a real source, not authorship. Added the "vibe path" 60-second contribution loop. |
| **`scripts/preflight.sh`** | FREE | One command runs every CI gate (validate → test → regenerate-drift → derive-checklists → manifest → eval) and prints a single green/red. Always builds the CLI fresh to avoid stale-binary false failures. |

**What this unlocks:** the H3 "AI Coding Security Leaderboard" is no longer
aspirational — its measurement engine (`eval`) exists. The remaining work is
*scale* (live-model generation, more corpora), not *invention*.

---

## H0 — Launch (shipped 2026-05-31)

The v1.0 cut: a polished, frictionless first impression.

| Deliverable | Role | Status |
|---|---|---|
| **Unify branding under ShieldNet360 umbrella** | REP | **In progress.** Confirmed hierarchy: ShieldNet360 (ecosystem) ⊃ vibe-guard (OSS) → vibe-guard Cloud (commercial). VISION.md + AGENTS/CONTRIBUTING are aligned; README, PROPOSAL, `mkdocs.yml`, `landing/` still need the pass. Tracked in BACKLOG. |
| Landing page live (`landing/`) | REP | Shipped — deploy to a stable host (Pages), not a tunnel. |
| Docs site polish (MkDocs) | REP | Shipped — quickstart works from a cold `git clone`. |
| Honest capability pass | REP | Ongoing discipline: every site/demo claim must be true today. |

**Exit criteria (met):** zero → skills active in an IDE in < 5 minutes. The one
open thread is finishing the branding unification across consumer-facing surfaces.

---

## H1 — Reach (now → 3 months)

Neutralize the two places competitors out-reach us. Cheap, high-leverage, zero
identity cost. **This is the adoption engine.**

| Deliverable | Role | What / why | Success metric |
|---|---|---|---|
| **Package-manager install** | FREE | Homebrew tap + `go install` + harden `landing/install.sh` into a one-line `curl \| sh`. Today install = `git clone` (the #1 adoption blocker vs `pip`/`brew`). | Install via brew/go works on macOS + Linux; < 30s to first run |
| **SARIF output + CI gating** | FREE | The `gate` command already blocks at a severity floor; surface its findings as SARIF so they upload to GitHub Code Scanning. Determinism is the CI *advantage*: no API keys, fast, reproducible. | SARIF uploads to Code Scanning; gate fails a PR on a planted finding |
| **Reusable GitHub Action** | FREE | Thin workflow wrapping `gate → SARIF → upload`. Mirrors the entrenched detector CI motion, but at generation-policy level. | One-block `uses:` snippet works in a sample repo |
| **`init` UX polish** | FREE | Make `skills-check init` the obvious first command across all IDE targets + MCP. | Each target verified end-to-end |

**Theme:** be everywhere a developer already is — terminal, CI, IDE — for free.

---

## H2 — Moat & monetization (3–9 months)

Deepen the differentiators and stand up the paid control plane. **This is where
the funnel converts.**

| Deliverable | Role | What / why | Success metric |
|---|---|---|---|
| **Freshness pipeline** | FREE (data) | Automate ingestion of advisories (OSV / GHSA / Socket / Phylum) → malicious-package + CVE DB → signed release. Freshness is the whole premise ("training data is stale") — make it operational and provable. | Median advisory→ship latency tracked + published |
| **`skills-check status` / staleness** | FREE | "Your AI's security knowledge is N days old" is a killer metric and an upgrade nudge. | Command reports per-source freshness |
| **Live-model eval generation** | FREE→REP | `skills-check eval gen`: produce `baseline`/`with_skill` from a real model (opt-in, offline-respecting) so prevention-lift becomes a *measured* rate, not an authored one. Feeds the leaderboard. | Reproducible lift number from a live model on ≥1 skill |
| **`evidence` → signed attestation** | FREE→PAID | Extend `evidence` into a signed, timestamped attestation: which rules active, which version, mapped to SOC2/HIPAA/PCI/FedRAMP. The `evals.json` artifact is the proof substrate. Free local report; **managed/historical = PAID**. | Verifiable signed artifact an auditor accepts |
| **Central policy & fleet management** | PAID | vibe-guard Cloud MVP: push one curated skill set + token budget across all repos/devs/tools in an org; enforce which skills are active. | 1+ design-partner org governed centrally |
| **Private rule distribution** | PAID | Org's internal namespaces + proprietary rules, signed via a private trust root (VerifyAny); air-gapped option. | Private signed bundle delivered + verified |
| **Premium freshness SLA** | PAID | Guaranteed rapid ingestion ahead of community best-effort. | Contracted SLA met for design partners |

**Theme:** free = the developer's tool; paid = the security team's control plane.

---

## H3 — Trust & category (9–18 months)

Cement the category and the credibility that makes enterprises buy. **This is the
air cover.** The measurement engine (`eval`) already exists — this horizon is
about *publishing* and *standardizing* it.

| Deliverable | Role | What / why | Success metric |
|---|---|---|---|
| **AI Coding Security Leaderboard** | REP | Use `skills-check eval` to measure how often each AI tool generates insecure code *with vs without* vibe-guard. Runs locally (consistent with no-telemetry). Link-bait + research moat + category narrative in one. | Published, reproducible, cited externally |
| **Standards alignment** | REP | Map `SKILL.md` + `evals.json` to agentskills.io / Codex Skills / Cisco AI Security Framework taxonomy; publish the schema as an open spec. Kills the "proprietary format" friction; buys interop credibility. | Crosswalk published; ≥1 external adopter of the spec |
| **Detector interop** | REP | CI-verify our own `dist/*-skills/` bundles pass third-party scanners (e.g. Cisco skill-scanner) clean; publish a "prevent → verify" integration guide. Positions us as ecosystem infrastructure, not a rival. | Green scan badge on our bundles |
| **Signed community gallery** | REP→PAID | Anyone publishes a skill; anyone verifies it (Ed25519 + VerifyAny). Answers the "ToxicSkills" problem head-on. Governance + key-rotation policy must land *before* this scales. | Public publish→verify flow; documented trust policy |
| **Governance dashboards** | PAID | Self-hostable / opt-in posture views across teams (preserves the no-telemetry trust promise). | Design partners using it for board/audit reporting |

---

## Guardrails — what we will NOT build

These are tempting (especially from comparison with detectors) but erode the
identity that *is* the moat:

- **No cloud LLM / AST / behavioral engines inside the tool.** Breaks offline +
  no-API-key + no-telemetry. The consumer's AI *is* the LLM; defer deep detection
  to detectors.
- **No auto-fix.** Detection + guidance only. Auto-fix is a slope into shipping
  AI-generated security-critical changes that bypass human review.
- **No general-purpose CVE/SCA sprawl.** Stay narrow on the AI-introduced
  supply-chain surface. Becoming "a worse NVD" is the strategic trap.
- **No paywalling a security fix.** The free framework stays complete for one team
  forever, or the reputation engine dies. A feature never moves OSS → commercial;
  paid needs are *born* above the value line.
- **No taste-gating contributions.** Merge on green gates + a real source, not on
  who (or what) wrote it. The eval harness is the objective bar.

---

## Sequencing at a glance

```
SHIPPED          [framework positioning] [eval harness] [gate-don't-gatekeep] [preflight]
H0 Launch        [landing/docs ✓] ──────► v1.0 (May 31 ✓)   · [brand unify ◐]
H1 Reach         [brew/go/curl] [SARIF + gate] [Action] [init UX]
H2 Moat          [freshness] [status] [live-model eval] [attestation] ─┐
                 [central policy] [private rules] [SLA] ◄──── PAID converts here
H3 Trust         [leaderboard] [standards] [interop] [gallery] [dashboards]
```

The single highest-leverage near-term bet is the **H1 bundle** (brew/go install
+ SARIF gate + GitHub Action): it closes both reach gaps, costs little, and
compromises none of the prevention / offline / signed identity.

---

## Open questions (to resolve before committing engineering)

1. **Commercial anchor** — does vibe-guard Cloud funnel into an existing
   platform (the PROPOSAL references `sn360-security-platform`), or is the paid
   SKU greenfield? Determines whether H2 builds an integration or a new product.
2. **SARIF surface** — extend the `gate` command to emit SARIF directly vs. a new
   `skills-check scan` subcommand. (Recommend: extend `gate`, so CLI + MCP +
   Action stay at parity on one scanner core.)
3. **Dashboard data path** — given the no-telemetry promise, paid dashboards must
   be self-hostable or strictly opt-in. Confirm the deployment model early.
4. **Gallery governance** — key-rotation and root-of-trust policy must be written
   and documented *before* the signed community gallery opens (VISION §8).
