# Vision

vibe-guard is an **open, signed standard and reference framework** for security
skills and gen-time → CI enforcement. Batteries included. Vendor-neutral.
Eval-gated contribution. A commercial control plane exists at org scale — but it
never gates the security itself.

This document is the north star: what we are, where the open framework ends and
the commercial control plane begins, the extension points that make this a
framework rather than a tool, and how we interop with the wider ecosystem.

---

## 1. Where we sit

vibe-guard is a member of the **ShieldNet360** ecosystem:

```
                         ShieldNet360  (ecosystem umbrella)
        ┌───────────────────────────────────────────────────────────────────────┐
        │   vibe-guard  (skills + gate)                                           │
        └───────────────────────────────────────────────────────────────────────┘
```

- **vibe-guard** (this repo) — security knowledge injected into AI coding
  assistants at generation time, plus a `gate` that blocks insecure diffs at
  commit/CI time.

Together these two enforcement points cover *what the AI is taught to write*
and *what is allowed to ship*.

---

## 2. What we are (and are not)

We are **prevention-first**. We inject security knowledge into the AI at the
moment code is generated, then verify the result before it ships.

| We ARE | We are NOT |
| --- | --- |
| A skill **format** (`SKILL.md`) + open standard | A runtime LLM firewall / gateway |
| A **reference implementation** (CLI + MCP + `gate`) | An auto-fixer that rewrites your code |
| Gen-time **prevention** (IDE configs feed rules into the AI) | A post-hoc scanner that only reports |
| CI-time **enforcement** (`gate` blocks at a severity floor) | A telemetry/cloud-dependent product |
| **Signed** & verifiable (Ed25519, VerifyAny) | A black box you must trust blindly |

Two enforcement points, one framework:

1. **PREVENTION (gen-time)** — `dist/` IDE configs + the MCP server feed security
   rules into the AI as it writes code.
2. **ENFORCEMENT (CI-time)** — the `gate` command (pre-commit hook + GitHub
   Action) blocks any diff with a finding at or above the severity floor.

---

## 3. The open ↔ commercial boundary

The dividing line is the most important thing in this document. **Everything
needed to prevent and block an insecure diff is open source, forever.** The
commercial tier sells *scale, managed trust, and proof* — never the security
itself.

```
══════════════════════════ vibe-guard ════════════════════════════════════════════

   OPEN SOURCE (MIT) — the framework, batteries included
   the rail everyone builds on. never crippled.
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │  FORMAT            SKILL.md open standard · checklists · evals.json schema     │
 │  KNOWLEDGE         security skills (OWASP / CWE / ATT&CK mapped)                │
 │  REFERENCE IMPL    skills-check CLI · skills-mcp (16 tools) · gate command     │
 │  GEN-TIME          dist/ IDE configs (claude/cursor/copilot/windsurf/agent)    │
 │  ENFORCEMENT       pre-commit hook + GitHub Action (severity-floor gate)       │
 │  TRUST             Ed25519 signing · VerifyAny · public delta channel          │
 │  EXTENSION POINTS  +rule/intel source  +scanner  +agent target  +trust root    │
 │                    +eval harness          ← contribute with zero Go, eval-gated│
 │  GALLERY           community-signed skills, anyone can publish & verify         │
 └──────────────────────────────────────────────────────────────────────────────┘
                                   │
 ════════ VALUE LINE: solo dev / single team / one repo gets everything ═════════
                                   │   crossing happens at ORG SCALE & TRUST, never at features
                                   ▼
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │  COMMERCIAL (vibe-guard Cloud)  — the control plane                            │
 │  you graduate here when you have many repos, many people, an auditor.          │
 │                                                                                │
 │  FLEET POLICY        org-wide rules, exceptions, drift dashboards across N repos│
 │  PRIVATE DISTRO      signed private skill registry (your own trust root)       │
 │  FRESHNESS SLA       managed, time-bound vuln/intel feed (vs self-host OSV)     │
 │  COMPLIANCE          SOC2 / ISO attestation, audit log, "who-shipped-what"     │
 │  IDENTITY / OPS      SSO, RBAC, on-prem / air-gap deploy, support              │
 └──────────────────────────────────────────────────────────────────────────────┘
```

**Rule of the line**

- Everything needed to PREVENT and BLOCK an insecure diff → OSS, forever.
- Commercial sells SCALE, MANAGED TRUST, and PROOF — not the security.
- A feature never moves OSS → commercial. New scale/compliance needs are *born*
  above the line; they are not taken from below it.

The discipline that keeps this honest: **the free side is a complete product for
one team, not a teaser.** Commercial only earns money when you have a fleet to
govern and an auditor to satisfy — capabilities a solo developer never needs, so
they never feel taxed.

---

## 4. Why a framework, not a solution

A *solution* is a product you adopt. A *framework* is a rail others build on —
and that is the defensible position against larger vendors, because the ecosystem
that grows on the rail is the moat.

The trap is the **empty abstraction**: a framework that ships interfaces and no
content, leaving every user to do the real work. We avoid it with one rule:

> **Opinionated core first, framework edges second.**

We ship a complete, batteries-included core (skills, scanners, signing, gate,
IDE configs) that works out of the box — *and* we expose clean extension points
so the core can be replaced, extended, and contributed to without forking.

---

## 5. The five extension points

These are what make vibe-guard a framework. Each is pluggable without touching
the core, and (where it matters) contributable with **zero Go**.

1. **Rule / intel sources** — where security knowledge comes from. Offline
   defaults today; pluggable live enrichment (e.g. OSV.dev) via
   `--vuln-source external|hybrid`. New sources register without core changes.
2. **Scanners** — `gate` routes a file to a scanner (secrets, dependencies,
   Dockerfile, GitHub Actions today). New scanners plug into the router and
   inherit the severity-floor contract.
3. **Agent targets (formatters)** — the same skills compile to many AI tools
   (Claude, Cursor, Copilot, Windsurf, agent bundles, …). A new target is a new
   formatter, not a new skill set.
4. **Trust roots (VerifyAny)** — multiple trusted signing keys. Orgs add their
   own root to distribute private signed skills; the public channel stays
   independent of any single key.
5. **Eval harness** — `skills-check eval` runs a skill's `evals/cases.json`
   (baseline vs. with-skill generations, judged by the real `gate` scanners or a
   signature regex) and records a **prevention-lift** number in `evals.json`.
   Contribution is **eval-gated, not taste-gated**, and the result is a signed
   artifact rather than a claim. This is how we stay open to the community
   without letting quality drift.

---

## 6. Contribution: easy, safe, and signed

- **Zero-Go path.** Adding a skill is writing a `SKILL.md` + its checklist +
  evals. No compiler knowledge required.
- **Eval-gated.** A contribution merges when its evals pass — an objective bar,
  not a maintainer's mood. `skills-check eval --all` reports the prevention lift
  across every skill that ships a corpus; `--enforce` turns it into a hard gate.
- **Signed gallery.** Anyone can publish a skill; anyone can verify it. The
  "ToxicSkills" problem (unsigned, unverifiable agent skills) is answered head-on:
  our skills are Ed25519-signed and verifiable by default.

---

## 7. Interop, not lock-in

We are a vendor-neutral standard. We meet the rest of the ecosystem where it is:

- **NVIDIA/skills & agentskills.io** — we emit `evals.json` and native skill
  bundles in the shared `SKILL.md` format, so vibe-guard skills are consumable
  by `npx skills add`–style tooling. We adopt the open standard rather than
  competing with it.
- **Cisco skill-scanner** — complementary, not competing. vibe-guard produces
  *clean, signed skills upstream*; a downstream detection scanner can scan them.
  Passing such a scan is a **trust badge**, not a threat.

Prevention-first + signed + gate is the least-crowded lane (vs. runtime firewalls
and post-hoc scanners). Interop keeps us at the center of it without walls.

---

## 8. Risks we are managing

- **Governance & signing keys.** A signed ecosystem lives or dies by key
  custody and a clear trust policy. VerifyAny keeps trust pluralistic (no single
  point of control), but key-rotation and root-of-trust governance must be
  explicit and documented before the gallery scales.
- **Cold-start.** A framework needs both content and contributors on day one.
  We seed with a complete, opinionated core (the batteries) so the framework is
  useful to a solo dev *before* the community exists — adoption first, network
  effects second.

---

## 9. North-star summary

> An open, signed standard and reference framework for security skills and
> gen-time → CI enforcement — batteries-included, eval-gated, vendor-neutral,
> with a commercial control plane (vibe-guard Cloud) at org scale, under
> the ShieldNet360 ecosystem.

Free is a complete product for one team. Commercial is the control plane for a
fleet. The line between them never moves down.
