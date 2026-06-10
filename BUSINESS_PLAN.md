# vibe-guard — Business Plan

> **Generation-time security for AI-written code.**
> The open-source security brain that lives inside every AI coding assistant —
> and the governance platform that lets enterprises trust what their AI ships.

**Company:** Uney GmbH · **Product:** vibe-guard · **Open-source core:** `skills-library` (MIT)
**Stage:** Pre-launch (public v1.0 target: 2026-05-31) · **Model:** Open-core
**Author:** Uney GmbH founding team · **Last updated:** 2026-05-28

---

## 1. The one-sentence pitch

> AI now writes most new code, but it writes it with security knowledge that is
> months out of date — vibe-guard injects always-current, cryptographically-signed
> security rules *into the moment of generation*, and gives security teams proof
> of what their AI was told.

We are not a scanner. Scanners tell you what's already broken. **vibe-guard stops
it from being written.**

---

## 2. Why now (the wave we are riding)

Three curves are crossing in 2026:

1. **AI writes the code now.** Cursor, Claude Code, GitHub Copilot, Codex,
   Windsurf, Devin — a majority of new code in modern teams is AI-drafted. "Vibe
   coding" is the default workflow, not a novelty.
2. **The AI's security knowledge is frozen in the past.** A model's training
   data is months-to-years stale on its release day. A package compromised
   yesterday is happily `import`-ed today. The model cannot know what it was
   never trained on.
3. **Nobody can answer the CISO's question.** *"What security rules is the AI
   applying when my team vibe-codes?"* Today the honest answer is **none that
   anyone governs.** This is an unowned, board-level risk.

The result: insecure-by-default code is being generated at machine speed, and
existing security tooling all runs *after* the diff exists — too late, out of
context, and bolted on. The market has a generation-time hole. We fill it.

---

## 3. The problem, precisely

| Failure | Who feels it | Today's "solution" | Why it fails |
|---|---|---|---|
| AI imports malicious / typosquatted packages | Every dev using AI | SCA scan in CI | Catches it *after* it's in `package.json`; the dev moved on |
| AI hardcodes secrets, writes injectable code | Every dev using AI | Secret scanner / SAST | Post-hoc, noisy, ignored |
| No record of what security guidance the AI had | CISO / auditor | Nothing | Cannot prove a control existed |
| Security knowledge goes stale the day the model ships | Everyone | Wait for next model | Months of exposure |
| Each team hand-writes its own `CLAUDE.md` rules | Tech leads | Copy-paste folklore | Inconsistent, unmaintained, unsigned |

Security has spent a decade "shifting left." vibe-guard is the next shift: **left of
the keystroke — into the model's context itself.**

---

## 4. The product

### 4.1 What it is
vibe-guard delivers a curated, versioned, **cryptographically-signed** library of
security knowledge — supply-chain intelligence, secret patterns, injection
rules, IaC hardening, compliance mappings — straight into the configuration
surface every AI coding tool already reads (`CLAUDE.md`, `.cursorrules`,
Copilot instructions, `AGENTS.md`, MCP tools, native agent skills).

The AI reads it *before it writes a line.* Prevention, in-context, at the speed
of generation.

### 4.2 The three things only we do
1. **In-context, not after-the-fact.** We live where code is born — inside the
   model's prompt/skill/MCP surface — not in a separate scan step.
2. **Always fresh + provable.** Signed (Ed25519) delta updates fix the
   stale-training-data problem and let anyone verify the knowledge is authentic
   and current. Detectors don't address staleness; we make it the headline.
3. **Governable + auditable.** We answer the CISO's question with a signed
   attestation: *these rules, this version, active on this date, mapped to these
   frameworks.* No competitor in the generation layer produces audit evidence.

### 4.3 Offline-first, zero-telemetry by design
The tool never phones home. It runs air-gapped from first `git clone`. This is
both a trust asset (a security tool that requires a server is itself a supply-
chain risk) and an enterprise unlock.

### 4.4 Surfaces
- **OSS core (vibe-guard):** 28+ skills, supply-chain DB (9 ecosystems),
  typosquat + dependency-confusion intel, CVE→code patterns, Sigma rules,
  compliance maps. CLI (`skills-check`) + MCP server (`skills-mcp`, 15 tools).
- **vibe-guard Cloud / Enterprise:** the org control plane (see §8).

---

## 5. Why we will NOT fight Cisco (or Snyk, Semgrep, Socket)

> We deliberately refuse the knife fight in the crowded detection market.

| | Detectors (Cisco skill-scanner, Snyk, Semgrep, Socket) | **vibe-guard** |
|---|---|---|
| When | *After* code/skill exists | *Before* — at generation |
| Question answered | "What's wrong with this artifact?" | "What should the AI never write?" |
| Buyer moment | Audit / CI gate | Inside the IDE + org governance |
| Category | Detection / scanning (mature, contested) | **Generation-time security (uncontested)** |

These tools are **downstream of us, and we are complementary to them.** Our
public stance: *prevention upstream → detection downstream.* We will publish
integrations ("vibe-guard prevents it; verify with your scanner") and even certify
that our own bundles pass Cisco's scanner clean. Cisco validates our open-core
playbook (their free scanner funnels to paid AI Defense) — we run the same motion
in a category they don't occupy. **We make detectors look like the safety net,
and ourselves like the seatbelt.**

---

## 6. Market & opportunity

- **Bottom-up TAM:** tens of millions of developers now use AI assistants; each
  is a free-tier install and a potential seat.
- **Top-down TAM:** the DevSecOps / AppSec market (~$15B+ and growing double
  digits) is creating a brand-new line item — *"AI-generated code security"* —
  that no incumbent owns end-to-end.
- **Wedge:** "secure your AI coding assistant" is a search every eng leader will
  run in the next 24 months. We intend to be the obvious answer.
- **Expansion:** every company adopting AI coding (i.e., all of them) eventually
  needs governance + attestation. That is the enterprise budget.

This is a category-creation opportunity, not a share-stealing one — the defining
characteristic of venture-scale outcomes.

---

## 7. Business model — open-core funnel

**Free builds the audience and the brand; the org control plane captures value.**
The line is drawn at **org scale, never by crippling the individual.**

```
Individual dev installs free OSS  ──►  team standardizes on it
        ──►  security mandates it org-wide  ──►  Enterprise contract
```

| Tier | Audience | Price | What you get |
|---|---|---|---|
| **Community** (OSS, MIT) | Individuals, small teams, OSS maintainers | **Free forever** | Full skill library, CLI, MCP server, offline, signed public updates, SARIF CI gate, GitHub Action |
| **Team** | Startups & scaleups | Per-developer / mo | Central policy push across repos, private/custom rules, freshness SLA, CI dashboards, Slack + IDE integrations, priority updates |
| **Enterprise** | Regulated & large orgs | Custom | Fleet governance, **compliance attestation-as-a-service** (SOC2/HIPAA/PCI/FedRAMP evidence), air-gapped private distribution channel, SSO/RBAC, on-prem, support SLA |

**Anti-"open-bait" guarantee:** the Community tier is genuinely complete for a
working developer, forever. We never paywall a security fix. We charge for
*managing security across many developers*, not for security itself.

---

## 8. The commercial product (vibe-guard Cloud)

The free tool is one developer's seatbelt. The paid product is the security
team's control plane over thousands of them:

1. **Central policy & fleet management** — define one curated skill set + token
   budget; enforce it across every repo, dev, and AI tool in the org.
2. **Private rule distribution** — your internal package namespaces, proprietary
   detection rules, signed and delivered through vibe-guard's distribution channel;
   air-gapped option for the most regulated.
3. **Premium freshness SLA** — guaranteed rapid ingestion of new advisories,
   ahead of the community best-effort feed.
4. **Compliance attestation-as-a-service** — signed, audit-ready, historical
   evidence of which rules governed your AI, when, mapped to frameworks. This is
   the line item a CISO can put in front of a board or an auditor.
5. **Governance dashboards** — self-hostable / opt-in (preserving the no-
   telemetry trust promise) coverage and posture views across teams.

---

## 9. Go-to-market

**Phase 1 — Developer-led growth (reputation engine).**
- World-class OSS, frictionless install (`brew`, `go install`, one-line `curl`).
- Launch loud: Show HN, Product Hunt, the Cursor / Claude Code / Copilot
  communities, dev-influencer seeding.
- **Own a benchmark:** publish the *"AI Coding Security Leaderboard"* — a
  reproducible eval of how often each AI tool generates insecure code with vs
  without vibe-guard. This is link-bait, credibility, and a moat in one.

**Phase 2 — Standards & trust (air cover).**
- Contribute upstream (agent-skill specs, OSV, Sigma) so vibe-guard is seen as
  ecosystem infrastructure, not a vendor.
- Publish research on AI-generated-code risk. Become the cited source.

**Phase 3 — Bottom-up to top-down (revenue).**
- PLG signal (orgs with many installs) triggers a governance conversation with
  their security leadership. Sell the control plane and the attestation.

---

## 10. Moat / defensibility

- **Freshness pipeline + signing** — operational excellence that compounds; hard
  to match and continuously valuable.
- **Data network effect** — every adopter and contributor sharpens the rule
  corpus and false-positive suppressions; the library gets better and fresher
  the more it's used.
- **Category & brand ownership** — if "secure your AI coding" means vibe-guard, late
  entrants fight uphill.
- **Trust posture** — offline, no-telemetry, signed, MIT. A credibility position
  cloud-funnel incumbents structurally cannot fully copy.
- **Distribution surface lock-in** — once vibe-guard is the org's standard
  `CLAUDE.md` / MCP / skill bundle, it's embedded in every new repo by default.

---

## 11. Roadmap (funnel-aware)

| Horizon | Theme | Ships | Funnel role |
|---|---|---|---|
| **H1 — Now** | Reach | Homebrew / `go install` / one-line installer; SARIF output + `--fail-on-severity`; reusable GitHub Action | Top-of-funnel adoption, free |
| **H2 — Next** | Moat | Automated advisory ingestion + freshness SLA; `evidence` → signed attestation; central policy / fleet management | Graduates into paid tiers |
| **H3 — Later** | Trust | Standards alignment; the AI Coding Security Leaderboard / eval benchmark | Reputation & air cover |

**Guardrails (identity is the asset):** no cloud LLM inside the tool, no
auto-fix, no general-purpose CVE/SCA sprawl. Stay the prevention + governance
layer; defer detection depth to detectors.

---

## 12. Key metrics (north stars)

- **Adoption:** installs, weekly-active repos, GitHub stars, MCP calls.
- **Reputation:** benchmark citations, standards contributions, inbound press.
- **Funnel:** orgs above the install threshold → governance conversations.
- **Revenue:** Team seats, Enterprise ARR, net revenue retention (expansion).
- **Trust:** library freshness (median advisory→ship latency), signature
  verification rate.

---

## 13. Risks & mitigations

| Risk | Mitigation |
|---|---|
| AI vendors build security knowledge in natively | We're cross-tool, always-fresher, signed, and governance-grade; we ride on top of all of them rather than betting on one |
| "Open-bait" backlash | Community tier is permanently complete for individuals; we never paywall a fix |
| No-telemetry blinds the funnel | Value-pull GTM + opt-in/self-hosted dashboards; PLG signal from public install surfaces |
| Brand inconsistency (legacy ShieldNet360 / kennguy3n naming) | Unify all surfaces under Uney GmbH (company) + vibe-guard (product) before launch |
| Commodification of rule content | Moat is freshness + signing + governance + network effect, not any single rule |

---

## 14. The ask / next 90 days

1. **Unify the brand** under Uney GmbH (company) + vibe-guard (product) across repo, docs, and module path.
2. **Ship Horizon 1** (install reach + SARIF + Action) to ignite developer
   adoption.
3. **Launch the benchmark** to claim the category narrative.
4. **Stand up vibe-guard Cloud MVP** (central policy + attestation) for design-
   partner enterprises sourced from the PLG signal.

> Detection is a crowded room. **Generation-time security is an empty one with a
> rising tide.** vibe-guard gets there first, free, and trusted — then sells the
> control plane to every company whose AI is already writing code.
