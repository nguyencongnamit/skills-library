# IDEA.md — The $1B Thesis & Deep-AI Integration Map

> **INTERNAL · git-ignored** (competitive moat — never publish, never put in `docs/`).
> Created 2026-06-20. Companion to [STRATEGY.md](./STRATEGY.md) + [BACKLOG.md](./BACKLOG.md).

## TL;DR
The billion-dollar version is **not a better scanner** — it's the **trust & compliance
layer for AI-generated code**, defended by a **verified-DB network effect** and accelerated
by **AI grounded in that DB**. The mechanic is the *flywheel*, not any single feature: AI
auto-verify scales the contribution moat; the moat grounds the AI so it runs at a lower
false-positive rate than anyone else's. That two-way coupling is the only thing here an
incumbent can't fork.

---

## 1. Is $1B real in this space? (market comps)
Yes — there are direct comps:
- **Wiz** — $32B (Google). **Snyk** — ~$7.4B peak ("developer-first security").
  **Socket / GitGuardian / Endor Labs** — all venture-scale.
- **Endor Labs is the comp that matters most:** raised big on *exactly* our DQ-V thesis —
  "**reachability kills false positives** in dependency analysis." Our vertical-depth work
  (V.1/V.2 done, V.3 taint open) **is** that thesis. The market has already validated that
  "depth that removes noise" is fundable at scale.
- We are the **open-core, AI-native, contribution-networked** version of that.

## 2. The reframe — the $1B narrative
Category, not tool: **"the trust & compliance layer for AI-generated code,"** timed to two
waves at once:
1. AI writes exploding volumes of code; human review doesn't scale → security must run
   **in-loop with the agent**. We already live at the **MCP layer** — the wedge nobody owns yet.
2. **Nobody owns AI-generated-code compliance** (EU AI Act, NIST AI-RMF). Our signed
   `evidence --scan` bundles are a **CISO/CFO-level artifact**, not a dev toy.

## 3. The three structural upgrades to be venture-scale

| # | Upgrade | Why it's the difference |
|---|---|---|
| 1 | **Build the contribution-loop moat (v1.1)** | *Data network effect* (every user's finding → herd immunity for all) is the **only** durable defensibility. Non-negotiable for $1B. Without it we're "a fork with a logo." |
| 2 | **Depth that enables *enforcement* (DQ-V.3 taint)** | Low-FP turns "advisory toy" → "blocks the PR / signs the attestation." Enterprises pay for *enforcement*, not advice. Depth is the **permission to gate**. |
| 3 | **Enterprise monetization layer (v2.0)** | Open-core: free OSS bottoms-up (dev love) → private canon, fleet, RBAC/SSO, CI gate, compliance reports top-down. The revenue engine (Snyk/GitLab playbook). |

## 4. Where to integrate AI *deeply* (ranked by leverage)

**Unifying principle — AI scoped to the verified DB.** Generic "LLM security scanner" is a
commodity and FP-ridden (everyone ships it). *LLM reasoning constrained by a
cryptographically-verified, network-contributed DB* is the thing **nobody else has.** Deploy
AI only where the DB grounds it.

| Rank | Where | AI's role | Why it's defensible / high-leverage |
|---|---|---|---|
| **1** | **Auto-verify gate (v1.1)** | LLM-as-verifier: given a candidate finding, write a minimal repro, run it in a sandbox, judge if it's real | **Moat × AI.** Lets us crowdsource candidates *safely at scale*. Deterministic auto-verify is brittle; LLM auto-verify makes the contribution flywheel actually spin. **The single highest-leverage AI integration in the product.** |
| **2** | **DQ-V.3 taint** | Deterministic dataflow finds source→sink candidates (high recall, high FP) → **LLM judges exploitability** to prune | Kills FPs = the entire game. Same idea as Semgrep Assistant / Snyk DeepCode, but **grounded in the verified DB** → narrower, more precise. Unlocks safe gating (upgrade #2). |
| **3** | **Grounded auto-remediation (v1.4)** | Verified finding + verified-DB fix pattern → LLM writes the patch → **re-scan to verify the fix** | Detection→*fix* is where ACV jumps. Constrained to a *known vuln class + known fix* → low hallucination, unlike generic "AI fix." Closed-loop verify makes it trustworthy. |
| **4** | **The sanitizer (v1.1)** | LLM generalizes a concrete vulnerable snippet into a portable detection pattern **without leaking the user's code** | Enables the network loop's core promise ("code never leaves the machine"). Pair the LLM with a **deterministic leak-checker** that rejects any literal code string. |
| 5 | **Adaptive prevention (RAG)** | Instead of dumping all skills into IDE context, LLM retrieves the security knowledge relevant to what the agent is writing *right now* | Makes prevention context-aware; lets the two-loop apply to *knowledge*, not just findings. |
| 6 | **Compliance narrative + KG query (v1.2)** | LLM turns signed evidence → human audit report + "what's my EU-AI-Act gap and the 3 steps to close it"; NL query over the weakness→control→skill graph | CISOs pay for the narrative, not the JSON. High-margin enterprise polish. |

## 5. The flywheel (why this compounds, not just adds)
```
 more users → more candidate findings → LLM auto-verify (AI #1) scales the gate
        ↑                                              │
        │                                              ▼
 herd immunity (sync down) ← verified DB grows ← signed into canon
        │                                              │
        └──── better DB → grounds LLM taint/remediation (AI #2,#3) → lower FP → more trust → more users
```
AI makes the moat compound *faster*; the moat makes the AI *more accurate than anyone's*.
That coupling — not any single feature — is the billion-dollar mechanic.

## 6. What does NOT get you there (don't waste cycles)
- A chatbot / "ask our AI about your security." Gimmick.
- **LLM-only scanning with no DB** — FP-ridden commodity; we'd be one of fifty.
- More *horizontal* breadth forever — a feature race we lose to incumbents with bigger teams.
- Pure-OSS with no enterprise enforcement/compliance wedge — beloved, unmonetized.

## 7. Recommended sequence
**v1.1 contribution loop (LLM auto-verify = AI #1) → DQ-V.3 LLM-pruned taint (AI #2) →
enterprise compliance/enforcement (v2.0).** That's the order in which
AI-grounded-in-the-verified-DB turns into a flywheel — and the flywheel is the only thing
here an incumbent can't fork.

> **Honest caveat:** $1B outcomes also need distribution, capital, and timing — architecture
> is necessary, not sufficient. The architecture above is the one that *could* support it.
