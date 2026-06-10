# CLAUDE.md — project context for vibe-guard

> Companion to `AGENTS.md` (which holds hard agent rules). This file is durable product/strategy context. See `BACKLOG.md` and `ROADMAP.md` for live work.

## What this is
**vibe-guard** — open-core, **prevention-first** security framework for AI-written code.
- Go module `github.com/namncqualgo/skills-library` · CLI `skills-check` · command `gate` · MIT.
- **Two enforcement points:** (1) gen-time **PREVENTION** — signed skills feed AI assistants so they write secure code; (2) CI-time **BLOCK** — `gate` fails the build at a severity floor.
- Offline, zero-telemetry, deterministic, Ed25519-signed. **Not** an auto-fixer, **not** a detector, **no** cloud LLM in the tool.

## Naming (avoid confusion)
Product brand evolved Qualgo → secure-code / SkillShield → vibe-gate → **vibe-guard** (current). "vibe-gate" was dropped (collided with "prompt gate"). **secure-edge** (a runtime prompt gate) was **removed** from positioning — do not reintroduce it.

Brand hierarchy: **ShieldNet360** = ecosystem umbrella · **vibe-guard** = the OSS framework (product) · **Cloud** = the commercial control plane (fleet policy, private signed registry, freshness SLA, compliance attestation, SSO/RBAC/on-prem).

⚠️ **Functional identifiers are NOT renamed yet** and must stay until the GitHub org is renamed at the platform level: the Go module path `github.com/namncqualgo/skills-library`, the CLI name `skills-check`, repo/pages URLs (`namncqualgo.github.io`), and the winget package id. Don't "fix" these to vibe-guard — they're real and load-bearing. The vibe-guard rename is a **prose/marketing** change only.

## Positioning — "left of the cursor"
The next shift-left. Ladder: Gen 1 Production (DAST·pentest·WAF) → Gen 2 CI (SAST) → Gen 3 IDE (SonarLint) → **Gen 4 Generation (vibe-guard)**. We own the surface that only existed once AI started writing code.
- **Sonar analogy:** GTM *shape* mirrors SonarLint→SonarQube's open-core funnel; live before the code exists (where Sonar can't reach) and treat detectors as downstream verifiers, not rivals.
- **Shift-left economics:** the earlier a risk is removed, the cheaper it is and the less ever ships → owning the leftmost edge removes the most risk at the lowest cost → **more shift-left = more risk reduced = the bigger the prize.**
- **Competitive landscape:** everyone else secures *how the AI behaves* (NVIDIA NeMo Guardrails/garak, Microsoft PyRIT/Content Safety = runtime; Cisco AI Defense/skill-scanner = post-hoc artifact scan). vibe-guard secures *what the AI builds* — the code — at generation-time + CI. Mostly complementary, not competitive.

## Moat guardrails (don't break these)
No cloud LLM/AST in-tool · no auto-fix · no CVE/SCA sprawl · never paywall a security fix · eval-gated not taste-gated contributions. Open-core discipline: free is a complete product for one team; paid is born at org scale, never a crippled free tier. Biggest risk = drifting into the crowded post-hoc-scanner lane.

## Git / safety
Never commit or push unless explicitly asked. Committing framework work requires `gh auth switch --user namncqualgo` + explicit go-ahead. Never `--no-verify`, never force-push main. Never fabricate sources/CVEs/advisory URLs/compliance mappings (see `AGENTS.md`).
