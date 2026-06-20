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

## Coverage strategy — grow both axes + the contribution loop
The build steer (2026-06-19): strengthen **both axes simultaneously**, and stand up the engine that makes the library compound instead of going stale. Name the axis when proposing work — it keeps scope honest.
- **↔ Horizontal (breadth) — prevention's job.** More ecosystems (PHP/Dart/Swift/conda…), more artifact types (IaC: Terraform/k8s/Helm), more compliance frameworks (NIST SSDF, OWASP ASVS, SLSA, AI-RMF). Maximises breadth + freshness.
- **↕ Vertical (depth) — detection's job.** package-on-a-list → **reachability** (actually imported/called?) → vulnerable function reached on a tainted path → finding becomes a verified reproduction + suggested fix. Maximises certainty + actionability. **Depth rule: never rebuild generic static analysis — depth stays scoped to the verified, signed DB.** That scoping is what keeps false positives low and is uniquely ours.
- **⟳ The contribution loop (the engine) — LEARN, currently UPCOMING.** Two decoupled loops: `contribute --local` writes an instant private overlay so `gate` blocks immediately (**code never leaves the machine**); opt-in `contribute --submit` ships only a *generalised pattern* (never your source/secrets/identity), signed with your key, into an **untrusted candidate queue** → dedup → auto-verify (sandbox reproduce) → corroborate (OSV xref) → review → **sign into canon with our key only** → signed-delta `update` to everyone (herd immunity). Crowdsource the candidates, never the canon. The **signing key** and the **verification pipeline** stay centralised forever — they are what make our data trustworthy where a fork's scraped data isn't.
- **Five coverage dimensions** the axes move: breadth · depth · freshness · certainty · actionability.

## Verified surface (snapshot 2026-06-20)
PREVENT (signed skills) · DETECT (CLI + **16 MCP tools**, SARIF) · ENFORCE (`gate`, severity floor) are **built**. ANALYZE (analyzer/dataflow), VERIFY (agent reproduce), LEARN (contribution loop) are **UPCOMING** — no `contribute`/`analyze` command exists yet. Counts: **29 skills · 27 Sigma rules · 16 MCP tools · 43 Go test files**. Local gate is `./scripts/preflight.sh` (there is **no Makefile** — the internal Team Guide PDF's `make build/check/test/validate` and its friendly `scan`/`secret`/`check` verbs are aspirational; real verbs are `scan-dependencies`/`scan-secrets`/`check-dependency`, no unified `scan <path>` tree-walker). H1 → v1.0 GA (target 30 Jun): SARIF from `gate` + the Action→Code-Scanning upload are done; the **`eval --enforce` prevention-lift gate is now hard in both CI (`validate.yml`) and `preflight.sh`**, and **eval corpora cover 8 skills** (secret-detection, container-, cicd-, database-, crypto-misuse, ssrf-prevention, deserialization-security, cors-security — 25 cases, 100pt lift). Remaining H1: install (`brew`/`go`/`curl`) + `init` UX verification, and the prose branding sweep. Branch `build/sarif-from-gate`.

## Moat guardrails (don't break these)
No cloud LLM/AST in-tool · no auto-fix · no CVE/SCA sprawl · never paywall a security fix · eval-gated not taste-gated contributions. Open-core discipline: free is a complete product for one team; paid is born at org scale, never a crippled free tier. Biggest risk = drifting into the crowded post-hoc-scanner lane.

## Git / safety
Never commit or push unless explicitly asked. Committing framework work requires `gh auth switch --user namncqualgo` + explicit go-ahead. Never `--no-verify`, never force-push main. Never fabricate sources/CVEs/advisory URLs/compliance mappings (see `AGENTS.md`).
