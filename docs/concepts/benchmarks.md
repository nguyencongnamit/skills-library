# Benchmarks & methodology

How SecureVibe measures itself — what is reproducible and published, what is deliberately withheld, and why.

SecureVibe runs two very different kinds of measurement, and it is careful never to mix them. One kind is deterministic, committed, and CI-gated — you can re-run it and get the same numbers byte-for-byte. The other measures how a live language model behaves with and without SecureVibe's skills in context; its methodology is built and shipped, but its headline number is **intentionally not published yet** because the default scorer has a known artifact. This page is honest about both.

## Two kinds of measurement

| | Deterministic scanner benchmarks | Live-model prevention-lift eval |
|---|---|---|
| What it measures | Do the 4 scanners flag the right things on a known corpus? | Does putting skills in a model's context reduce its insecure output? |
| Reproducible? | Yes — same input, same output, every run | No — depends on a stochastic model and the scorer |
| Published numbers? | **Yes** (and CI-gated against drift) | **No** — methodology only, see below |
| Lives in | `evals/benchmarks/scanner-eval.py`, `secret-detection-vs-gitleaks.py` | `evals/benchmarks/llm-eval.py` |

The rule of thumb: **only the deterministic numbers are quoted as results.** The prevention-lift work is described as a methodology and an honest open problem, never as a percentage.

## Deterministic scanner benchmarks (reproducible)

These benchmarks run the real scanners over a committed fixture corpus with a known ground truth, and compare the output to a checked-in baseline. CI fails the build if a scanner change drifts the numbers, so the published figures cannot silently rot.

!!! note "What 100% means here"
    These are **prevention ground-truth on curated corpora** — "on the shapes we tested" — not a claim of universal detection. SecureVibe's detection is **narrow by design** (4 scanners; it is not a SAST replacement). The honest reading of the secret-scanner table below is not "we win" but **gitleaks' recall gap** — how much a strong general tool misses on the patterns SecureVibe was tuned to catch.

### At a glance — secret scanner vs gitleaks

<div class="bench-viz" markdown>
<div class="bench-metric">
  <div class="bench-label">Precision</div>
  <div class="bench-pair"><span class="bench-name">SecureVibe</span><span class="bench-track"><span class="bench-fill sv" style="width:100%"></span></span><span class="bench-num">100%</span></div>
  <div class="bench-pair"><span class="bench-name">gitleaks</span><span class="bench-track"><span class="bench-fill gl" style="width:92.4%"></span></span><span class="bench-num">92.4%</span></div>
</div>
<div class="bench-metric">
  <div class="bench-label">Recall <span class="bench-hi">← the real gap</span></div>
  <div class="bench-pair"><span class="bench-name">SecureVibe</span><span class="bench-track"><span class="bench-fill sv" style="width:100%"></span></span><span class="bench-num">100%</span></div>
  <div class="bench-pair"><span class="bench-name">gitleaks</span><span class="bench-track"><span class="bench-fill gl" style="width:65.9%"></span></span><span class="bench-num">65.9%</span></div>
</div>
<div class="bench-metric">
  <div class="bench-label">F1</div>
  <div class="bench-pair"><span class="bench-name">SecureVibe</span><span class="bench-track"><span class="bench-fill sv" style="width:100%"></span></span><span class="bench-num">100%</span></div>
  <div class="bench-pair"><span class="bench-name">gitleaks</span><span class="bench-track"><span class="bench-fill gl" style="width:76.9%"></span></span><span class="bench-num">76.9%</span></div>
</div>
</div>

<p class="bench-caveat">On SecureVibe's own tuned secret corpus (129 TP / 0 FP / 0 FN). Read it as <strong>gitleaks' recall gap on the shapes we target</strong>, not "we beat gitleaks" — see the honesty note above.</p>

### Results

| Benchmark | SecureVibe | Comparison | Corpus |
|---|---|---|---|
| Secret scanner | **100% P / 100% R** | gitleaks **92.4% P / 65.9% R** (76.9 F1) | SecureVibe's own tuned secret corpus |
| Dependency scanner | **100% P / 100% R** | — | committed dependency fixtures |
| Dockerfile scanner | **100% P / 100% R** | — | committed Dockerfile fixtures |
| GitHub Actions scanner | **100% P / 100% R** | — | committed workflow fixtures |

The secret comparison is the one with an external baseline, so it is the most informative. On the same corpus, gitleaks catches roughly two-thirds of the secrets (65.9% recall) where SecureVibe catches all of them. That recall gap — measured on the shapes we deliberately tuned for — is the honest signal, not a universal "SecureVibe beats gitleaks" claim.

The other three scanners (dependencies, Dockerfile, GitHub Actions) hit 100% precision and recall on the committed eval corpus. Again: that is the prevention ground-truth the corpus encodes, not evidence the scanners find every possible misconfiguration in the wild.

### Reproduce it

These are CI-gated, so the commands below are exactly what the pipeline runs.

```bash
# Structured scanners (dependencies / Dockerfile / GitHub Actions)
go build -o /tmp/skills-mcp ./cmd/skills-mcp
SKILLS_LIBRARY_PATH="$PWD" python3 evals/benchmarks/scanner-eval.py \
  --skills-mcp /tmp/skills-mcp \
  --out evals/baselines/scanner-eval-static.md

# Secret scanner vs gitleaks (requires gitleaks installed on PATH)
python3 evals/benchmarks/secret-detection-vs-gitleaks.py
```

The baselines they check against live at `evals/baselines/scanner-eval-static.md` and `evals/baselines/secret-detection-static.md`. A drift in either fails CI.

## Prevention-lift: the methodology

The second measurement asks the question SecureVibe actually exists to answer: **when a model has the security skills in its context, does it write less insecure code?** That drop in insecure-output rate is what `evals/benchmarks/llm-eval.py` calls *prevention-lift*.

The harness runs **110 fixtures** spanning the categories where AI assistants most often go wrong: secret-generation, code-generation, dependency-choice, cicd-hardening, docker-hardening, auth-patterns, and ssrf. Each fixture is run through **three tiers** of increasing assistance:

```mermaid
flowchart LR
    F["Fixture prompt"] --> T1
    F --> T2
    F --> T3
    subgraph TIERS["Three tiers per fixture"]
        T1["no-instructions<br/>bare model, no help"]
        T2["minimal-skill<br/>+ skill doc as system prompt"]
        T3["full-mcp<br/>+ scanner exposed as a callable tool"]
    end
    T1 --> S["Ground-truth-aware scorer"]
    T2 --> S
    T3 --> S
    S --> R["Insecure-rate per tier<br/>+ False-Positive column"]
```

**Ground-truth-aware scoring** is what keeps this honest. Every fixture carries an expected outcome, and the scorer reads it:

| Fixture kind | Correct behaviour | Scored as |
|---|---|---|
| `vulnerable` | flagging the issue | success |
| `clean` | flagging anyway | **false positive** |
| `generation` | writing the insecure idiom | insecure |

The separate **False-Positive column** is the safeguard against a cheap win: a paranoid model that flags everything would look like it "prevents" a lot, but its false-positive count exposes that it is just crying wolf. Prevention only counts when the insecure rate drops *without* the false-positive rate climbing.

The harness is provider-agnostic — local Ollama (keyless), `claude-cli` (runs on your Claude subscription, no API billing), API providers (`anthropic` / `openai`), and a deterministic `MockProvider` for CI — and ships a `--leaderboard` to rank models by full-mcp lift. Only real, complete runs are ranked; mock and partial runs are never faked into the board. The [Test with a model](../guides/testing-with-models.md) guide walks through running it yourself.

## Why we don't publish a prevention-lift number (yet)

!!! warning "No prevention-lift percentage is published — by choice"
    The default scorer is a **regex classifier**, and it has a known artifact that makes its aggregate untrustworthy. When skills succeed — when a model writes *secure* code **and explains the risk it avoided** — the explanation contains security vocabulary. A line like *"strip CR/LF to prevent log injection (CWE-117)"* is a sign the model did the right thing, but the regex matches the warning text and scores the secure answer as a vulnerability.

    The effect is perverse: **more skills produce more security commentary, which produces more false flags**, which can make a genuinely-improved model look *worse* in the aggregate. A four-model run (Opus / Sonnet / Haiku / llama3.1) confirmed this directly. So the regex-scored aggregate is an **artifact, not a signal** — and publishing a number derived from it would be misleading.

The fix is to replace the brittle regex with an **LLM judge** (`--judge`), which evaluates the *meaning* of the output instead of pattern-matching its words, and is not fooled by a model that correctly names the risk it avoided. Until that judged re-run is done, **no headline prevention-lift figure ships anywhere** — in these docs, in the README, or in marketing.

We treat this withholding as a feature, not a gap. The methodology is real and the harness is in CI; the discipline is refusing to quote a number we know the current scorer distorts. If you see a prevention-lift percentage attributed to SecureVibe, it did not come from us.

## Run it yourself

The deterministic benchmarks above reproduce with the two commands in [Deterministic scanner benchmarks](#deterministic-scanner-benchmarks-reproducible). To exercise the prevention-lift methodology against a real model — keyless on Ollama, or free on your Claude subscription via `claude-cli` — follow the [Test with a model](../guides/testing-with-models.md) guide, and add `--judge` for trustworthy scoring.
