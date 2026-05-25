---
id: ml-security
version: "1.0.0"
title: "ML / LLM Security"
description: "Prompt injection, model poisoning, deserialization attacks, PII in training data, secret leaks in notebooks"
category: prevention
severity: high
applies_to:
  - "when generating code that calls an LLM API or builds an LLM-driven agent"
  - "when generating code that loads ML models from disk / Hub / S3"
  - "when generating data pipelines that ingest user content for fine-tuning"
languages: ["python", "javascript", "typescript", "jupyter", "go"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2700
rules_path: "rules/"
related_skills: ["secret-detection", "supply-chain-security", "api-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP Top 10 for LLM Applications 2025"
  - "NIST AI 100-2 (Adversarial Machine Learning)"
  - "MITRE ATLAS (Adversarial Threat Landscape for AI Systems)"
  - "CWE-502, CWE-1039, CWE-1426"
---

# ML / LLM Security

## Rules (for AI agents)

### ALWAYS
- Treat every model input — including tool outputs and retrieved documents
  fed back into the prompt — as untrusted. Indirect prompt injection through
  a retrieved web page or document is the most common LLM attack in the
  wild.
- Sanitize and re-encode anything the model emits before feeding it to a
  downstream system: SQL builder, shell, file writer, HTTP request, code
  evaluator. Model output is never a primary key for trust.
- Enforce an **output schema** with structured generation (JSON Schema,
  function-call mode, constrained decoding) when the next step consumes the
  output programmatically. Reject anything that fails validation.
- Maintain an allowlist of tools / function names a model can invoke; reject
  any other invocation. Apply per-tool authorization to the *human user* of
  the agent, not just the model.
- For RAG: stamp retrieved documents with provenance, and segregate
  "instructions" from "context" in the prompt; do not let retrieved data
  override system instructions.
- When loading models, use **safetensors** for PyTorch and Hugging Face; use
  `weights_only=True` with `torch.load` on PyTorch 2.4+; never load
  arbitrary `.pkl` / `.pt` files from untrusted sources.
- Scrub PII, credentials, and secrets from training data — at the source
  (data ingestion), at storage (encryption + access control), and at output
  (response filters / detectors).
- Rate-limit / quota every LLM-backed endpoint. Track per-tenant token
  spend.
- Track every prompt + model version + retrieved context as an audit log;
  redact secrets first.

### NEVER
- `pickle.loads` / `joblib.load` / `dill.loads` / `torch.load` an artifact
  fetched at runtime from an untrusted source. These deserializers execute
  arbitrary code by design.
- Concatenate user input directly into a prompt that contains higher-trust
  instructions: e.g. `f"You are a helpful agent. {user_input}"`. Use a
  templated boundary plus explicit system-role separation.
- Hand an LLM-derived string straight to `eval`, `exec`, `os.system`,
  `subprocess(shell=True)`, `vm.runInNewContext`, or a SQL `.raw()` call.
- Hard-code OpenAI / Anthropic / Cohere API keys in notebooks or repo
  files. Use environment variables and the `secret-detection` skill.
- Store training-data examples that contain PII in long-term storage
  without explicit consent, retention windows, and deletion APIs.
- Trust client-supplied model parameters (model name, system prompt, tool
  list) without server-side validation — clients will downgrade to
  cheaper / weaker / unauthorized models.
- Use a model fine-tuned by an external vendor without provenance / lineage
  verification.
- Cache LLM responses indexed only by prompt text — that mixes users'
  contexts when prompts share prefixes.

### KNOWN FALSE POSITIVES
- Research / red-team notebooks that intentionally exercise jailbreak prompts
  belong in an isolated environment without production credentials.
- Pre-publication academic models from trusted authors are often distributed
  as `.pt` checkpoints; convert to safetensors as a first step.
- Synthetic data generation pipelines may legitimately produce raw model
  output that's then committed — make sure it's labeled and reviewed for
  inadvertent PII / hallucinated secrets.

## Context (for humans)

The OWASP LLM Top 10 (2025) folds the most-common attacks into ten classes;
**LLM01 Prompt Injection** and **LLM05 Improper Output Handling** are the
top operational concerns because they apply to virtually every agentic
deployment. NIST AI 100-2 frames the underlying adversarial ML categories
(evasion, poisoning, extraction); MITRE ATLAS provides a kill-chain view.

This skill assumes Devin (or any AI assistant) is the one building the
LLM-using app. Treat the resulting app as a security boundary — even when
the "user" is another AI agent.

## References

- `rules/prompt_injection_patterns.json`
- `rules/unsafe_deserialization.json`
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/).
- [NIST AI 100-2](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2023.pdf).
- [MITRE ATLAS](https://atlas.mitre.org/).
- [CWE-1426](https://cwe.mitre.org/data/definitions/1426.html) — Improper Validation of Generative AI Output.
