---
id: ml-security
version: "1.1.0"
title: "ML Model Security"
description: "Model artifact loading (pickle vs safetensors), model & data poisoning, PII in training data, secrets in notebooks, model provenance / lineage"
category: prevention
severity: high
applies_to:
  - "when generating code that loads ML models from disk / Hub / S3"
  - "when generating data pipelines that ingest user content for training / fine-tuning"
  - "when generating ML notebooks or training / evaluation scripts"
languages: ["python", "jupyter"]
token_budget:
  minimal: 700
  compact: 900
  full: 1800
rules_path: "rules/"
related_skills: ["llm-app-security", "secret-detection", "supply-chain-security", "deserialization-security"]
last_updated: "2026-06-04"
sources:
  - "NIST AI 100-2 (Adversarial Machine Learning)"
  - "MITRE ATLAS (Adversarial Threat Landscape for AI Systems)"
  - "CWE-502, CWE-1039, CWE-1395"
---

# ML Model Security

## Rules (for AI agents)

### ALWAYS
- When loading models, use **safetensors** for PyTorch and Hugging Face; use
  `weights_only=True` with `torch.load` on PyTorch 2.4+; never load arbitrary
  `.pkl` / `.pt` files from untrusted sources.
- Verify **provenance / lineage** of any third-party or externally fine-tuned
  model — known author, signed or hashed checkpoint, recorded source — before
  loading it.
- Pin and hash **model + dataset versions** and record them, so a poisoned
  artifact can be traced and rolled back.
- Scrub PII, credentials, and secrets from training / fine-tuning data — at the
  source (ingestion), at storage (encryption + access control), and in anything
  committed to the repo.
- Treat ML notebooks as code: no plaintext credentials in cells or cell output,
  and clear outputs before committing.

### NEVER
- `pickle.loads` / `joblib.load` / `dill.loads` / `torch.load` an artifact
  fetched at runtime from an untrusted source. These deserializers execute
  arbitrary code by design.
- Use a model fine-tuned or distributed by an external party without
  provenance / lineage verification.
- Store training-data examples that contain PII in long-term storage without
  explicit consent, retention windows, and deletion APIs.
- Hard-code OpenAI / Anthropic / Cohere API keys in notebooks or repo files.
  Use environment variables and the `secret-detection` skill.
- Commit synthetic or generated training data without labeling it and reviewing
  it for inadvertent PII or leaked secrets.

### KNOWN FALSE POSITIVES
- Pre-publication academic models from trusted authors are often distributed as
  `.pt` checkpoints; convert to safetensors as a first step rather than
  rejecting them outright.
- Synthetic data generation pipelines may legitimately produce raw model output
  that is then committed — make sure it is labeled and reviewed.

## Context (for humans)

NIST AI 100-2 frames the underlying adversarial-ML categories (evasion,
poisoning, extraction); MITRE ATLAS provides a kill-chain view. This skill
covers the **model and data artifacts** — how they are loaded, where they come
from, and what sensitive data they carry.

For securing an application *feature* that calls an LLM with prompts — prompt
injection, output handling, RAG context segregation, tool allowlists — see the
**`llm-app-security`** skill.

## References

- `rules/unsafe_deserialization.json`
- [NIST AI 100-2](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2023.pdf).
- [MITRE ATLAS](https://atlas.mitre.org/).
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html) — Deserialization of Untrusted Data.
- [CWE-1039](https://cwe.mitre.org/data/definitions/1039.html) — Inadequate Detection or Handling of Adversarial Input.
