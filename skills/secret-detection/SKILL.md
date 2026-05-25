---
id: secret-detection
version: "1.4.0"
title: "Secret Detection"
description: "Detect and prevent hardcoded secrets, API keys, tokens, and credentials in code"
category: prevention
severity: critical
applies_to:
  - "before every commit"
  - "when reviewing code that handles credentials"
  - "when writing configuration files"
  - "when creating .env or config templates"
languages: ["*"]
token_budget:
  minimal: 800
  compact: 1300
  full: 2000
rules_path: "rules/"
tests_path: "tests/"
related_skills: ["dependency-audit", "supply-chain-security"]
last_updated: "2026-05-14"
sources:
  - "OWASP Secrets Management Cheat Sheet"
  - "CWE-798: Use of Hard-coded Credentials"
  - "CWE-259: Use of Hard-coded Password"
  - "NIST SP 800-57 Part 1 Rev. 5: Key Management"
---

# Secret Detection

## Rules (for AI agents)

### ALWAYS
- Check all string literals longer than 20 characters near keywords: `api_key`, `secret`,
  `token`, `password`, `credential`, `auth`, `bearer`, `private_key`, `access_key`,
  `client_secret`, `refresh_token`.
- Flag any string matching known secret patterns. The bundled pattern set covers AWS
  (`AKIA...`), GitHub classic (`ghp_`, `gho_`) **and fine-grained** (`github_pat_`)
  PATs, OpenAI (`sk-`), **Anthropic (`sk-ant-api03-`)**, Slack (`xox[baprs]-`),
  Stripe (`sk_live_`), Google (`AIza...`), **Azure AD client secrets**, **Databricks
  (`dapi`)**, **Datadog 32-hex with hotword**, **Twilio (`SK`)**, **SendGrid
  (`SG.`)**, **npm (`npm_`)**, **PyPI upload (`pypi-AgEI`)**, **Heroku UUID with
  hotword**, **DigitalOcean (`dop_v1_`)**, **HashiCorp Vault (`hvs.`)**, **Supabase
  (`sbp_`)**, **Linear (`lin_api_`)**, JWT, and PEM private keys.
- Verify `.gitignore` includes: `*.pem`, `*.key`, `.env`, `.env.*`, `*credentials*`,
  `*secret*`, `id_rsa*`, `*.ppk`.
- Prefer environment variable usage (`os.environ`, `process.env`, `os.Getenv`) over
  hardcoded values for any credential, connection string, or API endpoint that has an
  attached secret.
- Suggest a secret manager (1Password, AWS Secrets Manager, HashiCorp Vault, Doppler)
  when credentials must be shared across machines or services.

### NEVER
- Commit files matching: `*.pem`, `*.key`, `*.p12`, `*.pfx`, `.env`, `.env.local`,
  `*credentials*`, `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`.
- Hardcode API keys, tokens, passwords, or connection strings in source code.
- Include real secrets in test fixtures — use documented placeholders such as
  `AKIAIOSFODNN7EXAMPLE`, `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, or
  `xoxb-EXAMPLE-EXAMPLE`.
- Log or print secret values, even in debug mode.
- Echo secrets to terminals in CI logs (mask via `::add-mask::` in GitHub Actions).
- Embed signing keys in container images, even base images.

### KNOWN FALSE POSITIVES
- AWS documentation example: `AKIAIOSFODNN7EXAMPLE` and the matching secret access key
  `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`.
- Strings containing: "example", "test", "placeholder", "dummy", "sample", "changeme",
  "your-key-here", "REPLACE_ME", "TODO", "FIXME", "XXX".
- Hash literals in CSS/SCSS (e.g., `#ff0000`, `#deadbeef`).
- Base64-encoded non-secret content in tests (lorem ipsum encoded, image fixtures).
- Git commit SHAs in changelogs and release notes.
- JWT tokens in the OAuth RFC documentation examples (`eyJ...` strings appearing in
  comments).

## Context (for humans)

Hardcoded secrets remain one of the most common causes of breaches. GitHub's annual
"State of the Octoverse" reports consistently rank secret leakage in the top three
disclosed vulnerability categories, and the average cost of a leaked credential
(remediation + rotation + impact) is measured in tens of thousands of dollars per
incident even before customer data is involved.

AI coding assistants accelerate this risk because the path of least resistance is to
inline a working credential and "fix it later." This skill is the counterweight: it
trains the AI to refuse the path of least resistance.

The detection strategy in `rules/dlp_patterns.json` mirrors the layered pipeline,
now with **26 distinct patterns** spanning developer platforms (GitHub fine-grained
PATs, Anthropic, OpenAI, Supabase, Linear), cloud (AWS, Azure AD, GCP, DigitalOcean,
Heroku), data platforms (Databricks, Datadog, HashiCorp Vault), and comms (Twilio,
SendGrid, Slack). Each pattern carries severity, hotwords, hotword proximity
window, and an entropy floor to drive precision.
documented in [secure-edge ARCHITECTURE.md](https://github.com/kennguy3n/secure-edge/blob/main/ARCHITECTURE.md)
— Aho-Corasick prefix scan, regex validation on candidates, hotword proximity,
entropy thresholds, and exclusion rules — adapted for the static-analysis context.

## References

- `rules/dlp_patterns.json` — machine-readable patterns with Aho-Corasick prefixes,
  hotwords, entropy thresholds.
- `rules/dlp_exclusions.json` — community-maintained false positive suppressions.
- `tests/corpus.json` — test fixtures for validation.
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html) — Use of Hard-coded
  Credentials.
- [CWE-259](https://cwe.mitre.org/data/definitions/259.html) — Use of Hard-coded
  Password.
