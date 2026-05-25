# Translation glossaries

Each `locales/glossary.<bcp47>.yaml` defines the canonical translation
of a set of security terms of art for one locale. Translators MUST
use the listed translation for each term so the same English concept
is rendered the same way across every translated SKILL.md.

The list is small and high-signal: terms that are either ambiguous
across registers (e.g. "secret" vs "key" in Chinese) or commonly
mis-translated by general-purpose dictionaries (e.g. "least
privilege" → literal translations break the meaning).

## Schema

```yaml
schema_version: "1.0"
locale: "<bcp47>"
description: "<one-liner>"
terms:
  - english: "secret"
    translation: "<localized form>"
    notes: "<optional disambiguation>"
```

## What goes in a glossary

- Single concepts that recur in security skill prose (secret,
  credential, token, key, least privilege, RBAC, mutual TLS,
  hotword, false positive, …).
- Terms where the literal dictionary form would be wrong or
  ambiguous in this locale.
- Acronyms that translators may be tempted to expand (JWT, OAuth,
  CWE, CVE) — list them so they stay as the acronym.

## What does NOT go in a glossary

- Brand and product names: AWS, GitHub, Azure, npm, PyPI, Stripe.
  These stay in English everywhere.
- File-format identifiers: `package.json`, `requirements.txt`,
  `go.sum`. Code, not prose.
- Numeric identifiers: CWE-798, CVE-2022-42889. Untranslated.

## AI assistance disclosure

Initial drafts of these glossaries were authored by an AI assistant
under the AGENTS.md override accepted by the project owner for the
locale support roadmap. Each row must be reviewed by a native
speaker before it is treated as authoritative.
