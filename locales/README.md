# Localizations

This tree holds translated copies of selected `SKILL.md` files from
**secure-code**, intended for human review and downstream LLM use in
non-English contexts.

Translations are **informational** — they are not auto-loaded by the CLI.
The canonical English file under `skills/<id>/SKILL.md` remains the source
of truth for the validator, evidence reports, and IDE config generators.
See [`docs/LOCALE_AUDIT.md`](../docs/LOCALE_AUDIT.md) for the coverage
roadmap (top-10 world languages, GCC, Southeast Asia, Germany).

Initial coverage:

| Locale | Skills |
|---|---|
| `es` (Spanish) | secret-detection, supply-chain-security, infrastructure-security |
| `fr` (French)  | secret-detection, supply-chain-security, infrastructure-security |
| `de` (German)  | secret-detection, supply-chain-security, infrastructure-security |

Each translated SKILL.md keeps the same YAML frontmatter shape as the
English original, with the addition of a top-level `language: <bcp47>`
field.

To add a new locale or skill, copy the English SKILL.md into
`locales/<locale>/<skill-id>/SKILL.md`, translate the prose, set the
`language` field, and update this table.
