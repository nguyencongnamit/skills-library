# Locale & language-support audit

**Last updated:** 2026-05-14
**Scope:** Audit the natural-language coverage of **secure-code** against
the user-supplied target set (top-10 world languages, GCC region, Southeast
Asia, Germany). Recommendations only — no code or content changes are
implemented in this audit.

---

## 1. What "locale" means in this repo

secure-code has **two** orthogonal language axes:

| Axis | Where | Purpose |
|---|---|---|
| **Programming languages** | `languages: ["go", "python", …]` in each SKILL.md frontmatter | Tells the validator / IDE config generators which file types each skill applies to. Not a natural-language signal. |
| **Natural languages** | `locales/<bcp47>/<skill-id>/SKILL.md` | Translated copies of the prose. The canonical English file under `skills/<id>/SKILL.md` is the source of truth; `locales/` is **informational** and not auto-loaded by the validator (see `locales/README.md`). |

Additionally, several rule files contain **English-only** signal:

| Source | English-only content | Implication if used in a non-English codebase |
|---|---|---|
| `skills/secret-detection/rules/dlp_patterns.json` | `hotwords: ["aws", "access_key", …]` | Lower recall when reviewing code/comments written in another language (e.g. a Spanish-speaking dev writes `clave_acceso` next to `AKIA…`). |
| Every `SKILL.md` prose body | "ALWAYS / NEVER / KNOWN FALSE POSITIVES" headings + bullets | An LLM consuming the compiled `SECURITY-SKILLS.md` in a non-English session may still follow the rules (the LLM translates internally), but downstream documentation and human reviewers don't get a localized artifact. |
| Rule-file `description`, `title`, `rationale`, `fix` fields | English | Same as above. |

This audit covers the **natural-language** axis only.

---

## 2. Current state (as of 2026-05-14)

Files under `locales/` (directly verified on disk):

```
locales/README.md
locales/de/infrastructure-security/SKILL.md
locales/de/secret-detection/SKILL.md
locales/de/supply-chain-security/SKILL.md
locales/es/infrastructure-security/SKILL.md
locales/es/secret-detection/SKILL.md
locales/es/supply-chain-security/SKILL.md
locales/fr/infrastructure-security/SKILL.md
locales/fr/secret-detection/SKILL.md
locales/fr/supply-chain-security/SKILL.md
```

That is **3 locales × 3 skills = 9 translated files**, out of a possible
**N locales × 28 skills**.

| Metric | Current | Source of truth |
|---|---|---|
| Skills (canonical English) | **28** | `skills/<id>/SKILL.md` |
| Locales present | **3** — `de`, `es`, `fr` | `locales/<bcp47>/` |
| Skills translated per locale | **3** — `infrastructure-security`, `secret-detection`, `supply-chain-security` | filesystem walk |
| Translated `SKILL.md` files | **9** | filesystem walk |
| Coverage ratio | **9 / (28 × ?)** ≈ negligible for any non-English target | — |
| Translated **rule files** | **0** — `locales/*` contains only `SKILL.md` prose | — |
| Translated **hotwords** in `dlp_patterns.json` | **0** | inspection |
| Translated **compliance / CWE / OWASP mapping yaml** | **0** | inspection |

The `locales/` tree is purely a prose-translation surface for three
flagship skills. No rule-file logic, no hotwords, no checklist titles, and
no CWE/OWASP labels are translated.

---

## 3. Target language set

Per the request:

### 3.1 Top-10 by total speakers (L1 + L2)

Approximate ordering per Ethnologue 26th ed. (2023) and Wikipedia
"List of languages by total number of speakers":

| Rank | Language | BCP-47 tag | Currently in `locales/`? |
|---:|---|---|---|
| 1 | English | `en` | n/a — canonical, source of truth |
| 2 | Mandarin Chinese | `zh-Hans` (Simplified) / `zh-Hant` (Traditional) | **No** |
| 3 | Hindi | `hi` | **No** |
| 4 | Spanish | `es` | **Yes (3/28 skills)** |
| 5 | French | `fr` | **Yes (3/28 skills)** |
| 6 | Modern Standard Arabic | `ar` | **No** |
| 7 | Bengali | `bn` | **No** |
| 8 | Portuguese | `pt` / `pt-BR` / `pt-PT` | **No** |
| 9 | Russian | `ru` | **No** |
| 10 | Urdu | `ur` | **No** |

(Sources vary: some lists swap Bengali/Portuguese, or include
Indonesian/Japanese in the top-10. The audit recommendations below
default to the table above.)

### 3.2 GCC region (Gulf Cooperation Council)

All six member states are predominantly Arabic-speaking (Gulf dialect),
with extensive English in business/government.

| Country | Primary tag | Secondary tag(s) | Currently in `locales/`? |
|---|---|---|---|
| Saudi Arabia | `ar-SA` | `en-SA` | **No** |
| United Arab Emirates | `ar-AE` | `en-AE` | **No** |
| Qatar | `ar-QA` | `en-QA` | **No** |
| Kuwait | `ar-KW` | `en-KW` | **No** |
| Bahrain | `ar-BH` | `en-BH` | **No** |
| Oman | `ar-OM` | `en-OM` | **No** |

For technical documentation, **Modern Standard Arabic (`ar`)** is the
single practical translation target. Gulf-dialect spelling differences
matter for marketing copy, not for security rule files. RTL formatting is
the bigger concern.

### 3.3 South-East Asia (ASEAN scope)

| Country | Primary language | BCP-47 tag | Currently in `locales/`? |
|---|---|---|---|
| Indonesia | Indonesian | `id` | **No** |
| Malaysia | Malay | `ms` | **No** |
| Singapore | English (de facto) | `en-SG` | n/a |
| Brunei | Malay / English | `ms-BN` / `en-BN` | **No** |
| Philippines | Filipino / English | `fil` / `en-PH` | **No** |
| Vietnam | Vietnamese | `vi` | **No** |
| Thailand | Thai | `th` | **No** |
| Cambodia | Khmer | `km` | **No** |
| Laos | Lao | `lo` | **No** |
| Myanmar | Burmese | `my` | **No** |

### 3.4 Germany

| Country | Primary language | BCP-47 tag | Currently in `locales/`? |
|---|---|---|---|
| Germany | German | `de` | **Yes (3/28 skills)** |
| Germany | German (Austria) | `de-AT` | n/a (covered by `de`) |
| Germany | German (Switzerland) | `de-CH` | n/a (covered by `de`) |

`de` exists today. The gap is **breadth** — only 3 of 28 skills are
translated, and none of the rule files / checklists / mappings.

---

## 4. Gaps

### 4.1 Headline gap matrix

Cells = number of translated `SKILL.md` files / 28 canonical skills.

| Language | BCP-47 | Today | Top-10 | GCC | SE Asia | DE |
|---|---|---:|:---:|:---:|:---:|:---:|
| English | `en` | 28/28 | ✓ | ✓ | ✓ | ✓ |
| Spanish | `es` | 3/28 | ✓ | | | |
| French | `fr` | 3/28 | ✓ | | | |
| German | `de` | 3/28 | | | | ✓ |
| Mandarin (Simplified) | `zh-Hans` | 0/28 | ✓ | | | |
| Mandarin (Traditional) | `zh-Hant` | 0/28 | ✓ | | | |
| Hindi | `hi` | 0/28 | ✓ | | | |
| Arabic (MSA) | `ar` | 0/28 | ✓ | ✓ | | |
| Bengali | `bn` | 0/28 | ✓ | | | |
| Portuguese (Brazilian) | `pt-BR` | 0/28 | ✓ | | | |
| Portuguese (European) | `pt-PT` | 0/28 | ✓ | | | |
| Russian | `ru` | 0/28 | ✓ | | | |
| Urdu | `ur` | 0/28 | ✓ | | | |
| Indonesian | `id` | 0/28 | | | ✓ | |
| Malay | `ms` | 0/28 | | | ✓ | |
| Filipino | `fil` | 0/28 | | | ✓ | |
| Vietnamese | `vi` | 0/28 | | | ✓ | |
| Thai | `th` | 0/28 | | | ✓ | |
| Khmer | `km` | 0/28 | | | ✓ | |
| Lao | `lo` | 0/28 | | | ✓ | |
| Burmese | `my` | 0/28 | | | ✓ | |

Total unique target locales (excluding English): **20** (counting
`zh-Hans` and `zh-Hant` separately; `pt-BR` and `pt-PT` separately).
Reasonable practical target after deduplication: **18 locales** if you
collapse one Chinese script and one Portuguese variant.

### 4.2 Coverage-breadth gap

Even for the three locales that do exist, only **3 / 28 = 10.7%** of
skills are translated. The 25 missing translations per language are:

```
api-security                  ml-security
auth-security                 mobile-security
cicd-security                 protocol-security
compliance-awareness          saas-security
container-security            secure-code-review
cors-security                 serverless-security
crypto-misuse                 ssrf-prevention
database-security             websocket-security
dependency-audit              deserialization-security
error-handling-security       file-upload-security
frontend-security             graphql-security
iac-security                  iam-best-practices
logging-security
```

### 4.3 Coverage-depth gap (non-prose surfaces)

The bigger gap is that translation today **stops at SKILL.md prose**.
For a non-English user of the library, the following are still English-only
across **every** locale:

- All `rules/*.json` content (`title`, `rationale`, `fix`, `description`).
- All `checklists/*.yaml` content.
- All `rules/dlp_patterns.json` `hotwords` arrays.
- All `frameworks/cwe_mapping.yaml` and `frameworks/owasp_mapping.yaml`
  human-readable names (CWE-IDs are universal, but the explanatory
  fields are not).
- The compiled `SECURITY-SKILLS.md` distribution under `dist/`.
- The validator/CLI output strings (`go run ./cmd/skills-check …`).

For an Arabic-speaking team using secure-code, the impact of having
`locales/ar/secret-detection/SKILL.md` translated would still leave them
reading every rule, every CVE write-up, every CLI message in English.

### 4.4 Hotword-recall gap

`secret-detection`'s DLP regexes lean on hotwords for both **scoring** and
(for many patterns) **gating** (`require_hotword: true`). The current
hotword sets are exclusively English:

| Pattern | Hotwords (excerpt) |
|---|---|
| AWS Access Key | `aws, access_key, credentials, iam, secret` |
| BambooHR API Key | `bamboohr, api_key, hris` |
| Workday RaaS | `myworkday.com, customreport2, raas` |

A Spanish-speaking developer who writes `clave_acceso_aws` in a comment
above an `AKIA…` key still triggers the regex but **not** the hotword
boost, so the score may fall below the alerting threshold. Same problem
for `كلمة_السر` (Arabic), `密钥` (Chinese), `senha` (Portuguese), etc.

---

## 5. Recommendations

These are scoped recommendations only — no implementation in this PR per
the request ("audit report only").

### 5.1 Prioritization

Three tiers, in order of return-on-effort:

**Tier 1 — Highest leverage (machine-readable, broad impact):**
1. **Localize hotwords** in `skills/secret-detection/rules/dlp_patterns.json`.
   Translate each English hotword to the top-10 target languages
   (transliteration where the script differs from Latin). Concretely:
   - Maintain a sidecar `dlp_patterns.locales.json` mapping each English
     hotword to its multilingual equivalents.
   - At compile time, merge the locale arrays into each pattern's
     `hotwords` field so detection recall improves with no code change
     to the validator.
   - Optional: keep a separate `hotwords_by_locale` field so consumers
     can filter by language if recall vs. precision matters.

2. **Add a `language` axis to the manifest** so `manifest.json` records
   the BCP-47 tag of every translated file alongside its checksum. This
   lets downstream consumers (IDE plugins, AI agents) request the
   compiled bundle in their locale.

3. **Auto-generate a stub `locales/<tag>/<skill>/SKILL.md`** for every
   `(locale, skill)` cell that is empty. Stub contains the English
   text plus a `language: <tag>` frontmatter field and a top banner
   `> TRANSLATION PENDING — English original below`. This makes the
   coverage matrix visible in the filesystem and gives translators
   concrete files to claim.

**Tier 2 — High leverage (human-readable, narrow impact):**

4. **Translate the three flagship skills** (`secret-detection`,
   `supply-chain-security`, `infrastructure-security`) into the missing
   top-10 + GCC + SE-Asia + DE locales. Reuse the same translation
   workflow as the existing `de`/`es`/`fr` translations.

5. **Translate the `saas-security` SKILL.md** (added in this PR) into
   the same locales. SaaS security questions disproportionately come
   from non-English-speaking ops teams.

6. **Translate `rules/*.json` `title` / `rationale` / `fix` fields**
   into the same locales. Mechanism: sidecar `rules/<file>.<bcp47>.json`
   with only the translated fields; merged at compile time.

**Tier 3 — Lower leverage (operational):**

7. **Translate `compliance-awareness/frameworks/cwe_mapping.yaml` and
   `owasp_mapping.yaml` `name` and `description` fields.** CWE-IDs are
   universal, so translation is incremental on top of the existing
   structure.

8. **Translate the compiled `dist/SECURITY-SKILLS.md`** by running the
   regenerate step per locale and emitting `dist/SECURITY-SKILLS.<bcp47>.md`.

9. **Localize the CLI output strings** (`cmd/skills-check`) via Go's
   `golang.org/x/text/message` package. Lowest priority — developers
   running the CLI already read English error messages.

### 5.2 Concrete language list to commit to

Practical 18-locale target set after deduplication:

```
ar     bn     de     en (canonical)
es     fil    fr     hi
id     km     lo     ms
my     pt-BR  ru     th
ur     vi     zh-Hans
```

(Drop `zh-Hant`, `pt-PT`, and Gulf-Arabic variants on the first pass;
add them in a follow-up if Hong Kong / Portugal / Saudi-specific
customers ask.)

### 5.3 RTL & rendering considerations

`ar`, `ur`, and (partly) `fa` (if added) are right-to-left scripts. If
translated SKILL.md prose is rendered in any UI surface (IDE preview,
documentation site, generated PDF), the rendering pipeline must:

- Set `dir="rtl"` at the document level.
- Use a font stack with full Arabic-script coverage (e.g. Noto Naskh
  Arabic, Cairo) for `ar`/`ur`.
- Verify that code blocks (with LTR identifiers) inside an RTL document
  stay LTR by wrapping in `<bdo dir="ltr">` or markdown-flavor LTR
  isolators.

### 5.4 Translation workflow

To keep translations maintainable as English content evolves:

- Every translated SKILL.md should carry a `source_revision: <commit-sha>`
  frontmatter field pointing at the English commit it was translated
  from. CI can compare and flag stale translations on every PR.
- Use a translation memory / glossary file (e.g.
  `locales/glossary.<bcp47>.yaml`) so terms like "secret", "credential",
  "hotword", "least privilege" translate consistently across skills.
- Translators commit via PR; reviews from a native speaker + a security
  engineer (to catch term-of-art mistranslations like translating
  "JWT" or "RBAC" literally).

### 5.5 Out-of-scope for secure-code

- Translating CVE descriptions / public advisory text in
  `vulnerabilities/cve/`. Those are quoted from the upstream advisory
  and should stay in the advisory's original language.
- Translating third-party documentation URLs in `references` fields.
  Keep the upstream URL as published.

---

## 6. Summary

| Question | Answer |
|---|---|
| **Top-10 languages covered?** | Partially: `es` and `fr` only, and only 3/28 skills each. **8 of 10 are not translated at all.** |
| **GCC region covered?** | **No.** No Arabic translation exists. |
| **South-East Asia covered?** | **No.** No Indonesian, Malay, Vietnamese, Thai, Filipino, Khmer, Lao, or Burmese translations exist. |
| **Germany covered?** | **Partially.** `de` exists for 3/28 skills. Rules, checklists, mappings, and CLI output remain English. |
| **What's the cheapest first improvement?** | Localize **hotwords** in `dlp_patterns.json` — Tier 1.1 above. One JSON sidecar, one compile-time merge, improves recall for non-English codebases across every existing pattern. |
| **What's the biggest win?** | Tier 1.2 (manifest language axis) + Tier 2.4 (translate the three flagship skills + `saas-security` into the 14 missing target locales). |

No further changes are made in this PR for the locale axis. This audit
serves as the scoping document for a future multilingual rollout.
