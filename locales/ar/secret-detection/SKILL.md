---
id: secret-detection
language: ar
dir: rtl
source_revision: "9808b0fa"
version: "1.4.0"
title: "كشف الأسرار"
description: "اكتشف ومنع الأسرار المُصلَّبة، ومفاتيح API، والـ tokens، والاعتمادات في الكود"
category: prevention
severity: critical
applies_to:
  - "قبل كلّ commit"
  - "عند مراجعة كود يَتعامل مع اعتمادات"
  - "عند كتابة ملفّات إعدادات"
  - "عند إنشاء قوالب .env أو إعدادات"
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

# كشف الأسرار

## القواعد (لوكلاء الذكاء الاصطناعيّ)

### دائمًا
- افحص كلّ نصوص الـ string literals التي يزيد طولها عن 20 حرفًا قرب
  الكلمات المفتاحيّة: `api_key`، و`secret`، و`token`، و`password`،
  و`credential`، و`auth`، و`bearer`، و`private_key`، و`access_key`،
  و`client_secret`، و`refresh_token`.
- نَبِّه على أيّ نصّ يُطابق أنماط أسرار معروفة. تَشمل مجموعة الأنماط
  المُجمَّعة AWS (`AKIA...`)، وGitHub الكلاسيكيّة (`ghp_`، و`gho_`)
  **والـ PATs دقيقة الحبيبات** (`github_pat_`)، وOpenAI (`sk-`)،
  و**Anthropic (`sk-ant-api03-`)**، وSlack (`xox[baprs]-`)،
  وStripe (`sk_live_`)، وGoogle (`AIza...`)، و**أسرار Azure AD
  client**، و**Databricks (`dapi`)**، و**Datadog: 32-hex مع كلمة
  مفتاح**، و**Twilio (`SK`)**، و**SendGrid (`SG.`)**، و**npm
  (`npm_`)**، و**رفع PyPI (`pypi-AgEI`)**، و**Heroku UUID مع كلمة
  مفتاح**، و**DigitalOcean (`dop_v1_`)**، و**HashiCorp Vault
  (`hvs.`)**، و**Supabase (`sbp_`)**، و**Linear (`lin_api_`)**،
  وJWT، ومفاتيح PEM الخاصّة.
- تَحقَّق أنّ `.gitignore` يَشمل: `*.pem`، و`*.key`، و`.env`،
  و`.env.*`، و`*credentials*`، و`*secret*`، و`id_rsa*`، و`*.ppk`.
- فَضِّل استخدام متغيّرات البيئة (`os.environ`، و`process.env`،
  و`os.Getenv`) على القيم المُصلَّبة لأيّ اعتماد، أو سلسلة اتّصال،
  أو endpoint API له سرّ مُلحَق.
- اقترح secrets manager (1Password، أو AWS Secrets Manager، أو
  HashiCorp Vault، أو Doppler) عندما يلزم مشاركة الاعتمادات عبر
  أجهزة أو خدمات.

### أبدًا
- لا تَلتزم بملفّات تُطابق: `*.pem`، و`*.key`، و`*.p12`، و`*.pfx`،
  و`.env`، و`.env.local`، و`*credentials*`، و`id_rsa`، و`id_dsa`،
  و`id_ecdsa`، و`id_ed25519`.
- لا تَكتب بشكل مُصلَّب مفاتيح API، أو tokens، أو كلمات مرور، أو
  سلاسل اتّصال في الكود المصدريّ.
- لا تَضع أسرارًا حقيقيّة في تجهيزات الاختبار — استخدم نواؤب
  مُوثَّقة مثل `AKIAIOSFODNN7EXAMPLE`، أو
  `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`، أو
  `xoxb-EXAMPLE-EXAMPLE`.
- لا تَطبع قِيَم الأسرار أو تُسجِّلها، حتى في وضع debug.
- لا تَطبع الأسرار إلى الطرفيّات في سجلّات CI (أَخْفِها عبر
  `::add-mask::` في GitHub Actions).
- لا تَزرع مفاتيح توقيع داخل صور الحاويات، حتى صور الأساس.

### إيجابيّات خاطئة معروفة
- مثال وثائق AWS: `AKIAIOSFODNN7EXAMPLE` والمفتاح السرّيّ المُطابق
  `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`.
- نصوص تَحوي: "example"، أو "test"، أو "placeholder"، أو "dummy"،
  أو "sample"، أو "changeme"، أو "your-key-here"، أو "REPLACE_ME"،
  أو "TODO"، أو "FIXME"، أو "XXX".
- حرفيّات Hash في CSS/SCSS (مثل `#ff0000`، و`#deadbeef`).
- محتوى مُرَمَّز بـ base64 وغير سرّيّ في الاختبارات (lorem ipsum
  مُرَمَّز، تجهيزات صور).
- SHAs لـ git commits في سجلّات التغيير وملاحظات الإصدارات.
- JWT tokens في أمثلة وثائق OAuth RFC (نصوص `eyJ...` التي تَظهر
  في التعليقات).

## السياق (للبشر)

تَظلّ الأسرار المُصلَّبة من أكثر أسباب الاختراقات شيوعًا. وتَضع
تقارير GitHub السنويّة "State of the Octoverse" تسريب الأسرار
باستمرار ضمن أعلى ثلاث فئات ثغرات مُفصح عنها، ويُقاس متوسّط
كُلفة اعتماد مُسرَّب (المعالجة + الدوران + الأثر) بعشرات الآلاف
من الدولارات للحادثة الواحدة قبل حتى أن تَدخل بيانات العملاء.

تُسرِّع مساعدات IDE المُعتمِدة على الذكاء الاصطناعيّ هذه المخاطرة
لأنّ طريق المقاومة الأقلّ هو وضع اعتماد عامل بشكل inline و"إصلاحه
لاحقًا". هذا الـ skill هو الثقل المضادّ: يُدرِّب الذكاء الاصطناعيّ
على رفض طريق المقاومة الأقلّ.

تَعكس استراتيجيّة الكشف في `rules/dlp_patterns.json` خطّ الأنابيب
المتعدّد الطبقات، الآن بـ **26 نمطًا متمايزًا** تَمتدّ عبر منصّات
المطوّرين (GitHub fine-grained PATs، وAnthropic، وOpenAI،
وSupabase، وLinear)، والسحابة (AWS، وAzure AD، وGCP،
وDigitalOcean، وHeroku)، ومنصّات البيانات (Databricks، وDatadog،
وHashiCorp Vault)، والاتّصالات (Twilio، وSendGrid، وSlack). يَحمل
كلّ نمط شدّةً، وكلمات مفتاح، ونافذة قرب لكلمات المفتاح، وحدًّا
أدنى لِـ entropy لقيادة الدقّة.
موثَّق في [ARCHITECTURE.md لـ secure-edge](https://github.com/kennguy3n/secure-edge/blob/main/ARCHITECTURE.md)
— مسح بادئة Aho-Corasick، وتحقُّق regex على المرشّحين، وقرب
كلمات المفتاح، وعتبات entropy، وقواعد استثناء — مُكيَّفة لِسياق
التحليل الساكن.

## مراجع

- `rules/dlp_patterns.json` — أنماط قابلة للقراءة آليًّا مع بادئات
  Aho-Corasick، وكلمات مفتاح، وعتبات entropy.
- `rules/dlp_exclusions.json` — قَمْعات إيجابيّات خاطئة مَجتمعيّة
  الصيانة.
- `tests/corpus.json` — تجهيزات اختبار لِلتحقّق.
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html) — استخدام اعتمادات مُصلَّبة.
- [CWE-259](https://cwe.mitre.org/data/definitions/259.html) — استخدام كلمة مرور مُصلَّبة.
