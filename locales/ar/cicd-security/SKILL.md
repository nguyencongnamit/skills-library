---
id: cicd-security
language: ar
dir: rtl
source_revision: "4c215e6f"
version: "1.0.0"
title: "أمن خطوط CI/CD"
description: "تصليب GitHub Actions و GitLab CI وما يماثلها ضد هجمات سلسلة التوريد، وتسريب الأسرار، وإساءة الاستخدام من نمط pwn-request"
category: prevention
severity: critical
applies_to:
  - "عند تأليف أو مراجعة ملفات سير العمل لـ CI/CD"
  - "عند إضافة action / image / script طرف ثالث إلى خط أنابيب"
  - "عند توصيل اعتمادات السحابة أو السجل بـ CI"
  - "عند فرز اشتباه باختراق خط أنابيب"
languages: ["yaml", "shell", "*"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "checklists/"
related_skills: ["supply-chain-security", "secret-detection", "container-security"]
last_updated: "2026-05-13"
sources:
  - "OpenSSF Scorecard — Pinned-Dependencies / Token-Permissions"
  - "SLSA v1.0 Build Track"
  - "GitHub Security Lab — Preventing pwn requests"
  - "StepSecurity — tj-actions/changed-files attack analysis"
  - "CWE-1395: Dependency on Vulnerable Third-Party Component"
---

# أمن خطوط CI/CD

## القواعد (لوكلاء الذكاء الاصطناعي)

### دائمًا
- ثبّت كل GitHub Action تابع لطرف ثالث بـ **SHA الـ commit** (الـ 40 محرفًا
  كاملةً)، لا بـ tag — الـ tags يمكن إعادة دفعها. ينطبق الأمر نفسه على
  مراجع `include:` في GitLab CI وعلى الـ reusable workflows. أدوات
  Renovate / Dependabot قادرة على تحديث تثبيتات الـ SHA باستمرار.
- صرّح `permissions:` على مستوى الـ workflow أو الـ job، واجعل الافتراضي
  `contents: read` فقط. امنح أي نطاقات إضافية (`id-token: write`،
  `packages: write` إلخ) job-by-job، لا على مستوى الـ workflow كله.
- استخدم **OIDC** (`id-token: write` + سياسة ثقة عند مزود السحابة)
  للحصول على اعتمادات سحابة قصيرة العمر. لا تخزّن مفاتيح AWS / GCP /
  Azure طويلة العمر كأسرار GitHub Secrets أبدًا.
- عامِل `pull_request_target` و`workflow_run` وأي job من `pull_request`
  يستخدم `actions/checkout` مع
  `ref: ${{ github.event.pull_request.head.ref }}` كـ **سياق موثوق فوق
  شيفرة غير موثوقة**. إما أن لا تشغّلها، أو شغّلها بلا أسرار وبلا رموز
  بصلاحية كتابة.
- مرّر أي تعبير غير موثوق (`${{ github.event.* }}`) عبر متغيّر بيئة أولًا؛
  لا تُضمّنه مباشرةً داخل جسم `run:` — هذا هو sink الـ script-injection
  الأشهر في GitHub Actions.
- وقّع مواد الإصدار (Sigstore / cosign) وانشر شهادات provenance لـ SLSA.
  تحقق من الـ provenance في أي خط أنابيب مستهلك يجلب المادة.
- اضبط `runs-on` على صورة runner مُصلَّبة وثبّت إصدار الـ runner. يُنصح
  باستخدام StepSecurity Harden-Runner بوضع audit (أو جدار egress مكافئ)
  لأي workflow يتعامل مع أسرار.
- عامِل `npm install` و`pip install` و`go install` و`cargo install`
  و`docker pull` المستدعاة داخل CI على أنها تنفيذ شيفرة غير موثوقة. شغّلها
  بـ `--ignore-scripts` (npm/yarn)، مع lockfiles مثبّتة، وقوائم سماح لسجل
  الحزم، ورموز ذات أدنى صلاحيات لكل job.

### أبدًا
- لا تثبّت action طرف ثالث بـ tag متحرّك (`@v1`، `@main`، `@latest`).
  حادثة tj-actions/changed-files في مارس 2025 سرّبت أسرارًا من أكثر من
  23,000 مستودع تحديدًا لأن المستهلكين استخدموا tags متحرّكة.
- لا تستخدم `curl | bash` (أو `wget -O- | sh`) لأي سكربت تثبيت داخل CI.
  اختراق رافع bash الخاص بـ Codecov في 2021 سرّب env vars إلى مهاجم خلال
  ~10 أسابيع لأن آلاف خطوط الأنابيب كانت تشغّل
  `bash <(curl https://codecov.io/bash)`. حمّل ثم تحقق من المجموع
  الاختباري، ثم نفّذ.
- لا تُخرج أسرارًا إلى السجلات حتى عند الفشل. استخدم `::add-mask::` لأي
  سرّ يُحتسب في وقت التشغيل، وراجع ذلك ببحث سجلات الـ workflow في GitHub.
- لا تسمح بتشغيل workflows على PRs من forks بـ `pull_request_target` إذا
  لمس أي job رمزًا بصلاحية كتابة أو سرًّا. هذه التركيبة هي النمط الكلاسيكي
  "pwn request" الذي وثّقه GitHub Security Lab.
- لا تكش حالة متغيّرة (مثل `~/.npm`، `~/.cargo`، `~/.gradle`) باستخدام
  `os` فقط كمفتاح. إصابة الكاش عبر jobs مختلفة هي سطح هجوم بين
  المستأجرين — استخدم تجزئة lockfile كمفتاح ونطّقه على ref الـ workflow.
- لا تثق بتحميل مواد من تشغيلات workflow عشوائية دون التحقق من workflow
  المصدر + SHA الـ commit. تسميم build-cache يجري عبر إعادة استخدام مواد
  بلا نطاق.
- لا تُخزّن أسرارًا في متغيّرات المستودع (`vars.*`) — فهي نص صريح لكل من
  لديه صلاحية قراءة. فقط `secrets.*` تخضع لقواعد فحص الأسرار والنطاق.

### إيجابيات خاطئة معروفة
- actions أول-طرف من المنظمة نفسها تعكسها أو تعمل لها fork داخليًا قد
  تُثبَّت بـ tag بشكل شرعي إذا فرضت المنظمة tags موقّعة + حماية فروع على
  مستودع الـ action.
- خطوط أنابيب البيانات العامة التي لا تتعامل مع أسرار ولا تنتج مواد
  موقّعة (مثل فحوص روابط ليلية) لا تحتاج OIDC ولا provenance لـ SLSA،
  ويمكنها استخدام tags متحرّكة دون أثر عملي.
- `pull_request_target` مشروع لأجل bots التصنيف / الفرز التي تستدعي
  GitHub API فقط بأدنى النطاقات اللازمة، ولا تجلب شيفرة الـ PR، ولا
  تكشف أسرارًا في env.

## السياق (للبشر)

أصبح CI/CD اليوم أكثر هدف منفرد ربحًا في سلسلة التوريد. خط الأنابيب يشغّل
شيفرة موثوقة باعتمادات موثوقة وسجلات موثوقة — اختراقه مرة واحدة يمنح
الوصول إلى كل مستهلك لاحق لكل مادة ينتجها. اختراق Codecov 2021،
وحادثة SolarWinds 2021، وتسميم خط أنابيب إصدار Ultralytics على PyPI
في 2024، وتسريب tj-actions/changed-files الكبير في 2025 جميعها اعتمدت
على تغييرات غير موثقة لسكربتات أو actions يستهلكها الـ CI.

أغلب الدفاعات ميكانيكية: ثبّت بـ SHA، قلّل الصلاحيات، استخدم OIDC،
وقّع المواد، تحقق من provenance. الصعب هو فرض ذلك على مستوى منظمة. يُؤتمت
OpenSSF Scorecard فحوصَ الدفاعات الميكانيكية ويتكامل مع حماية الفروع.

تركّز هذه الـ skill على ضعف الأنماط التصميمية (pwn requests، حقن
السكربت، curl-pipe-bash، tags متحرّكة، تحميل مواد غير موثوقة) لأنها
الأنماط التي يعيد توليدها YAML سير العمل المولَّد من الذكاء الاصطناعي
أكثر من غيرها.

## مراجع

- `checklists/github_actions_hardening.yaml`
- `checklists/gitlab_ci_hardening.yaml`
- [OpenSSF Scorecard](https://github.com/ossf/scorecard).
- [SLSA v1.0 Build Track](https://slsa.dev/spec/v1.0/levels).
- [GitHub Security Lab — Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/).
- [StepSecurity — tj-actions/changed-files attack analysis](https://www.stepsecurity.io/blog/tj-actions-changed-files-attack-analysis).
- [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html).
