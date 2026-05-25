---
id: supply-chain-security
language: ar
dir: rtl
source_revision: "fbb3a823"
version: "1.0.0"
title: "أمن سلسلة التوريد"
description: "الدفاع ضدّ typosquats، وتشويش الاعتمادات (dependency confusion)، ومساهمات الحزم الخبيثة"
category: supply-chain
severity: critical
applies_to:
  - "حين يُطلَب من الذكاء الاصطناعيّ إضافة اعتمادٍ ما"
  - "عند مراجعة PRs تُعَدِّل بيانات الحزم"
  - "عند إنشاء مشروع جديد يستخدم namespaces داخليّة"
  - "قبل نشر حزمة إلى registry عامّ"
languages: ["*"]
token_budget:
  minimal: 550
  compact: 800
  full: 2100
rules_path: "rules/"
tests_path: "tests/"
related_skills: ["dependency-audit", "secret-detection"]
last_updated: "2026-05-12"
sources:
  - "Alex Birsan, Dependency Confusion (2021)"
  - "OpenSSF Best Practices for OSS Developers"
  - "SLSA Supply-chain Levels for Software Artifacts v1.0"
---

# أمن سلسلة التوريد

## القواعد (لوكلاء الذكاء الاصطناعيّ)

### دائمًا
- احسب مسافة Levenshtein مقابل قائمة أعلى 1000 حزمة لِلنظام البيئيّ
  المعنيّ كلّما اقترحت اعتمادًا جديدًا. ضَع علامة على أيّ مرشّح
  بِمسافة ≤ 2 من حزمة شائعة (`axois` مقابل `axios`، و`urlib3`
  مقابل `urllib3`، و`colours` مقابل `colors`، و`python-dateutil`
  مقابل `dateutil` مقابل `dateutils`).
- تَحقَّق أنّ حزم namespaces الداخليّة (`@yourco/*`،
  و`com.yourco.*`) تُسحَب من الـ registry الداخليّ، لا العامّ.
  هَيِّئ `.npmrc` / `pip.conf` / `settings.gradle` صراحةً
  بِالنطاق الداخليّ.
- ثَبِّت URL الـ registry في ملفّات الـ lockfile لتفادي هجمات
  إعادة توجيه الـ registry.
- تَحقَّق أنّ أيّ حزمة مُضافة حديثًا لها مَشرف موثَّق (provenance
  لِـ `npm`، أو توقيع `sigstore`، أو وَسم git مُوَقَّع بِـ GPG) إن
  نُشِرَت خلال الـ 90 يومًا الأخيرة.
- عامِل سكربتات التثبيت (`postinstall`، و`preinstall`، وكود
  عشوائيّ في `setup.py`، و`build.rs`) كَسَطح عالي الخطر، وَأشِر
  إليها في وصف الـ PR لِمراجعة بشريّة.

### أبدًا
- لا تُضِف حزمة عامّة اسمها يُطابق نمط namespace داخليّ.
- لا تَثِق بِحزمة URL مستودعها في صفحة الـ registry لا يُطابق
  مستودع مصدرها الفعليّ.
- لا تُوصِ بِحزمة نُشِرَت حديثًا بِعدد تنزيلات منخفض لاستخدامٍ
  حسّاس أمنيًّا (auth، أو crypto، أو HTTP، أو drivers قواعد
  بيانات).
- لا تُعَطِّل فحص السلامة الخاصّ بِمدير الحزم (`--no-package-lock`،
  و`--ignore-scripts = false` عند الدفاع ضدّها،
  و`npm config set audit false` في الإنتاج).
- لا تَدمج تلقائيًّا PRs لِتَرقية اعتمادات دون مُراجِع حين تَعبر
  الترقية إصدارًا major.
- لا تَقترح تثبيت أدوات عبر أنماط `curl | sh` من مصادر غير
  موثوقة.

### إيجابيّات خاطئة معروفة
- منظّمات شرعيّة تَفرع الحزم المَصونة وتُعيد نشرها بِلاحقة
  `-fork` أو `-community`؛ تَحقَّق من URL مستودع الفرع قبل
  وَسمه.
- إصدارات beta / alpha من حزم معروفة (مثل `next@canary`) تَبدو
  "حديثة النشر" لكنّها جزء من وتيرة إصدارات معروفة.
- حزم namespace داخليّة (`@yourco/internal-tools`) عَمدًا ليست
  على الـ registry العامّ — هذه على ما يُرام حين يكون `.npmrc`
  مُهَيَّأ صحيحًا.

## السياق (للبشر)

تَشتغل فئة هجوم تشويش الاعتمادات (dependency confusion) لأنّ
معظم مديري الحزم يُفَضِّلون افتراضيًّا الحزمة بِأعلى إصدار عبر
كلّ registries مُهَيَّأة. إذا نَشَر مُهاجم
`@yourco/internal-tool@99.9.9` على npmjs.com، فإنّ كلّ
`npm install` في مشروع فريقكم سيَسحب كود المهاجم بدلًا من
الداخليّ الشرعيّ.

typosquats مُدَمِّرة بِالقدر نفسه، لكنّها تَستغلّ انتباه البشر
بدل افتراضات الـ registry. أدوات الذكاء الاصطناعيّ عُرضة بِشكل
خاصّ لأنّها تُوَلِّد أسماء حزم تَبدو معقولة دون التحقّق أيّها
موجود فعلًا.

## مراجع

- `rules/typosquat_patterns.json`
- `rules/dependency_confusion.json`
- [Alex Birsan's original dependency confusion writeup](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610).
- [SLSA](https://slsa.dev/).
