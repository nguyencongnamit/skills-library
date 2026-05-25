---
id: dependency-audit
language: ar
dir: rtl
source_revision: "fbb3a823"
version: "1.0.0"
title: "تدقيق التبعيات"
description: "تدقيق تبعيات المشروع بحثًا عن ثغرات معروفة وحزم خبيثة ومخاطر سلسلة التوريد"
category: supply-chain
severity: high
applies_to:
  - "عند إضافة تبعية جديدة"
  - "عند ترقية التبعيات"
  - "عند مراجعة بيانات الحزم (package.json، requirements.txt، go.mod، Cargo.toml)"
  - "قبل دمج PR يعدّل ملفات التبعيات"
languages: ["*"]
token_budget:
  minimal: 400
  compact: 750
  full: 1900
rules_path: "rules/"
related_skills: ["secret-detection", "supply-chain-security"]
last_updated: "2026-05-12"
sources:
  - "OWASP Top 10 2021 — A06: Vulnerable and Outdated Components"
  - "CWE-1104: Use of Unmaintained Third Party Components"
  - "CISA Software Bill of Materials guidance"
---

# تدقيق التبعيات

## القواعد (لوكلاء الذكاء الاصطناعي)

### دائمًا
- ثبّت التبعيات على إصدارات دقيقة في ملفات القفل
  (`package-lock.json`، `yarn.lock`، `Pipfile.lock`، `poetry.lock`،
  `go.sum`، `Cargo.lock`).
- قارن اسم كل تبعية جديدة بقائمة الحزم الخبيثة المُضمَّنة في
  `vulnerabilities/supply-chain/malicious-packages/`.
- فضِّل الحزم الراسخة ذات عدد التنزيلات المرتفع، وتعدّد المشرفين،
  والنشاط الحديث، على البدائل الأحدث التي تحلّ المشكلة ذاتها.
- شغّل أمر التدقيق لمدير الحزم (`npm audit`، `pip-audit`،
  `cargo audit`، `govulncheck`) وراجع المسائل المُبلَّغ عنها قبل
  الدمج.
- تحقّق أن رابط مستودع الحزمة المذكور في صفحتها موجود فعلًا ويطابق
  مشروع GitHub / GitLab / Codeberg المرتبط.

### أبدًا
- لا تضف تبعية بدون تثبيت إصدارها.
- لا تثبّت الحزم باستخدام `--unsafe-perm` أو ما يكافئها من رايات تتجاوز
  عزل التثبيت.
- لا تضف تبعية يظهر اسمها ضمن قائمة الحزم الخبيثة المُضمَّنة.
- لا تضف حزمة جديدة تمامًا (نُشرت في آخر 30 يومًا) دون سبب واضح
  ومُوثَّق — فعادةً ما تكون عمليات الـ typosquat حديثة النشر.
- لا تستخدم وسم `latest` في ملف قفل إنتاج أو في سطر FROM لصورة
  حاويات.
- لا تُلزِم تبعيات غير مستخدمة — فهي توسِّع سطح الهجوم مجّانًا.

### إيجابيات خاطئة معروفة
- حزم الـ monorepo الداخلية (`@yourco/*`) المُعلَّمة بـ "unknown" —
  وهي صحيحة حين تكون مساحة الأسماء مملوكة لمؤسستك.
- إصدارات الترقيع الجديدة لحزم مستقرة (مثل `react@18.2.5` بعد
  `18.2.4`) المُعلَّمة بأنها "حديثة النشر" — تحديثات الترقيع آمنة
  عادة.
- أسماء حزم تتقاطع بشكل مشروع مع إدخالات خبيثة قديمة بسنوات أعاد
  المشرف الأصلي تسجيلها.

## السياق (للبشر)

نمت هجمات سلسلة التوريد بسرعة تفوق أيّ فئة هجوم أخرى منذ 2019. اختراق
حزمة مشهورة (event-stream، ua-parser-js، colors، faker، xz-utils) أو
نشر typosquat (axois مقابل axios، urllib3 مقابل urlib3) يضمن للمهاجم
آلاف الضحايا في الاتجاه السفلي خلال ساعات.

أدوات البرمجة المعتمدة على الذكاء الاصطناعي عُرضة بشكل خاص لأن
النموذج لا يعرف متى تعرّضت حزمة للاختراق آخر مرة. يوصي النموذج بما
تعلّمه خلال التدريب؛ فإذا تعرّض مشرف للاختراق بعد قطع التدريب، يوصي
الذكاء الاصطناعي بمرح بنسخة تحوي بابًا خلفيًا.

تعوّض هذه الـ skill عن ذلك بحقن قاعدة بيانات الحزم الخبيثة الحيّة في
سياق عمل الذكاء الاصطناعي واشتراط أن يستشيرها قبل إضافة أي تبعية.

## مراجع

- `rules/known_malicious.json` — وصلة رمزية أو نسخة من ملفات
  `vulnerabilities/supply-chain/malicious-packages/*.json` ذات الصلة.
- [OWASP Top 10 A06](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/).
- [npm Advisories](https://github.com/advisories?query=type%3Aunreviewed+ecosystem%3Anpm).
- [PyPI Advisory Database](https://github.com/pypa/advisory-database).
