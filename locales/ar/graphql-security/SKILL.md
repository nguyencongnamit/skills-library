---
id: graphql-security
language: ar
dir: rtl
source_revision: "4c215e6f"
version: "1.0.0"
title: "أمن GraphQL"
description: "الدفاع عن واجهات GraphQL البرمجيّة: حدود العمق/التعقيد، وintrospection في الإنتاج، وإساءة استخدام batching/aliasing، والتفويض على مستوى الحقل، وpersisted queries"
category: prevention
severity: high
applies_to:
  - "عند توليد مخططات GraphQL أو resolvers أو ضبط الخادم"
  - "عند توصيل المصادقة/التفويض بنقطة نهاية GraphQL"
  - "عند إضافة بوّابة API GraphQL عامّة"
  - "عند مراجعة كشف نقطة النهاية /graphql"
languages: ["javascript", "typescript", "python", "go", "java", "kotlin", "csharp", "ruby"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "auth-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP GraphQL Cheat Sheet"
  - "CWE-400: Uncontrolled Resource Consumption"
  - "Apollo GraphQL Production Checklist"
  - "graphql-armor (Escape technologies)"
---

# أمن GraphQL

## القواعد (لوكلاء الذكاء الاصطناعي)

### دائمًا
- افرض **عمق استعلام** أقصى (نموذجيًّا: 7–10) و**تعقيد استعلام**
  (تكلفة) على الخادم. استعلام مُتداخل بخمسة مستويات على علاقة
  many-to-many قد يعيد مليارات العقد؛ وبدون حدّ تكلفة يُسقط عميل
  واحد قاعدة البيانات.
- عطِّل **introspection** في الإنتاج. تجعل introspection
  الاستكشاف هيّنًا؛ والعملاء الشرعيّون يحملون الـ schema مُدمَجًا
  عبر codegen أو ملف `.graphql`.
- استخدم **persisted queries** (تجزئات عمليّات ضمن allowlist) لأيّ
  API عامّة أو ذات حركة مرور عالية. GraphQL مجهول الهويّة وبشكل
  حرّ هو المعادل في GraphQL لـ `eval(req.body)`.
- طبِّق **تفويضًا على مستوى الحقل** داخل الـ resolvers، لا عند نقطة
  النهاية فقط. يَجمَع GraphQL حقولًا كثيرة في استجابة HTTP واحدة
  — غياب `@auth` واحدة على حقل حسّاس يُسرِّب البيانات عبر
  الاستعلام كلّه.
- حُدَّ عدد **aliases** لكل طلب (نموذجيًّا: 15) وعدد **العمليّات
  لكل batch** (نموذجيًّا: 5). يدعم كلّ من Apollo / Relay
  الاستعلامات المُجمَّعة — وبدون حدود تُصبح هذه بدائية تضخيم بسعة
  N صفحات من الـ API.
- ارفض تعريفات **fragment الدوريّة** مبكّرًا (تفعل ذلك معظم
  الخوادم، أمّا الـ executors المخصّصة فلا). الـ fragment الذي
  يُشير إلى نفسه يُحدث كلفة تحليل أُسّيّة.
- أعِد للعملاء أخطاءً عامّة (`INTERNAL_SERVER_ERROR`،
  `UNAUTHORIZED`) ووجِّه stack traces / مقاطع SQL إلى سجلّات
  الخادم فقط. أخطاء Apollo الافتراضيّة تُسرِّب تفاصيل داخليّة من
  الـ schema والاستعلام.
- اضبط حدّ حجم للطلب (نموذجيًّا: 100 KiB) وانقضاء مهلة للطلب
  (نموذجيًّا: 10 ث) في طبقة HTTP أمام خادم GraphQL. لا استخدام
  مشروع لاستعلام GraphQL بحجم 1 MiB.

### أبدًا
- لا تكشف introspection لـ `/graphql` على نقطة نهاية إنتاج. يجب
  تعطيل playground الخاص بـ GraphQL (GraphiQL، Apollo Sandbox)
  في بنى الإنتاج أيضًا.
- لا تثق بعمق / تعقيد الاستعلام لأن "عملاءنا يرسلون استعلامات
  جيّدة التشكيل فقط". أيّ مهاجم يستطيع تشكيل طلب إلى `/graphql`
  يدويًّا.
- لا تسمح لتوجيهات `@skip(if: ...)` / `@include(if: ...)` بأن
  تحكم فحوصات التفويض. تَعمل التوجيهات بعد التفويض في معظم
  الـ executors، لكن ترتيب توجيهات مخصّص أنتج تجاوزات للتفويض.
- لا تُطبِّق أنماط N+1 في الـ resolvers (استعلام DB لكلّ سجلّ أب).
  استخدم DataLoader أو الجلب القائم على join. N+1 خلل أداء
  ومُضخِّم DoS في الوقت ذاته.
- لا تسمح برفع الملفات عبر multipart الخاص بـ GraphQL
  (`apollo-upload-server`، `graphql-upload`) دون حدود حجم وتحقّق
  من MIME وفحص فيروسات خارج النطاق. أظهرت CVE-2020-7754 لعام 2020
  (`graphql-upload`) كيف يمكن لـ multipart مشوّه أن يُسقط الخادم.
- لا تُخزِّن استجابات GraphQL في ذاكرة التخزين المؤقّت بحسب الـ URL
  وحده. يستخدم POST `/graphql` دائمًا الـ URL نفسه؛ يجب أن
  يَجزّئ الكاش وفق hash العمليّة + المتغيّرات + ادّعاءات
  المصادقة لتجنّب التسرّب بين الـ tenants.
- لا تكشف mutations تتلقّى كائنات `input:` بـ JSON غير موثوق دون
  التحقّق من schema. تُفرَض أنواع GraphQL في طبقة الـ schema،
  لكن أنواع `JSON` / `Scalar` تتجاوزها كاملةً.

### إيجابيات خاطئة معروفة
- نقاط نهاية GraphQL الإداريّة الداخلية خلف VPN مُصادَقة قد تترك
  introspection مفعَّلة لراحة المطوّر بصورة مشروعة.
- تجعل persisted queries ذات allowlist الثابتة فحوصات العمق /
  التعقيد زائدة على تلك العمليّات — احتفظ بالفحوصات لأيّ عمليّة ليست
  ضمن الـ allowlist (أي عمليّات عبر علم `disabled`).
- قد تستخدم واجهات API العامّة لقراءة البيانات فقط حدود تكلفة
  مرتفعة جدًّا مع تكوين caching مكثّف عند طبقة CDN؛ ويُوثَّق
  التنازل لكلّ نقطة نهاية.

## السياق (للبشر)

يَمنح GraphQL العملاء لغة استعلام. هذه اللغة Turing-كاملة عمليًّا
— العمق والـ aliasing والـ fragments والـ unions تتركّب لتُشكِّل
حسابًا شبه عشوائي مقابل رسم الـ resolvers. التعامل مع `/graphql`
بوصفه نقطة نهاية واحدة مع ضوابط WAF / تحديد معدّل بسيطة لا يكفي.

تمحورت حقبة 2022-2024 من حوادث GraphQL (Hyatt، وبحث Slack الصادر
عن Apollo، وعدد من حالات الاستيلاء على الحسابات عبر batching)
كلّها إمّا حول تفويض مفقود على مستوى الحقل أو حول تحليل تكلفة
مفقود. توفّر graphql-armor (Escape) وقواعد التحقّق المُضمَّنة في
Apollo الآن middleware جاهزة لمعظم هذه الحالات — استخدمها.

## مراجع

- `rules/graphql_safe_config.json`
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html).
- [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
- [Apollo Production Checklist](https://www.apollographql.com/docs/apollo-server/security/production-checklist/).
- [graphql-armor](https://escape.tech/graphql-armor/).
