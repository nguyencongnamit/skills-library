---
id: logging-security
language: ar
dir: rtl
source_revision: "afe376a8"
version: "1.0.0"
title: "أمن التسجيل (logging)"
description: "منع تسرّب الأسرار / PII داخل logs، ودفع هجمات log-injection، وضمان audit trails، وتجنّب احتفاظ ضعيف"
category: prevention
severity: high
applies_to:
  - "عند توليد نداءات logger أو schemas للتسجيل المُهيكَل"
  - "عند توصيل log shippers، وsinks، والاحتفاظ، وضوابط الوصول"
  - "عند مراجعة متطلَّبات audit logging"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2400
rules_path: "rules/"
related_skills: ["secret-detection", "error-handling-security", "compliance-awareness"]
last_updated: "2026-05-13"
sources:
  - "OWASP Logging Cheat Sheet"
  - "CWE-532 — Insertion of Sensitive Information into Log File"
  - "CWE-117 — Improper Output Neutralization for Logs"
  - "NIST SP 800-92 (Guide to Computer Security Log Management)"
---

# أمن التسجيل (logging)

## القواعد (لوكلاء الذكاء الاصطناعي)

### دائمًا
- سَجِّل بـ**صيغة مُهيكَلة** (JSON أو logfmt) بأسماء حقول ثابتة.
  ضَمِّن `timestamp`، و`service`، و`version`، و`level`،
  و`trace_id`، و`span_id`، و`user_id` (عند المصادقة)،
  و`request_id`، و`event`.
- مَرِّر كل رسالة سجلّ عبر **مُحرِّر تنقية** قبل وصولها إلى sink:
  كلمات المرور، وtokens، ومفاتيح API، وcookies، وروابط URL كاملة
  تحوي `?token=`، وأنماط PII الشائعة (بشكل SSN، وبشكل بطاقة ائتمان،
  وبريد إلكترونيّ اختياريًّا).
- نَقِّ newlines / محارف التحكّم من أيّ نصٍّ يَتحكَّم فيه المستخدم
  قبل تسجيله (CWE-117): استَبدِل `\n`، و`\r`، و`\t` لكي لا يتمكَّن
  المهاجم من حقن أسطر سجلّ مزيَّفة.
- سَجِّل الأحداث الأمنيّة المُهمَّة بوصفها **سجلّات تدقيق غير قابلة
  للتعديل**: نجاح/فشل login، وتحدّيات MFA، وتغيير كلمة المرور،
  وتغيير الدور، ومنح/إبطال الوصول، وتصدير البيانات، والعمليّة
  الإداريّة. سجلّات التدقيق تَحصُل على احتفاظ أطول ووصول أكثر صرامة.
- اضبط الاحتفاظ حسب فئة البيانات لا عالميًّا: قصير لـ debug، طويل
  لـ audit، وبلا PII بعد انتهاء الموافقة.
- اشحَن السجلّات إلى مخزن مُركَّز append-only (Cloud Logging،
  وCloudWatch، وElastic، وLoki) بوصول قراءة مقصور على الهندسة /
  SecOps.
- نَبِّه على غياب سجلّات خدمةٍ ما (فشل صامت)، وعلى شذوذ حجم
  السجلّات (قفزة 10× أو هبوط 10×).

### أبدًا
- لا تُسجِّل bodies كاملة لـ request / response في INFO. ففي
  الـ bodies باستمرار كلمات مرور، وtokens، وPII، وملفّات مرفوعة.
- لا تُسجِّل headers `Authorization`، أو headers `Cookie` /
  `Set-Cookie`، أو tokens في query-string، ولا أيّ حقل يُسمّى
  `password`، أو `secret`، أو `token`، أو `key`، أو `private`،
  أو `credential` — ولو بعد "إخفاء" مثل `***`.
- لا تُسجِّل عبارات SQL مربوطة كاملةً بقيم معاملاتها؛ سَجِّل بدلاً
  من ذلك القالب + *أسماء* المعاملات + معرِّف قيمة مُجَزَّأ
  بـ hash.
- لا تَسمح لمستخدمين غير مميَّزين بقراءة سجلّات خام تحوي بيانات
  مستخدمين آخرين.
- لا تستخدم `print()` / `console.log` / `fmt.Println` صرفًا في
  خدمات الإنتاج؛ استخدم الـ logger المُهيَّأ لتُطبَّق التنقية
  والـ structure بشكلٍ موحَّد.
- لا تُعطِّل تسجيل محاولات المصادقة الفاشلة بحجّة "تقليل الضجيج"
  — فاكتشاف brute-force يعتمد على تلك السجلّات.
- لا تُسجِّل إلى ملفّ وحيد على قرصٍ محلّيّ في الإنتاج؛ تَضيع تلك
  السجلّات حين يموت الـ pod / container / VM.

### إيجابيات خاطئة معروفة
- يمكن مشروعًا أن يُخفَّض حجم سجلّات health-check أو probe لـ
  load balancer عند load balancer لتوفير الحجم.
- قيمة `request_id` التي تَبدو كـ token ليست token — فمُحرِّرات
  التنقية القائمة على مطابقة النمط قد تُفرِط في التنقية؛ ضَع
  بادئات آمنة معروفة على القائمة البيضاء (مثلًا معرّفات الربط
  `req_` لديك).
- سجلّات الوصول إلى APIs عامّة بلا headers مصادقة ليست مشكلة
  خصوصيّة بحدّ ذاتها؛ لكن قد تَظلّ IPs العملاء بياناتٍ شخصيّةً
  بموجب GDPR.

## السياق (للبشر)

السجلّات هي المكان الأكثر شيوعًا الذي تنتهي فيه الأسرار نصًّا
صريحًا — dumps الطلبات، وآثار الاستثناءات، وطباعات debug،
وtelemetry من SDKs خارجيّة. تُغطّي OWASP Logging Cheat Sheet
القواعد التشغيليّة؛ ويُغطّي NIST SP 800-92 جانب الاحتفاظ /
المركزيّة / audit trail. تَظهر متطلَّبات audit trail تحت SOC 2
CC7.2، وPCI-DSS 10، وHIPAA §164.312(b)، وISO 27001 A.12.4.

هذا الـ skill شريكٌ لـ `secret-detection` (الذي يفحص المصدر)
ولـ `error-handling-security` (الذي يُنقّي الردّ الخارجيّ).
تَجلس السجلّات بينهما وتَنزف في كلا الاتّجاهين.

## مراجع

- `rules/redaction_patterns.json`
- `rules/audit_event_schema.json`
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
- [CWE-532](https://cwe.mitre.org/data/definitions/532.html).
- [CWE-117](https://cwe.mitre.org/data/definitions/117.html).
- [NIST SP 800-92](https://csrc.nist.gov/publications/detail/sp/800-92/final).
