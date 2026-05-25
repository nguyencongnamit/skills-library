---
id: error-handling-security
language: ar
dir: rtl
source_revision: "afe376a8"
version: "1.0.0"
title: "أمن معالجة الأخطاء"
description: "لا تتبّعات للمكدس / SQL / مسارات / إصدارات إطار في ردود العميل؛ أخطاء عامّة للخارج وأخطاء مُهيكَلة في السجلات"
category: prevention
severity: medium
applies_to:
  - "عند توليد معالجات أخطاء HTTP / GraphQL / RPC"
  - "عند توليد كتل exception / panic / rescue"
  - "عند توصيل صفحات الأخطاء الافتراضية للإطار"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 900
  full: 1900
rules_path: "rules/"
related_skills: ["api-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP Error Handling Cheat Sheet"
  - "CWE-209 — Generation of Error Message Containing Sensitive Information"
  - "CWE-754 — Improper Check for Unusual or Exceptional Conditions"
---

# أمن معالجة الأخطاء

## القواعد (لوكلاء الذكاء الاصطناعي)

### دائمًا
- التقط الاستثناءات عند الحدّ (معالج HTTP، أو طريقة RPC، أو مستهلك
  رسائل). سجّلها بالسياق الكامل من جانب الخادم؛ وأعِد للخارج خطأً
  مُنظَّفًا.
- تتضمّن ردود الأخطاء الخارجية: رمز خطأ مستقرّ، ورسالة قصيرة قابلة
  لقراءة البشر، ومعرّف ربط / طلب. ولا تتضمّن أبدًا: تتبّع مكدس، أو
  مقطع SQL، أو مسار ملف، أو اسم مضيف داخلي، أو شعار إصدار إطار.
- سجّل الأخطاء على المستوى المناسب: `ERROR` / `WARN` للإخفاقات
  القابلة للمعالجة؛ و`INFO` للنتائج التشغيلية المتوقَّعة؛ و`DEBUG`
  لتفاصيل التشخيص (وفقط عند تفعيلها بشكل صريح).
- أعِد ردود أخطاء موحّدة عبر سطح الـ API كاملًا — الشكل ذاته، ومجموعة
  الرموز ذاتها — حتى لا يستطيع المهاجمون استنتاج السلوك من اختلاف
  الأخطاء (مثل تسجيل الدخول: الرسالة ذاتها والتوقيت ذاته لـ "اسم
  مستخدم خاطئ" مقابل "كلمة سرّ خاطئة").
- عطِّل صفحات الأخطاء الافتراضية للإطار في الإنتاج
  (`app.debug = False` / `Rails.env.production?` /
  `Environment=Production` / `DEBUG=False`). استبدلها بصفحة 5xx
  تُعيد فقط معرّف الربط.
- استعمل مساعد إخراج أخطاء مركزيًّا كي تعيش قواعد التنظيف في مكان
  واحد، بلا تكرار.

### أبدًا
- لا تُخرِج `traceback.format_exc()`، أو `e.toString()`، أو
  `printStackTrace()`، أو `panic`، أو صفحات debug الخاصة بالإطار
  للعميل في الإنتاج.
- لا تردّد استعلامات / معاملات SQL في رسائل الأخطاء — رسالة من
  نوع `IntegrityError: duplicate key value violates unique constraint
  "users_email_key"` تُخبر المهاجم باسم الجدول واسم العمود.
- لا تُسرّب معلومات وجود سجلّ: `User not found` مقابل `Invalid
  password` يتيح للمهاجم تعداد الحسابات. استخدم رسالة واحدة في
  الحالتَين.
- لا تُسرّب مسارات نظام الملفات (`/var/www/app/src/handlers.py`) أو
  شعارات إصدار (`X-Powered-By: Express/4.17.1`).
- لا تعامل `try / except: pass` كأنّه معالجة أخطاء؛ إمّا أن
  الاستثناء متوقَّع (سجّل + تابع)، وإمّا أن لا يكون كذلك (دعه
  ينتشر).
- لا تستخدم ردود الأخطاء 4xx للتحقّق من شكل الإدخال — تَستعرض
  البوتات المعاملات وتستخدم متن الردّ لتعلّم الـ schema. أعِد 400
  موحَّدًا مع معرّف ربط لمدخل غير صالح الشكل.
- لا ترسل تفاصيل الأخطاء الكاملة (بما فيها PII) إلى خدمات تتبّع
  أخطاء خارجية بلا scrubber. أخفِ `password`، و`Authorization`،
  و`Cookie`، و`Set-Cookie`، و`token`، و`secret`، وأنماط PII
  الشائعة.

### إيجابيات خاطئة معروفة
- صفحات الأخطاء الموجَّهة للمطوّرين على `localhost` / `*.local` لا
  بأس بها.
- قد تُعيد قلّة من نقاط النهاية في الـ API (debug، admin، RPC
  داخلي) تفاصيل أوسع بشكل مشروع؛ ويجب أن تشترط متّصلين موثّقين
  ومُصرَّحًا لهم، وألّا تكون قابلة للوصول من الإنترنت أبدًا.
- تكشف فحوصات الصحّة واختبارات الدخان في الـ CI تفاصيل عمدًا حين
  تُستدعى من داخل العنقود.

## السياق (للبشر)

CWE-209 نصّ قصير لكن أثره كبير: هكذا ينتقل المهاجم من "هذه الخدمة
موجودة" إلى "هذه الخدمة تشغّل Spring 5.2 على Tomcat 9 مع جدول
PostgreSQL اسمه `users` وعمود اسمه `email_normalized`". كل تفصيل
إضافي في رسالة الخطأ يُقلّل تكلفة الهجمة التالية.

هذه الـ skill ضيّقة بقصد، وتتكامل مع `logging-security` (جانب
*السجل* للعملية نفسها) ومع `api-security` (شكل الردّ).

## مراجع

- `rules/error_response_template.json`
- `rules/redaction_patterns.json`
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html).
- [CWE-209](https://cwe.mitre.org/data/definitions/209.html).
