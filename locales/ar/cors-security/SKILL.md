---
id: cors-security
language: ar
dir: rtl
source_revision: "afe376a8"
version: "1.0.0"
title: "أمن CORS"
description: "إعداد CORS صارم: لا wildcard مع الاعتمادات، أصول من allowlist، تخزين preflight معقول، رؤوس مكشوفة بالحد الأدنى"
category: prevention
severity: high
applies_to:
  - "عند توليد middleware لـ CORS أو إعداد إطار العمل"
  - "عند توصيل رؤوس CORS لـ API Gateway / CloudFront / Nginx"
  - "عند مراجعة endpoint موجَّه للمتصفح يعبر الأصول"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1000
  full: 2000
rules_path: "rules/"
related_skills: ["frontend-security", "api-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP HTML5 Security Cheat Sheet — CORS"
  - "CWE-942 — Permissive Cross-domain Policy with Untrusted Domains"
  - "Fetch Living Standard (CORS)"
---

# أمن CORS

## القواعد (لوكلاء الذكاء الاصطناعي)

### دائمًا
- استخدم **allowlist** للأصول، لا `*`. اعكس رأس `Origin` الوارد فقط حين
  يطابق مدخلًا معروفًا من الإعدادات (أو regex مُسبق التركيب لأسماء مضيف
  يتحكم بها المشغّل).
- إن كانت الاستجابات تتضمن اعتمادات (cookies أو `Authorization`)، اضبط
  `Access-Control-Allow-Credentials: true` **و** تأكَّد أن
  `Access-Control-Allow-Origin` نصّ أصل محدّد واحد — أبدًا ليس `*`.
- ضع `Vary: Origin` على الاستجابات التي يعتمد جسمها على `Origin` الطلب،
  كي لا تُقدِّم الذاكرات المؤقتة استجابةَ أصلٍ لأصل آخر.
- قيّد `Access-Control-Allow-Methods` للـ preflight على الطرق التي
  يقبلها الـ endpoint فعلًا؛ وقيّد `Access-Control-Allow-Headers` على
  الرؤوس المستهلكة فعلًا.
- اضبط `Access-Control-Max-Age` على قيمة معقولة (≤ 86400 في الإنتاج)
  لإطفاء كُلفة preflight دون تثبيت allowlist خاطئة.
- احتفظ بـ allowlist في الشيفرة (أو في ملف إعدادات في المستودع)، لا
  مشتقَّة من قاعدة بيانات — كي لا يضيف المهاجمون أصلهم بإدخال صف.

### أبدًا
- لا تضبط `Access-Control-Allow-Origin: *` مع
  `Access-Control-Allow-Credentials: true`. تحظر مواصفة Fetch ذلك
  لسبب — سترفض المتصفحات الاستجابة، لكن المشكلة الأكبر أن proxy /
  cache أمامي ربما يكون قد سرّبها مسبقًا.
- لا تعكس رأس `Origin` دون فحص allowlist
  (`Access-Control-Allow-Origin: <Origin>` لكل أصل وارد). هذا يعادل
  `*` بالنسبة للاعتمادات مع سلوك تخزين مؤقت أسوأ.
- لا تسمح بـ `null` كأصل. `null` هو ما يرسله Chrome من iframes في
  sandbox ومن URIs بنوع `data:` و`file://` — ولا ينبغي لأيٍّ منها
  وصول معتمَد إلى واجهتك.
- لا تسمح بنطاقات فرعية عشوائية بـ regex مثل `.*\.example\.com$` دون
  مراعاة الاستيلاء على النطاق الفرعي. ثبّت نطاقات فرعية محددة؛ وعامِل
  `*.example.com` كقرار متعمَّد مرتبط بضوابط ملكية النطاقات الفرعية.
- لا تكشف رؤوسًا داخلية عبر `Access-Control-Expose-Headers`. اقتصر على
  أدنى حد يحتاجه الواجهة الأمامية فعلًا.
- لا تستخدم CORS كآلية تخويل. CORS سياسة *متصفح*؛ لا توقف
  server-to-server ولا curl ولا العملاء غير المتصفّحين. وثّق الطلب
  بمصادقة سليمة.

### إيجابيات خاطئة معروفة
- الواجهات العامة بصدق وغير المُصادقة (بيانات مفتوحة، endpoints لـ CDN
  تسويقي) يمكن أن تستخدم شرعًا `Access-Control-Allow-Origin: *`
  *دون* اعتمادات.
- أدوات إدارة داخلية مقصورة على شبكة خاصة يمكنها استخدام أصل واحد
  ثابت؛ هاجس الـ wildcard لا ينطبق لعدم وجود مستدعين عابرين للأصول.
- بعض التكاملات (Stripe.js و Plaid و Auth0) تتوقع رؤوس CORS محددة —
  اقرأ قسم CORS لكل مزوّد قبل تخفيف الأساس.

## السياق (للبشر)

كثيرًا ما يُساء فهم CORS كضابط أمني. ليس كذلك — هو *تخفيف* لسياسة
نفس الأصل. الضابط الأمني هو المصادقة. سوء إعداد CORS يهمّ لأنه عند
الاقتران بالكوكيز أو رأس `Authorization` يمنح الأصول غير الموثوقة
القدرة على إصدار طلبات عابرة للأصول معتمدة وقراءة الاستجابة.

هذه الـ skill قصيرة بالتصميم — مصفوفة التركيبات السيّئة محدودة،
والقواعد قاطعة.

## مراجع

- `rules/cors_safe_config.json`
- [OWASP CORS Origin Header Scrutiny](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny).
- [CWE-942](https://cwe.mitre.org/data/definitions/942.html).
- [Fetch — CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol).
