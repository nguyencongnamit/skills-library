---
id: auth-security
language: ar
dir: rtl
source_revision: "afe376a8"
version: "1.0.0"
title: "أمن المصادقة والتفويض"
description: "JWT و OAuth 2.0 / OIDC وإدارة الجلسات و CSRF وتجزئة كلمات المرور وإلزام MFA"
category: prevention
severity: critical
applies_to:
  - "عند توليد تدفقات تسجيل الدخول / إنشاء الحساب / إعادة تعيين كلمة المرور"
  - "عند توليد إصدار JWT أو التحقق منه"
  - "عند توليد شيفرة عميل أو خادم OAuth 2.0 / OIDC"
  - "عند توصيل كوكيز الجلسة وtoken الـ CSRF و MFA"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1300
  full: 2700
rules_path: "rules/"
related_skills: ["api-security", "crypto-misuse", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "OWASP Authentication Cheat Sheet"
  - "OWASP Session Management Cheat Sheet"
  - "RFC 6749 — OAuth 2.0"
  - "RFC 7519 — JSON Web Token"
  - "RFC 9700 — OAuth 2.0 Security BCP"
  - "NIST SP 800-63B (Authenticator Assurance)"
---

# أمن المصادقة والتفويض

## القواعد (لوكلاء الذكاء الاصطناعي)

### دائمًا
- عند التحقق من JWT، ثبّت الخوارزمية المتوقعة (`RS256`، `EdDSA`، أو
  `ES256`) وتحقق من `iss` و`aud` و`exp` و`nbf` و`iat`. ارفض `alg=none`
  وأي خوارزمية غير متوقعة.
- لعملاء OAuth 2.0 العامين (SPA / موبايل / CLI)، استخدم **تدفق
  authorization code مع PKCE** (S256). لا تستخدم implicit flow أبدًا. ولا
  تستخدم resource owner password credentials grant.
- كوكيز الجلسة: `Secure; HttpOnly; SameSite=Lax` (أو `Strict` للتدفقات
  الحساسة). استخدم البادئة `__Host-` حين لا توجد مشاركة بين النطاقات
  الفرعية.
- دوّر مُعرّف الجلسة عند تسجيل الدخول وعند تغيّر الامتيازات. اربط الجلسة
  بـ user agent كإشارة لينة فقط — لا كفحص وحيد.
- جزّئ كلمات المرور بـ argon2id (m=64 MiB, t=3, p=1) مع salt عشوائي لكل
  مستخدم. Bcrypt cost ≥ 12 أو scrypt N≥2^17 بدائل مقبولة للأنظمة
  legacy. PBKDF2-SHA256 يتطلب ≥ 600,000 تكرار (الحد الأدنى لـ OWASP
  2023).
- اشترط طول كلمة المرور ≥ 12 محرفًا دون قواعد تركيب؛ اسمح بـ Unicode؛
  افحص كلمات المرور المرشحة ضد قائمة كلمات المرور المُسرَّبة (HIBP / واجهة
  k-anonymity لـ pwned-passwords).
- نفّذ قفل الحساب *أو* تحديد المعدّل لمحاولات كلمة المرور (NIST SP 800-63B
  §5.2.2: على الأكثر 100 فشل خلال 30 يومًا).
- نفّذ حماية CSRF للطلبات التي تُغيّر الحالة ويمكن الوصول إليها من جلسة
  متصفح: synchronizer token، أو double-submit cookie، أو
  `SameSite=Strict` لنقاط النهاية عالية المخاطر.
- اطلب MFA / step-up للعمليات الإدارية وتغيير كلمة المرور وتغيير جهاز
  MFA وتغيير الفوترة.
- لـ OIDC، تحقق من `nonce` الذي أرسلتَه مقابل `nonce` في الـ ID token؛
  وتحقق من `at_hash` / `c_hash` متى وُجدا.

### أبدًا
- لا تستخدم `Math.random()` (أو أي RNG ليس CSPRNG) لتوليد مُعرّفات
  جلسة، أو رموز إعادة تعيين، أو رموز استرداد MFA، أو مفاتيح API.
- لا تقبل JWT بـ `alg=none`؛ ولا تقبل HS256 من عميل بينما المُصدِر يوقّع
  بـ RS256 (هجوم خلط الخوارزميات الكلاسيكي).
- لا تقارن كلمات المرور أو تجزئات الرموز بـ `==` / `strcmp`؛ استخدم
  مقارِنًا بزمن ثابت.
- لا تخزّن كلمات المرور بشكل قابل للعكس (مشفّرة بدلًا من مجزّأة). يجب
  أن يكون التخزين باتجاه واحد.
- لا تكشف أيهما الخاطئ — اسم المستخدم أم كلمة المرور. أعد رسالة عامة
  "invalid credentials".
- لا تضع رموز وصول أو رموز تحديث أو مُعرّفات جلسة في query strings الـ URL
  — فهي تُسرَّب إلى السجلات وترويسات Referer وتاريخ المتصفح.
- لا تستخدم `localStorage` / `sessionStorage` لحفظ رموز تحديث طويلة العمر.
  استخدم كوكيز HttpOnly.
- لا تثق بأدوار / مطالبات يقدّمها العميل في طبقة الـ API — اشتقّ الموضوع
  المُصادَق عليه من جديد، وابحث عن التفويض على جهة الخادم في كل طلب.
- لا تُصدر رموز وصول طويلة العمر (>ساعة واحدة)؛ اعتمد على رموز التحديث مع
  التدوير.
- لا تستخدم implicit flow ولا password grant.

### إيجابيات خاطئة معروفة
- رموز خدمة-إلى-خدمة بـ TTL طويل قد تكون مقبولة أحيانًا حين تكون مخزّنة في
  مدير أسرار ومربوطة بهوية workload محدّدة.
- مصادقة "magic link" في تطوير محلي بلا تجزئة كلمة مرور لمستخدمين مؤقتين
  مقبولة إن كانت محصورة خلف env flag ومعطّلة في الإنتاج.
- وجود الرموز في query الـ URL مقبول في موضع *واحد* — مسار العودة من
  authorization code في OAuth — لأن القيمة قصيرة العمر وذات استخدام
  واحد.

## السياق (للبشر)

تظهر إخفاقات المصادقة باستمرار في OWASP Top 10 (A07:2021 — Identification
and Authentication Failures). الأنماط الشائعة هي: تخزين كلمات مرور ضعيف،
ورموز قابلة للتنبؤ، وغياب MFA، وسوء إعداد JWT، وتثبيت الجلسة. RFC 9700
(OAuth 2.0 Security BCP) و NIST SP 800-63B هما المرجعان الرسميان للوصفة.

تميل مساعدات الذكاء الاصطناعي إلى شحن مصادقة "تعمل في dev": JWT بـ HS256
بأسرار مكتوبة في الشيفرة، و`bcrypt.hash` بقيمة cost الافتراضية 10، ولا
PKCE، ورموز في localStorage. هذه الـ skill تلتقط كل واحدة منها.

## مراجع

- `rules/jwt_safe_config.json`
- `rules/oauth_flows.json`
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
- [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700).
