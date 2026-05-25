---
id: protocol-security
language: ar
dir: rtl
source_revision: "afe376a8"
version: "1.0.0"
title: "أمن البروتوكولات"
description: "TLS 1.2+، وmTLS، والتحقّق من الشهادات، وHSTS، واعتمادات قنوات gRPC، وفحوصات Origin في WebSocket"
category: hardening
severity: critical
applies_to:
  - "عند توليد عملاء وخوادم HTTP / gRPC / WebSocket / SMTP / قواعد البيانات"
  - "عند توليد تكوين TLS في الكود أو في تكوين المنصّة"
  - "عند توليد مصادقة من خدمة إلى خدمة"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2400
rules_path: "rules/"
related_skills: ["crypto-misuse", "frontend-security", "api-security"]
last_updated: "2026-05-13"
sources:
  - "NIST SP 800-52 Rev. 2 (TLS Guidelines)"
  - "RFC 8446 — TLS 1.3"
  - "RFC 6797 — HSTS"
  - "OWASP Transport Layer Security Cheat Sheet"
  - "CWE-295, CWE-326, CWE-319, CWE-757"
---

# أمن البروتوكولات

## القواعد (لوكلاء الذكاء الاصطناعيّ)

### دائمًا
- اجعل الافتراض **TLS 1.3** للعملاء والخوادم الجديدة؛ ولا تَسمح بـ
  TLS 1.2 إلّا لتشغيل بين الأقران القُدامى. وعطِّل TLS 1.0/1.1
  وSSLv2/v3.
- تَحقَّق من شهادة الخادم: سَلسلة موثوقة إلى CA، والاسم يُطابق
  الـ hostname المتوقَّع (أو SAN)، وغير منتهية، وغير ملغاة (OCSP
  stapling مُفعَّل).
- فَعِّل HSTS على ردود HTTP لكلّ ما يُقدَّم عبر HTTPS:
  `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.
  وأَضِف الـ host إلى قائمة HSTS preload بعد الاستقرار.
- استخدم **mutual TLS** (mTLS) لحركة من خدمة إلى خدمة داخل نطاق
  ثقة (شبكة: Istio / Linkerd؛ ومستقلّ: SPIFFE / SPIRE للهويّة).
- لِعملاء/خوادم gRPC، استخدم `grpc.secure_channel` /
  `grpc.SslCredentials` / `credentials.NewTLS` — ولا تستخدم أبدًا
  `insecure_channel` في الإنتاج.
- لخوادم WebSocket، تَحقَّق من ترويسة `Origin` مقابل قائمة بيضاء،
  وصادِق على المصافحة (cookies + token CSRF، أو bearer في
  query-string يُستخدَم مرّةً عند الترقية ويُعاد التحقّق منه).
- لِـ tokens من خدمة إلى خدمة، فَضِّل **معرّفات SPIFFE**
  (`spiffe://trust-domain/...`) مع شهادات حِمل قصيرة العمر بدل
  مفاتيح API طويلة العمر.
- ثَبِّت الشهادة (pinning للمفتاح العامّ) لِعملاء الجوّال / سطح
  المكتب عالية المخاطر التي تَتّصل بخلفيّة مُشغِّلها.

### أبدًا
- لا تُعطِّل التحقّق من الشهادة (`InsecureSkipVerify: true`،
  `verify=False`، `rejectUnauthorized: false`،
  `CURLOPT_SSL_VERIFYPEER=0`). الاستخدام الوحيد المقبول هو في
  اختبار وحدة يَعمل مقابل شهادة عابرة على localhost.
- لا تُنفِّذ `X509TrustManager` / `HostnameVerifier` /
  `URLSessionDelegate` / `ServerCertificateValidationCallback`
  مُخصَّصًا يَعود بـ "موثوق" دون شرط.
- لا تَخلط موارد HTTP وHTTPS في الصفحة نفسها (محتوى مختلَط) —
  ستحجب المتصفّحات الحديثة الموارد الفرعيّة، لكنّ APIs تَبقى
  عُرضة لخفض رتبة MITM.
- لا تُرسِل tokens / كلمات مرور عبر HTTP صريح — حتى على localhost
  في dev، ما لم تكن بيئة dev موثَّقةً على أنّها غير ذات صلة
  بالأمن.
- لا تَستخدم `grpc.insecure_channel(...)` في كود الإنتاج.
- لا تَثِق بترويسات `Host` / `X-Forwarded-Host` / `Forwarded` بلا
  قائمة بيضاء؛ فعناوين URL المطلقة المبنيّة من `Host` تَفتح بابَ
  حقن ترويسة Host وتسميم إعادة تعيين كلمة المرور.
- لا تُمرِّر ترويسات `Authorization` / `Cookie` الواردة عَمْياء
  عبر أصول مختلفة في service mesh لديك — اشتقّ الهويّة من جديد
  من mTLS أو من service token.
- لا تُفعِّل إعادة تفاوُض TLS على العملاء الذين تَتحكَّم بهم؛
  ثَبِّت على `tls.NoRenegotiation` حيثما توفّر ذلك.

### إيجابيّات خاطئة معروفة
- خوادم dev مَحصورة على localhost بِشهادات موقَّعة ذاتيًّا
  ومُوثَّقة صراحةً لا بأس بها؛ واختبارات CI مقابل شهادات عابرة
  مُوقَّعة من CA لا بأس بها.
- يَتطلَّب عدد قليل من تكاملات المؤسّسات القديمة TLS 1.2 بِـ
  cipher محدَّد؛ وَثِّق الاستثناء وَاعزل التكامل خلف وكيل.
- يُمكن لِنقاط النهاية العامّة للقراءة فقط (مثلًا صفحات الحالة) أن
  تُقدَّم عبر HTTP بشكل مشروع لِأجل قابليّة التخزين المؤقَّت، وإن
  ظلّ HTTPS مفضَّلًا.

## السياق (للبشر)

NIST SP 800-52 Rev. 2 هو المرجع الأمريكيّ الحكوميّ المعتمَد لـ TLS؛
وRFC 8446 هو TLS 1.3 ذاته. ووضع الفشل المتكرّر في مراجعة الكود هو
**`InsecureSkipVerify`** (أو ما يُعادله في كلّ لغة) — ويُدخَل عادةً
"لتشغيل الاختبارات"، ولا يُعاد إلى وضعه السليم.

يَتكامَل هذا الـ skill بشكل طبيعيّ مع `crypto-misuse` (اختيار
الخوارزميّة) و`auth-security` (إصدار الـ tokens).

## مراجع

- `rules/tls_defaults.json`
- `rules/cert_validation_sinks.json`
- [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final).
- [RFC 8446 — TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446).
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html).
- [CWE-295](https://cwe.mitre.org/data/definitions/295.html) — Improper Certificate Validation.
