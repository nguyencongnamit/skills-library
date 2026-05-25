---
id: websocket-security
language: ar
dir: rtl
source_revision: "4c215e6f"
version: "1.0.0"
title: "أمن WebSocket"
description: "تأمين endpoints الـ WebSocket: التحقّق من Origin، والمصادقة عند المُصافحة، وحدود حجم / معدّل الرسائل، وwss فقط، والتراجع عند إعادة الاتّصال"
category: prevention
severity: high
applies_to:
  - "عند توليد خادم WebSocket / Socket.IO / SignalR"
  - "عند توصيل مراسلة فوريّة، أو presence، أو تحرير تعاونيّ"
  - "عند مراجعة كشف endpoints الـ /ws أو wss://"
languages: ["javascript", "typescript", "python", "go", "java", "csharp", "ruby", "elixir"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "cors-security", "auth-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP WebSocket Security Cheat Sheet"
  - "RFC 6455 — The WebSocket Protocol"
  - "CWE-1385: Missing Origin Validation in WebSockets"
  - "CWE-770: Allocation of Resources Without Limits or Throttling"
---

# أمن WebSocket

## القواعد (لوكلاء الذكاء الاصطناعيّ)

### دائمًا
- تَحقَّق من **header `Origin`** عند مُصافحة ترقية WebSocket مقابل
  allowlist. CORS **لا** يَنطبق على WebSockets — يَرقى المتصفّح
  بِسعادة عبر الأصول ويَسمح لِـ JavaScript على `attacker.com`
  بِفتح `wss://api.example.com/ws` بِكوكيز المستخدم
  (Cross-Site WebSocket Hijacking).
- اطلب المصادقة **عند المُصافحة نفسها**، لا كأوّل رسالة بعد
  الاتّصال. إمّا:
  1. مصادقة بِكوكيز على ترقية HTTP (مع حماية CSRF عبر التحقّق
     من Origin)، أو
  2. token موقَّع قصير العمر (5–10 دقائق) في header الـ
     subprotocol `Sec-WebSocket-Protocol`، أو
  3. token موقَّع في معامل استعلام.
  لا تَثِق أبدًا بِرسالة `subscribe` / `auth` بعد الترقية —
  بِحلول تلك اللحظة، يكون الاتّصال قد فُتِح بِسياق كوكيز
  مُصدَّق.
- استخدم **`wss://`** فقط في الإنتاج. `ws://` بِنصّ صريح عبر
  الإنترنت المكشوف يَكشف session tokens، ومحتوى الرسائل،
  وأوّليّات CSRF لِأيّ مُراقِب على المسار.
- افرض **حدًّا أقصى لِحجم الرسالة** على الخادم (نموذجيًّا:
  32 KiB لِلدردشة، و256 KiB لِلتحرير التعاونيّ، وأعلى فقط حين
  يَتطلّب الاستخدام ذلك وتكون عتبة المصادقة عالية). بدون حدّ،
  قد يَستنزف socket واحد مفتوح ذاكرة الخادم.
- افرض **حدّ معدّل لِلرسائل** لكلّ اتّصال (مثلًا 60 رسالة/
  دقيقة) و**حدّ معدّل لِلاتّصال** لكلّ IP مصدر / لكلّ مستخدم
  مُصدَّق. سوء الاستخدام في الزمن الفوريّ (spam دردشة، فيضان
  ping presence) مصدر متكرّر لِـ DoS.
- نَفِّذ **نبضات ping / pong** (كلّ 20–30 ثانية) وأغلق الاتّصال
  عند فقدان pong. وإلّا تَتراكم sockets TCP نصف مفتوحة خلف
  مُوازنات الحمل.
- على جانب العميل، استخدم **تراجعًا أُسّيًّا محدودًا** لِإعادة
  الاتّصال (مثلًا base 1s، وfactor 2، وmax 60s، وjitter ±20%).
  حلقة إعادة اتّصال ساذجة `setTimeout(connect, 0)` تُذيب الخادم
  أثناء الأعطال.
- عامِل كلّ رسالة WebSocket كَطلب منفصل لِأغراض **التحقّق من
  المُدخل** و**التفويض**. قد تَتغيّر صلاحيّات المستخدم بعد فتح
  الـ socket (تسجيل خروج، تغيير دور، قفل حساب) — أعد الفحص
  في كلّ فعل مُمَيَّز.

### أبدًا
- لا تَتخَطَّ التحقّق من Origin لأنّه "WebSocket، وCORS لا
  ينطبق". هذا تحديدًا سبب وجوب القيام بِها يدويًّا. الهجوم
  الموثَّق هو Cross-Site WebSocket Hijacking، عُرِض علنًا
  عام 2013 ولا يَزال شائعًا في تقارير bug-bounty عام 2024.
- لا تَستخدم session cookie كـ token WebSocket طويل العمر. إذا
  كان من المُفتَرض أن يَنجو اتّصال WS عبر تبويبات / صفحات
  متعدّدة، أصدِر JWT قصيرًا قابلًا لِلتحديث في الـ subprotocol؛
  ولا تَعتمد على بقاء الكوكيز إلى الأبد.
- لا تَسمح بِـ `subprotocols` عشوائيّة من العميل تُؤثِّر في
  routing من جانب الخادم بلا allowlist. التفاوض على
  subprotocol مَحكوم بِالمهاجم.
- لا تُشَغِّل handlers الـ WebSocket في نفس العمليّة / تجمّع
  الخيوط الخاصّ بِمُعالِجات طلبات HTTP بلا حدود تحجيم — قد
  يُجَوِّع WebSocket على غرار slow-loris كلّ عمل HTTP.
- لا تَكشف طوبولوجيا الكتلة الداخليّة في رسائل WebSocket
  (مثلًا `{"server_id": "pod-prod-42"}`). المعرّفات الداخليّة
  مادّة استطلاع على قناة فوريّة كثيرة الكلام.

### إيجابيّات خاطئة معروفة
- endpoints دردشة / presence عامّة عَمدًا مفتوحة لِأيّ origin
  يجب أن تَفرض رغم ذلك حدود معدّل لكلّ اتّصال وسقفًا لكلّ IP
  مصدر؛ وقد تَسمح بِشكل مشروع بِـ `Origin: null` لِعملاء
  سطح المكتب / المحمول.
- عملاء المحمول / سطح المكتب الأصليّون لا يُرسلون header
  `Origin`. قَرِّر مسبقًا إن كنت تَسمح بِهم (وطَبِّق وضع
  مصادقة مختلفًا مثل device-cert + bearer token) أم تَرفضهم
  مباشرةً.
- WebSockets خدمة-إلى-خدمة (مثل Kafka WebSocket bridge، أو
  Apache Pulsar) داخل VPC خاصّة قد تَستخدم بشكل مشروع `ws://`
  مع mTLS مُعالَج على طبقة الشبكة.

## السياق (للبشر)

WebSockets هي القريب طويل العمر لِـ HTTP. لا تَنطبق معظم ضوابط
HTTP المجّانيّة (CORS، وCSP، ومصادقة لكلّ طلب) خارج الصندوق،
وتُخفي أطر العمل التي تَلفّ WebSockets خلف API أعلى مستوى
(Socket.IO، وSignalR، وPhoenix Channels) آليّة الترقية بما يَكفي
لِيَنسى المطوّرون تَقسيتها.

فئتا الحوادث المتكرّرتان هما:
1. **Cross-Site WebSocket Hijacking** — غياب فحص Origin +
   مصادقة بِكوكيز → يَفتح attacker.com WS بِكوكيز المستخدم
   ويَقرأ تَدفُّقه.
2. **استنزاف الموارد** — لا حدّ حجم / معدّل / اتّصال + بروتوكول
   ثَرثار → DoS تافه.

كلاهما إصلاحات بسيطة، لكنّ كليهما سهل النسيان عند توليد ميزة
دردشة / تعاون سريعة. يَعكس هذا الـ skill ورقة OWASP وإضافة
المُتطلّبات التشغيليّة (نبضات، تراجع).

## مراجع

- `rules/websocket_hardening.json`
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Cheat_Sheet.html).
- [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html).
- [Cross-Site WebSocket Hijacking explainer](https://christian-schneider.net/CrossSiteWebSocketHijacking.html).
- [RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455).
