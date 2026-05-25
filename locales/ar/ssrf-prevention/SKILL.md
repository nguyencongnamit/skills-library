---
id: ssrf-prevention
language: ar
dir: rtl
source_revision: "4c215e6f"
version: "1.0.0"
title: "منع SSRF"
description: "الدفاع ضدّ Server-Side Request Forgery: حَجب metadata السحابيّة، وتصفية IPs الداخليّة، والدفاع ضدّ DNS rebinding، وجَلب URL بِناءً على allowlist"
category: prevention
severity: critical
applies_to:
  - "عند توليد كود يَجلب URL يُورِّده العميل"
  - "عند توصيل webhooks، وimage proxies، وPDF renderers، وoEmbed fetchers"
  - "عند التشغيل في أيّ بيئة سحابيّة بِخدمة metadata للنماذج"
  - "عند مراجعة wrapper لِتحليل URL أو HTTP client"
languages: ["*"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "cors-security", "infrastructure-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP SSRF Prevention Cheat Sheet"
  - "CWE-918: Server-Side Request Forgery"
  - "Capital One 2019 breach post-mortem (IMDSv1 SSRF)"
  - "AWS IMDSv2 documentation"
  - "PortSwigger Web Security Academy — SSRF labs"
---

# منع SSRF

## القواعد (لوكلاء الذكاء الاصطناعيّ)

### دائمًا
- تَحقَّق من **كلّ** URL يُجلَب بِالنيابة عن عميل عبر **allowlist**
  من المضيفين المُتوقَّعين. الـ allowlist هي الدفاع الوحيد
  المستدام — تُتجَنَّب block-lists عبر حِيَل ترميز، وIPv6
  ثنائيّة المكدّس، وDNS rebinding.
- حُلَّ الـ hostname **مرّةً واحدة**، وتَحقَّق من الـ IP المُحَلَّل
  مقابل block-list الخاصّ بك بِالنطاقات الخاصّة / المحجوزة /
  link-local، ثمّ اتّصل بِذلك الـ IP المُثبَّت عبر SNI. وإلّا قد
  يَسبق المهاجم بِسباق DNS rebind بين التحقّق والاتّصال
  (`time-of-check / time-of-use`).
- احظر على طبقة الشبكة **و** طبقة التطبيق. أوقِف egress إلى
  `169.254.169.254`، و`[fd00:ec2::254]`،
  و`metadata.google.internal`، و`100.100.100.200` من أيّ خدمة
  لا تَحتاج خدمة الـ metadata بشكل مشروع.
- افرض **IMDSv2** على AWS EC2 (session-token، وhop-limit=1).
  IMDSv1 — النمط الذي استَغَلَّه اختراق Capital One عام 2019 —
  يجب تعطيله على مستوى النموذج.
- عَطِّل تحويلات HTTP افتراضيًّا في fetchers من جانب الخادم (أو
  اتبع عددًا صغيرًا محدودًا منها فقط، مع إعادة التحقّق من الـ URL
  الجديد مقابل الـ allowlist في كلّ قفزة). أكثر تجاوزات SSRF
  شيوعًا هو `https://allowed.example.com` يَرجع 302 إلى
  `http://169.254.169.254/...`.
- استخدم HTTP client منفصلًا ومُقَيَّدًا لِـ URLs *يتحكّم بها
  المستخدم* مقابل URLs *داخليّة*. سوء استخدام الـ client يجب أن
  يَفشل بِإغلاق (مثلًا عبر تمييز نوع في Go / Rust / TypeScript).
- حَلِّل URLs بِمُحَلِّل واحد معروف (`net/url.Parse` في Go،
  و`urllib.parse` في Python، و`new URL()` في JavaScript). المُحلِّلات
  التفاضليّة بين WHATWG وRFC-3986 مثلًا هي فئة موثَّقة من تجاوزات
  SSRF.

### أبدًا
- لا تَثِق بِـ hostname / IP يُورِّده المستخدم. أعد دائمًا الحلّ
  في الـ resolver الموثوق وأعد فحص العنوان المُحَلَّل.
- لا تَتَّصل بِـ URL استنادًا إلى hostname حين يَسمح البروتوكول
  بِتحويلات — `gopher://`، و`dict://`، و`file://`، و`jar://`،
  و`netdoc://`، و`ldap://` كلّها مُضَخِّمات شائعة لِـ SSRF.
  اقتصر على `http://` و`https://` (و`ftp://` فقط إذا كنت
  تَحتاجها فعلًا).
- لا تَثِق بِـ `0.0.0.0`، أو `127.0.0.1`، أو `[::]`، أو `[::1]`،
  أو `localhost`، أو `*.localhost.test` — كلّها تَصل إلى النموذج
  المحلّيّ. وتَشمل القائمة أيضًا link-local `169.254.0.0/16`،
  وIPv6 المُعَيَّن من IPv4 `::ffff:127.0.0.1`، وULA IPv6
  `fc00::/7`.
- لا تَستخدم نصّ URL المستخدم في سطر سجلّ أو ردّ خطأ — قد يكون
  وحي الانعكاس لِـ SSRF الذي يُحَوِّل SSRF أعمى إلى SSRF
  مُسَرِّب بيانات.
- لا تُشَغِّل sidecar / proxy حَجب metadata كدفاعٍ **وحيد** —
  مهاجم يَجد pseudo-URL لمقبس Unix أو hostname مَعِيب التهيئة
  قد يَلتفّ حول الـ proxy. تَظلّ allowlist على مستوى التطبيق
  مطلوبة.
- لا تَسمح بِـ IDN / Punycode في URLs المستخدم دون توحيد —
  هجمات الهَوْمُغراف بِـ IDN تَتجاوز فحوصات allowlist نصّيّة
  ساذجة (`gооgle.com` بِـ o سيريليّة ≠ `google.com`).

### إيجابيّات خاطئة معروفة
- تَكاملات خادم-إلى-خادم حيث يَسيطر المُشغِّل على الجانبَين والـ
  URL مُصلَّب في الـ config (لا يُورِّده المستخدم) — الـ
  allowlist هنا هي الـ config الساكن نفسه.
- استدعاءات خدمة-إلى-خدمة محلّيّة العنقود في Kubernetes — هذه
  لا تمرّ عبر مدخل مستخدم، لكن انتبه إلى أيّ network policy
  عبر namespaces.
- webhooks خارجة **إلى** العميل (مثل webhooks Slack، أو
  Discord، أو Microsoft Teams). تَحقَّق أنّ مضيف الـ URL في
  allowlist مُوثَّقة لِلتكامل، وليس عشوائيًّا.

## السياق (للبشر)

SSRF الآن ناقل وصول أوّليّ بِحُكم الواقع لاختراقات السحابة.
السلسلة هي: URL يُورِّده المستخدم → الخادم يَجلبها → الخادم
لديه اعتمادات ضمنيّة (IAM لِـ metadata السحابة، وAPIs إدارة
داخليّة، ونقاط نهاية RPC) → المهاجم يَسرق الاعتمادات. اختراق
Capital One عام 2019 (80 مليون سجلّ عميل) كان حالة من كتاب
الـ SSRF + تسريب IMDSv1. الإصلاحات بسيطة ومُوثَّقة جيّدًا؛
الأنماط تَعود لأنّ جَلب URL ركن صغير في معظم كواعد الكود.

يُؤكِّد هذا الـ skill على فئات DNS-rebinding وتجاوز التحويلات
لأنّها حيث تَفشل أكثر مُحَقِّقات URL المُولَّدة بِالذكاء
الاصطناعيّ — حَجب 169.254.169.254 الواضح سهل الإضافة، أمّا
نمط allow-only-after-resolve-and-pin فيَحتاج تفكيرًا أكبر.

## مراجع

- `rules/ssrf_sinks.json`
- `rules/cloud_metadata_endpoints.json`
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
- [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
- [Capital One 2019 breach DOJ filing](https://www.justice.gov/usao-wdwa/press-release/file/1188626/download).
- [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html).
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf).
