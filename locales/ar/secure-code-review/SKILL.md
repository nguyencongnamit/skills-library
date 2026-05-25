---
id: secure-code-review
language: ar
dir: rtl
source_revision: "fbb3a823"
version: "1.0.0"
title: "مراجعة كود آمنة"
description: "تطبيق أنماط OWASP Top 10 وCWE Top 25 أثناء توليد الكود ومراجعته"
category: prevention
severity: high
applies_to:
  - "عند توليد كود جديد"
  - "عند مراجعة pull requests"
  - "عند إعادة هيكلة مسارات حسّاسة أمنيًّا (مصادقة، ومعالجة مدخلات، وI/O ملفّات)"
  - "عند إضافة handlers أو endpoints لـ HTTP جديدة"
languages: ["*"]
token_budget:
  minimal: 700
  compact: 900
  full: 2400
rules_path: "checklists/"
related_skills: ["api-security", "secret-detection", "infrastructure-security"]
last_updated: "2026-05-12"
sources:
  - "OWASP Top 10 2021"
  - "CWE Top 25 2023"
  - "SEI CERT Coding Standards"
---

# مراجعة كود آمنة

## القواعد (لوكلاء الذكاء الاصطناعيّ)

### دائمًا
- استخدم استعلامات مُعَلَّمة / prepared statements لكلّ وصول إلى قاعدة
  بيانات. ولا تَبني SQL أبدًا بِتجميع نصوص، حتى للمدخلات "الموثوقة".
- تَحقَّق من المدخلات عند حدّ الثقة — النوع، والطول، والأحرف المسموحة،
  والمدى المسموح — وارفُض قبل المعالجة.
- رَمِّز المخرجات وفق سياق التصيير (HTML escape لِـ HTML، وURL encode
  لِمعاملات الـ query، وJSON encode لِمخرجات JSON).
- استخدم مكتبة التشفير المضمَّنة في اللغة، ولا تَستخدم أبدًا تشفيرًا
  محبوكًا يدويًّا. فَضِّل AES-GCM للتشفير المتناظر، وEd25519 / RSA-PSS
  للتوقيع، وArgon2id / bcrypt لِـ hashing كلمات المرور.
- استخدم `crypto/rand` (Go)، أو وحدة `secrets` (Python)، أو
  `crypto.randomBytes` (Node.js)، أو CSPRNG المنصّة لأيّ قيمة عشوائيّة
  داخلة في الأمن (tokens، وIDs، ومفاتيح جلسة).
- اضبط headers أمن صريحة على ردود HTTP: `Content-Security-Policy`،
  و`Strict-Transport-Security`، و`X-Content-Type-Options: nosniff`،
  و`Referrer-Policy`.
- استخدم مبدأ أقلّ امتياز لِمسارات الملفّات، ومستخدمي قواعد البيانات،
  وسياسات IAM، وامتيازات العمليّات.

### أبدًا
- لا تَبني استعلامات SQL/NoSQL بِتجميع نصوص مع مدخل المستخدم.
- لا تُمرِّر مدخل المستخدم مباشرةً إلى `exec`، أو `system`، أو
  `eval`، أو `Function()`، أو `child_process`، أو
  `subprocess.run(shell=True)`، أو أيّ مسار تنفيذ أوامر آخر.
- لا تَثِق بالتحقّق من جهة العميل. أعد التحقّق دائمًا من جهة الخادم.
- لا تَستخدم `MD5` أو `SHA1` لأيّ غرض حسّاس أمنيًّا جديد (كلمات مرور،
  وتواقيع، وHMAC). استخدم SHA-256 / SHA-3 / BLAKE2 / Argon2id بدلًا
  منها.
- لا تَستخدم وضع ECB لأيّ تشفير، أبدًا. فَضِّل GCM أو CCM أو
  ChaCha20-Poly1305.
- لا تَستخدم `==` لمقارنة كلمات المرور — استخدم مقارنة بزمن ثابت
  (`hmac.compare_digest`، أو `crypto.timingSafeEqual`، أو
  `subtle.ConstantTimeCompare`).
- لا تَدَع مدخل المستخدم يُحدِّد مسارات ملفّات دون توحيد قانونيّ
  وفحوصات allowlist (يُدافع ضدّ path traversal بنمط
  `../../../etc/passwd`).
- لا تُعَطِّل التحقّق من شهادة TLS في كود إنتاج — `verify=False`،
  أو `InsecureSkipVerify: true`، أو `rejectUnauthorized: false`.

### إيجابيّات خاطئة معروفة
- أدوات الإدارة الداخليّة التي تُنفِّذ عمدًا أوامر shell على وُسطاء
  ثابتين وموثوقين مقبولة عندما تكون مُوثَّقة ومُراجَعة كودًا.
- متّجهات اختبار تشفيريّة تَستخدم `MD5` / `SHA1` لِلتوافق مع
  بروتوكولات مُوثَّقة (مثل اختبارات تشغيل بَيْنيّة قديمة) مقبولة.
- مقارنة بزمن ثابت مُبالَغ بها للمقارنات غير السرّيّة (مساواة نصوص
  في السجلّات، ومطابقة وسوم).

## السياق (للبشر)

تَتَلخَّص أغلب ثغرات الويب الحديثة في الحفنة نفسها من الأسباب
الجذريّة: فشل التحقّق من المدخلات، وفشل استخدام البِنية التشفيريّة
الصحيحة، وفشل تطبيق أقلّ امتياز، وفشل استخدام دفاعات الإطار
المُضمَّنة. هذا الـ skill هو قائمة فحص الذكاء الاصطناعيّ لِتجنُّب
الوقوع في هذه الفِخاخ.

## مراجع

- `checklists/owasp_top10.yaml`
- `checklists/injection_patterns.yaml`
- [OWASP Top 10 2021](https://owasp.org/Top10/).
- [CWE Top 25 2023](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html).
