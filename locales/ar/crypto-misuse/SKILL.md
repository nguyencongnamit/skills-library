---
id: crypto-misuse
language: ar
dir: rtl
source_revision: "afe376a8"
version: "1.0.0"
title: "سوء استخدام التشفير"
description: "حظر الخوارزميات الضعيفة، RNG قابل للتنبؤ، مفاتيح صغيرة، سوء استخدام slow-hash، والمقارنات غير ثابتة الزمن"
category: prevention
severity: critical
applies_to:
  - "عند توليد شيفرة تُهَشِّش / تُشَفِّر / تُوقِّع"
  - "عند توليد شيفرة تقارن أسرارًا / MACs / tokens"
  - "عند توصيل إعدادات TLS أو أحجام المفاتيح أو RNG"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2500
rules_path: "rules/"
related_skills: ["secret-detection", "auth-security", "protocol-security"]
last_updated: "2026-05-13"
sources:
  - "NIST SP 800-131A Rev. 2"
  - "NIST SP 800-57 Part 1 Rev. 5"
  - "OWASP Cryptographic Storage Cheat Sheet"
  - "CWE-327, CWE-338, CWE-916, CWE-208"
---

# سوء استخدام التشفير

## القواعد (لوكلاء الذكاء الاصطناعي)

### دائمًا
- استخدم مكتبة التشفير في اللغة/المنصّة. Python: `cryptography`،
  `secrets`. JavaScript: Web Crypto، `crypto.webcrypto`، Node
  `crypto`. Go: `crypto/*`، `golang.org/x/crypto`. Java: JCE / Bouncy
  Castle. .NET: `System.Security.Cryptography`.
- استخدم RNG آمنًا تشفيريًا: Python `secrets.token_bytes` /
  `secrets.token_urlsafe`، JS `crypto.getRandomValues` /
  `crypto.randomBytes`، Go `crypto/rand.Read`، Java `SecureRandom`.
- هَشِّش كلمات المرور بـ KDF بطيء معاير على ~100 ms على عتاد
  الإنتاج: **argon2id** (مُفضَّل، معاملات RFC 9106:
  m=64 MiB، t=3، p=1)، **scrypt** (N=2^17، r=8، p=1)، أو **bcrypt**
  (cost ≥ 12). دومًا مع salt عشوائي لكل مستخدم.
- شَفِّر باستخدام AEAD (تشفير موثَّق): AES-256-GCM،
  ChaCha20-Poly1305، أو AES-256-GCM-SIV. ولِّد nonce عشوائيًا جديدًا
  لكل عملية تشفير.
- استخدم TLS 1.2+ (يُفضَّل TLS 1.3 بقوة). عطِّل TLS 1.0/1.1
  وSSLv3 وRC4 و3DES وخوارزميات التصدير.
- قارن MACs / التواقيع / tokens بمساعدات ثابتة الزمن:
  `hmac.compare_digest`، `crypto.subtle.timingSafeEqual`،
  `subtle.ConstantTimeCompare`، `MessageDigest.isEqual`،
  `CryptographicOperations.FixedTimeEquals`.
- للمفاتيح غير المتماثلة: RSA ≥ 3072 bits، ECDSA P-256 أو P-384،
  Ed25519، X25519.

### أبدًا
- لا تستخدم MD5 أو SHA-1 للتواقيع أو الشهادات أو تخزين كلمات
  المرور أو مصادقة الرسائل. (تبقى صالحة لاستخدامات عَرَضِية غير
  أمنية مثل ETag أو إزالة تكرار الملفات، مع توثيق ذلك صراحةً.)
- لا تستخدم DES أو 3DES أو RC4 أو Blowfish في شيفرة جديدة.
- لا تستخدم نمط ECB. لا تستخدم CBC دون HMAC على النص المشفَّر.
  لا تعيد استخدام nonce في CTR/GCM.
- لا تستخدم تجزئة بلا salt لكلمات المرور. لا تستخدم
  `sha256(password)` لتخزين كلمات المرور — فهي تجزئة سريعة وكسرها
  بالقوة الغاشمة تافه.
- لا تستخدم `Math.random()` أو `random` في Python أو `rand()` في
  C / Go لـ tokens أو IDs أو nonces أو كلمات مرور. كلها قابلة للتنبؤ.
- لا تَهارد-كود IVs/nonces أو salts أو مفاتيح. لا تعد استخدام nonce
  GCM/Poly1305 تحت المفتاح نفسه أبدًا.
- لا تقارن الأسرار بـ `==` أو `===` أو `strcmp` أو `bytes.Equal` —
  فهي تتسرّب عبر التوقيت.
- لا تكتب تشفيرك بنفسك (XOR مخصّص، HMAC مخصّص، Diffie-Hellman
  مخصّص، مخططات توقيع مخصّصة). استخدم بدائيات مُدقَّقة.

### إيجابيات خاطئة معروفة
- MD5 / SHA-1 في سياقات غير أمنية: حساب HTTP ETag، إزالة تكرار
  المحتوى، مفاتيح ذاكرة مؤقتة لبيانات غير حساسة، بصمات fixtures.
  وثّق هذه الاستخدامات بتعليق `// non-security use: ...`.
- متجهات الاختبار وقيم KAT (Known Answer Test) تَهارد-كود قَصدًا
  IVs ومفاتيح ونصوصًا صريحة — مكانها `tests/`، لا الإنتاج.
- التشغيل البيني القديم: بعض البروتوكولات الصناعية/الحكومية تتطلب
  ما زالت خوارزميات قديمة محدّدة. وثّق الاستثناء واعزله خلف feature
  flag.

## السياق (للبشر)

NIST SP 800-131A Rev. 2 هو خارطة طريق حكومة الولايات المتحدة المرجعية
لإهمال الخوارزميات، و cheat sheet التخزين التشفيري لـ OWASP هو
الرفيق العملي بأسلوب "افعل هذه الأمور". أنماط الإخفاق المتكرّرة هي:
تجزئة سريعة لكلمات المرور (CWE-916)، RNG قابل للتنبؤ لـ tokens
(CWE-338)، اختيار خوارزمية مكسور (CWE-327)، ومقارنة غير ثابتة الزمن
للأسرار (CWE-208).

تميل مساعدات الذكاء الاصطناعي إلى تكرار أمثلة التشفير الشائعة على
Stack Overflow حوالي 2014، وهو ما يعني الكثير من `sha256(password)`
و`AES-CBC` بحشو يدوي. هذه الـ skill هي الموازن.

## مراجع

- `rules/algorithm_blocklist.json`
- `rules/key_size_minimums.json`
- [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final).
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).
- [CWE-327](https://cwe.mitre.org/data/definitions/327.html) — تشفير مكسور أو محفوف بالمخاطر.
- [CWE-916](https://cwe.mitre.org/data/definitions/916.html) — جهد حوسبي غير كافٍ لتجزئة كلمات المرور.
