---
id: frontend-security
language: ar
dir: rtl
source_revision: "afe376a8"
version: "1.0.0"
title: "أمن الواجهة الأمامية"
description: "تصليب من جانب المتصفح: XSS، وCSP، وCORS، وSRI، وDOM clobbering، وعزل iframe، وTrusted Types"
category: prevention
severity: high
applies_to:
  - "عند توليد قوالب HTML / JSX / Vue / Svelte"
  - "عند توصيل هيدرات الاستجابة في تطبيق ويب"
  - "عند إضافة وسوم scripts من جهات خارجية أو موارد CDN"
languages: ["html", "javascript", "typescript", "tsx", "jsx", "vue", "svelte"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2800
rules_path: "rules/"
related_skills: ["cors-security", "auth-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP XSS Prevention Cheat Sheet"
  - "OWASP Content Security Policy Cheat Sheet"
  - "CWE-79: Improper Neutralization of Input During Web Page Generation"
  - "MDN Trusted Types"
---

# أمن الواجهة الأمامية

## القواعد (لوكلاء الذكاء الاصطناعي)

### دائمًا
- عامِل جميع بيانات المستخدم / URL / storage على أنها غير موثوقة.
  استخدم تهريب إطار العمل في الرسم (`{}` في JSX/Vue/Svelte،
  و`{{ }}` في القوالب). لـ HTML الخام استخدم منظِّفًا موثوقًا
  (DOMPurify) مع allowlist صارمة.
- أرسل هيدر `Content-Security-Policy` صارمًا. الحد الأدنى في
  الإنتاج: `default-src 'self'; script-src 'self' 'nonce-<random>';
  object-src 'none'; base-uri 'self'; frame-ancestors 'none';
  form-action 'self'; upgrade-insecure-requests`. استخدم nonces أو
  hashes — ولا تستخدم أبدًا `'unsafe-inline'` ضمن `script-src`.
- اضبط `Strict-Transport-Security: max-age=63072000;
  includeSubDomains; preload`، و`X-Content-Type-Options: nosniff`،
  و`Referrer-Policy: no-referrer-when-downgrade` أو أصرم،
  و`Permissions-Policy` لتعطيل الميزات غير المستخدمة.
- أَضِف `integrity="sha384-..." crossorigin="anonymous"` إلى كل
  `<script>` و`<link rel="stylesheet">` يُحمَّل من CDN.
- أَضِف `sandbox="allow-scripts allow-same-origin"` (فقط السمات
  اللازمة) إلى كل `<iframe>`. الافتراض: بلا أي flags سماح.
- استخدم cookies بـ `Secure; HttpOnly; SameSite=Lax` (أو `Strict`
  للتدفّقات الحسّاسة). استخدم البادئة `__Host-` عندما لا توجد
  مشاركة بين النطاقات الفرعية.
- مكِّن Trusted Types حيث يدعمها المتصفح
  (`Content-Security-Policy: require-trusted-types-for 'script'`)
  ليُجبَر إسناد إلى DOM sinks (`innerHTML`،
  `setAttribute('src', ...)` للسكربتات) على المرور عبر policy
  مكتوبة.

### أبدًا
- لا تستخدم `dangerouslySetInnerHTML`، أو `v-html`، أو
  `{@html ...}`، أو `innerHTML =`، أو `document.write` مع مدخلات
  غير موثوقة.
- لا تستخدم `eval`، أو `new Function`، أو `setTimeout(string)`، أو
  `setInterval(string)`، أو `Function('return x')`.
- لا تحقن مدخلات المستخدم في `href`، أو `src`، أو `formaction`، أو
  `action`، أو أي سمة تحمل URL دون التحقّق من المخطّط (احجب
  `javascript:`، و`data:`، و`vbscript:`).
- لا تستخدم `target="_blank"` بدون `rel="noopener noreferrer"` —
  يُسرِّب `window.opener`.
- لا تثق بعقد DOM بناءً على id وحده. DOM clobbering: عنصر
  `<input name="config">` يتحكّم به المهاجم يَحجب
  `window.config`.
- لا تستخدم `postMessage` بدون التحقّق من `event.origin` مقابل
  allowlist.
- لا تخزِّن JWTs، أو رموز التحديث، أو بيانات شخصيّة في
  `localStorage` / `sessionStorage` — أي XSS يُسرِّبها. فضِّل
  cookies من نوع HttpOnly.
- لا تقرأ أو تكتب `document.cookie` من JavaScript لـ cookies
  المصادقة — يجب أن تكون HttpOnly أصلًا.

### إيجابيات خاطئة معروفة
- أدوات الإدارة الداخلية التي تَرسم Markdown / نصًّا غنيًّا عمدًا من
  مؤلّفين موثوقين قد تستخدم `dangerouslySetInnerHTML` بعد المرور
  بمنظِّف؛ وثِّق نداء المنظِّف inline.
- تحتاج إضافات المتصفح أحيانًا إلى `'unsafe-eval'` ضمن CSP
  الإضافة؛ لكن يجب أن يظلّ CSP تطبيق الويب الموجَّه للمستخدم
  حاظرًا لها.
- اتصالات WebSocket إلى نقاط غير same-origin مقبولة عندما يُجري
  الخادم تحقّقًا من الـ origin.

## السياق (للبشر)

ما يزال OWASP XSS Prevention Cheat Sheet المرجع الموثوق لقواعد
التهريب؛ وCSP طبقة الدفاع في العمق التي تحوّل تهريبًا فائتًا إلى
تقرير مُسجَّل بدل جلسة مسروقة. وTrusted Types هي النمط الأحدث
الذي يفرضه المتصفّح، ويُنقل سؤال "هل مرّ هذا بمنظِّف؟" من تدقيق
زمن التشغيل إلى نظام الأنواع.

تميل الواجهات المُولَّدة بالذكاء الاصطناعي إلى الإمساك بـ
`innerHTML` و`dangerouslySetInnerHTML` لأنّها أقصر؛ وهذا الـ skill
هو الثقل المعاكس.

## مراجع

- `rules/csp_defaults.json`
- `rules/xss_sinks.json`
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html).
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — البرمجة عبر المواقع.
- [Trusted Types (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API).
