---
id: file-upload-security
language: ar
dir: rtl
source_revision: "4c215e6f"
version: "1.0.0"
title: "أمن رفع الملفات"
description: "التحقّق من رفع المستخدمين: magic bytes لـ MIME، وتنظيف أسماء الملفات، وحدود الحجم، ونطاق تقديم منفصل، وفحص مضاد للفيروسات، وكشف polyglot"
category: prevention
severity: high
applies_to:
  - "عند توليد نقطة نهاية HTTP لرفع الملفات"
  - "عند توصيل الرفع عبر URL مُوقَّع مسبقًا إلى S3 / GCS / Azure Blob"
  - "عند إضافة معالجة الصور / PDF / المستندات لرفع المستخدمين"
  - "عند مراجعة تخزين وتقديم المحتوى المُولَّد من المستخدم"
languages: ["*"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "ssrf-prevention", "infrastructure-security", "cors-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP File Upload Cheat Sheet"
  - "CWE-434: Unrestricted Upload of File with Dangerous Type"
  - "CWE-22: Path Traversal"
  - "CVE-2018-15473 (libmagic), CVE-2016-3714 (ImageTragick)"
---

# أمن رفع الملفات

## القواعد (لوكلاء الذكاء الاصطناعي)

### دائمًا
- تحقّق من **magic bytes** لكل ملف مرفوع من جانب الخادم. الـ
  `Content-Type` وامتداد الملف يتحكّم بهما المهاجم ولا يكفيان أبدًا.
  استخدم libmagic، أو `file-type` (Node)، أو `mimetypes-magic`
  (Python)، أو Tika.
- احتفظ بـ **allowlist** بالأنواع المقبولة لكل نقطة نهاية
  (`image/png`، `image/jpeg`، `application/pdf`، …). ارفض ما عداها،
  بما فيها `text/html`، و`image/svg+xml` (تحمل `<script>`)،
  و`text/xml`، و`application/octet-stream`.
- نظِّف أسماء الملفات: انزع مكوّنات المسار، وطبِّع Unicode، وارفض
  `..`، وبايت NUL، وأحرف التحكّم، وأسماء Windows المحجوزة (`CON`،
  `PRN`، `AUX`، `NUL`، `COM1-9`، `LPT1-9`)، وأي محرف خارج
  `[a-zA-Z0-9._-]`. احفظ بصيغة UUID / hash وأبقِ الاسم الأصلي في
  عمود metadata منفصل ومُفلَّت.
- افرض **حدّ حجم** عند الـ proxy / بوّابة الـ API *و* في التطبيق —
  بطبقتين على الأقل. حدّ الـ proxy يمنع هجمات استنزاف عرض النطاق؛
  وحدّ التطبيق يمنع استنزاف الذاكرة عندما يكون الـ proxy مضبوطًا
  خطأ.
- خزِّن الملفات المرفوعة **خارج جذر الوثائق** وقدِّمها من نطاق
  منفصل (`usercontent.example.net`) عبر CDN. اضبط
  `Content-Disposition: attachment` للأنواع غير الصور، وضع هيدر
  `Content-Security-Policy: default-src 'none'; sandbox` لإبطال أي
  HTML/SVG يُرسَم inline.
- شغِّل **ماسحًا للفيروسات** (ClamAV، VirusTotal، Sophos) على كل
  ملف مرفوع قبل إتاحته للمستخدمين الآخرين — خارج النطاق حتى لا
  يلتصق الطلب نفسه بالكمون.
- أعِد ترميز الوسائط من جانب الخادم: `convert in.jpg out.jpg`
  (ImageMagick مع `policy.xml` صارم)، و`ffmpeg -i` للفيديو،
  و`pdftocairo` لملفات PDF. إعادة الترميز تُزيل معظم حمولات
  polyglot / الإخفاء وثغرات codec الغريبة.
- لـ SVG تحديدًا: إمّا أن ترسمه من جانب الخادم إلى صيغة شبكيّة، أو
  مرّره عبر منظِّف بـ allowlist صارم (DOMPurify في Node،
  `lxml.html.clean` في Python) يُزيل `<script>`، و`<iframe>`،
  و`<foreignObject>`، و`xlink:href` ذات `javascript:`، وكذلك CSS
  مع expression / url() لـ URIs غير data.

### أبدًا
- لا تثق بـ `Content-Type` القادم من العميل. مُستشعِر MIME في IE /
  Chrome الأقدم يقرأ المتن بحثًا عن إشارات النوع — حمولة HTML
  متخفّية بصيغة `image/png` ستعمل بوصفها HTML عند تقديمها على
  same-origin.
- لا تَبنِ مسار التخزين باسم الملف المُورَّد من المستخدم. كلٌّ من
  Path traversal (`../../etc/passwd`) وفئة الأسماء المحجوزة في
  Windows يُختزلان إلى "اسمح للمهاجم بأن يختار أين يكتب".
- لا تُقدِّم الملفات المرفوعة من الـ origin نفسه للتطبيق. تقديمها على
  `api.example.com/uploads/x.html` يعني أن حمولة HTML خبيثة تعمل
  بوصول كامل إلى ملفات تعريف ارتباط api.example.com وإلى CORS.
- لا تستخدم stack يعالج الملفات المرفوعة عبر ImageMagick / libraw /
  ExifTool / ffmpeg بلا policy.xml صارم / sandbox / ضبط للإصدارات.
  اعتمدت كلتا ثغرتَي ImageTragick (CVE-2016-3714) وExifTool في
  GitLab (CVE-2021-22205) على خادم يمرّر بايتات يتحكّم بها المستخدم
  بسعادة إلى مكتبة وسائط.
- لا تسمح برفع PDF + رسمه داخل المتصفح دون التحقّق من أن الـ PDF يجتاز
  تحقّقًا بنيويًّا (مثل `pdfinfo`). ملفات PDF الخبيثة بدائيّة شائعة
  لتنفيذ كود عن بُعد عبر JavaScript-في-PDF / XFA ضد Adobe Reader
  لدى المستلِم، حتى عندما يكون الخادم آمنًا.
- لا تستخدم استخراج `.docx` / `.xlsx` / `.zip` عبر `unzip` أو
  `python -m zipfile` دون مُستخرِج آمن ضد Path traversal. أخرجت
  Zip slip (CVE-2018-1002201) ملفات خارج المجلد الهدف عبر مدخلات
  `../`.
- لا تستخدم روابط الرفع المُوقَّعة مسبقًا في S3 / GCS دون شرط
  `Content-Type` موقَّع وصارم وبادئة object-key ثابتة. بدون هذه
  الشروط، يستطيع العميل رفع أيّ شيء إلى أيّ مفتاح.

### إيجابيات خاطئة معروفة
- قد تكون عمليات رفع الإدارة الداخلية فقط (مثل لوحة عمليات) محقّة في
  الوثوق بامتداد الملف لأن حدّ الثقة هو SSO + قائمة سماح IP. وثِّق
  ذلك بوصفه قرارًا مقصودًا في نقطة النهاية.
- تحتاج بعض التكاملات (مثل تصدير CSV من أدوات BI) إلى تدوير أسماء
  الملفات المُورَّدة من المستخدم؛ احفظها في الـ metadata، لكن يبقى
  الاسم على القرص UUID.
- لا تحتاج ملفات tarball / DEB / RPM في خط أنابيب البناء إلى فحص
  مضاد فيروسات — حدّ الثقة هو مفتاح التوقيع لخط البناء، لا الـ AV.

## السياق (للبشر)

رفع الملفات سطح هجوم غنيّ ودائم. كل مختبر اختراق في الواقع يبدأ
بحركة مبكرة من نوع "ابحث عن نموذج رفع"، لأن المسار من الرفع إلى
RCE قصير في الغالب: رفع ملف HTML فيه سارق اعتمادات بـ JavaScript،
أو رفع shell بـ PHP / JSP إلى doc-root مضبوط خطأ، أو رفع SVG فيه
`<script>` يسرق SAML، أو رفع صورة بحمولة EXIF إلى خدمة ImageMagick
هشّة.

الدفاعات معروفة جيدًا وقليلة الكلفة — العلّة أنّها تحتاج إلى تطبيقها
مجتمعةً. allowlist لـ magic bytes تُلتفّ بسهولة عبر polyglot (ملف
صحيح PNG وصفحة HTML صحيحة في الوقت ذاته). نطاق تقديم منفصل يُبطل
تنفيذ HTML الذي يحمله الـ polyglot. ماسح الفيروسات يلتقط البرمجيات
الخبيثة المعروفة. إعادة الترميز تُزيل حمولات codec الغريبة. كل دفاع
طبقة؛ نقص طبقة واحدة يحوّل معظم عمليات الرفع من "بيانات مخزَّنة" إلى
"RCE مخزَّن".

## مراجع

- `rules/upload_validation.json`
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).
- [CWE-434](https://cwe.mitre.org/data/definitions/434.html).
- [CWE-22 (Path Traversal)](https://cwe.mitre.org/data/definitions/22.html).
- [Snyk Zip Slip directory](https://snyk.io/research/zip-slip-vulnerability).
- [ImageTragick (CVE-2016-3714)](https://imagetragick.com/).
