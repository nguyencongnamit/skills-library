---
id: mobile-security
language: ar
dir: rtl
source_revision: "afe376a8"
version: "1.0.0"
title: "أمن تطبيقات الموبايل"
description: "تَقسية Android وiOS: مكوّنات exported، وATS، وkeychain، وcertificate pinning، وكشف root/jailbreak"
category: hardening
severity: high
applies_to:
  - "عند توليد كود تطبيق Android (Kotlin / Java) أو manifests"
  - "عند توليد كود تطبيق iOS (Swift / Objective-C)"
  - "عند توليد وحدات React Native / Flutter الأصليّة"
languages: ["kotlin", "java", "swift", "objc", "dart", "javascript", "typescript", "xml", "plist"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2500
rules_path: "checklists/"
related_skills: ["crypto-misuse", "secret-detection", "auth-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP MASVS v2.0"
  - "OWASP Mobile Application Security Testing Guide (MASTG)"
  - "CWE-919, CWE-921, CWE-925, CWE-926"
  - "Apple Platform Security Guide"
  - "Android Developers — App Security Best Practices"
---

# أمن تطبيقات الموبايل

## القواعد (لوكلاء الذكاء الاصطناعيّ)

### دائمًا
- **Android**: كلّ `<activity>` و`<service>` و`<receiver>` و`<provider>`
  في `AndroidManifest.xml` إمّا تَحمل `android:exported="false"`، أو
  تُعلِن صراحةً عن intent filter وتُصدَّر عمدًا. منذ Android 12 (API
  31)، يَلزم تعيين `android:exported` كلّما أُعلِن عن intent-filter.
- **Android**: خزِّن الأسرار في **Android Keystore** (`KeyStore` /
  EncryptedSharedPreferences مع `MasterKey`). لا تستخدم أبدًا
  `SharedPreferences` مكشوفة، أو ملفّات مكشوفة، أو `BuildConfig`.
- **iOS**: خزِّن الأسرار في **Keychain** بـ
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` أو أصرم. لا
  تَستخدم `UserDefaults` أو plist أو ملفّات.
- **iOS**: أَبقِ App Transport Security (ATS) مُفعَّلًا في
  `Info.plist`. وإن لَزم استثناء، فاحصره في host بعينه عبر
  `NSExceptionDomains`.
- تَحقَّق من شهادة TLS للخادم بـ **certificate pinning** (مع تفضيل
  pinning للمفتاح العامّ) للخلفيّات التي تُديرها. استخدم
  `OkHttp.CertificatePinner` على Android، و
  `URLSessionDelegate didReceiveChallenge` على iOS، أو الوحدة المكافئة
  في إطار العمل.
- خَفِّ / قَلِّص حِزم الإصدار (Android R8 / ProGuard مع
  `proguard-rules.pro`؛ iOS bitcode + تجريد رموز Swift). جَرِّد سجلّات
  debug من حِزم الإصدار.
- اكشف الأجهزة المَجذورة / المكسورة الحماية في تطبيقات عالية المخاطر
  (مصرفيّة، مدفوعات، مؤسّسيّة)، وخَفِّض الحسّاسيّة (احظر المدفوعات،
  ارفض الانضمام إلى managed profile). استخدم Play Integrity API على
  Android و`DeviceCheck` / `AppAttest` على iOS بوصفها التصديق
  المعتمَد.

### أبدًا
- لا تَشحن مفاتيح API، أو مفاتيح التوقيع، أو أسرار الخلفيّة في
  source أو resources أو `strings.xml` أو `BuildConfig` أو
  `Info.plist`. بل أَصدر tokens قصيرة العمر مَحصورة بالجهاز من
  الخلفيّة.
- لا تَضع `android:allowBackup="true"` لتطبيقات تُخزِّن اعتمادات —
  فالبيانات المنسوخة احتياطيًّا تُقرأ على أجهزة المطوِّرين. استخدم
  `android:fullBackupContent` لاستبعاد المسارات الحسّاسة.
- لا تَضع `android:debuggable="true"` في حِزم الإصدار، ولا
  `<application android:networkSecurityConfig>` يَسمح بالنصّ الصريح
  إلى مضيفين عشوائيّين.
- لا تُعطِّل ATS على مستوى التطبيق في iOS
  (`NSAllowsArbitraryLoads=true`). فإن وَجَب إضعافه، فاحصره لكلّ
  host على حِدة.
- لا تُنفِّذ معالجةً مُخصَّصة لـ TLS / الشهادات تَعود بـ "ثِق بالكلّ"
  (`X509TrustManager.checkServerTrusted` بِجِسم فارغ، أو
  `URLSessionDelegate` يَثِق دومًا). فهذا هو المُكتشَف الأمنيّ رقم 1
  الذي يَصل إلى إنتاج Android.
- لا تُمرِّر مُدخَلات المستخدم إلى `WebView.loadUrl` /
  `WKWebView.load` دون التحقّق من scheme؛ ولا تُفعِّل أبدًا
  `WebSettings.setAllowFileAccessFromFileURLs(true)` أو
  `setUniversalAccessFromFileURLs(true)`.
- لا تُنفِّذ مصادقة حيويّة (biometric) دون ربط المفتاح بـ
  `setUserAuthenticationRequired(true)` في `BiometricPrompt` —
  فالحصول على "true" من البصمة وحدها لا يُثبت شيئًا بلا تحدٍّ
  تشفيريّ.
- لا تُسجِّل أجسام الطلبات / الاستجابات كاملةً، بما في ذلك ترويسات
  `Authorization` — فهي تَنتهي في سجلّات adb / xcrun.

### إيجابيّات خاطئة معروفة
- المعرِّفات العامّة المقروءة فقط (مفتاح عامّ لـ analytics، أو DSN
  عامّ) المضمَّنة في الثنائيّ ليست أسرارًا؛ بل وُجِدَت قصدًا.
- كون `debuggable=true` افتراضيًّا في variants debug أمر طبيعيّ —
  والقاعدة تَسري على حِزم الإصدار.
- مخطّطات URL مُخصَّصة (`myapp://`) لردود نداء OAuth أمر متوقَّع؛
  تأكَّد أنّ intent filter المقابل مُقيَّد، وأنّ معامل `state` يُتحقَّق
  منه.

## السياق (للبشر)

ينقسم أمن الموبايل بوضوح إلى **ما هو داخل الثنائيّ** (أسرار،
debug flags، مكوّنات exported، pinning)، و**ما يَحدث وقت التشغيل**
(الثقة بـ TLS، الوصول إلى keychain، ربط الحيويّ). يَوفِّر OWASP MASVS
v2 الضوابط القابلة للاختبار المعتمَدة؛ في حين أنّ MASTG هو الدليل
الإجرائيّ للاختبار.

كثيرًا ما تُوَلِّد مساعِدات الذكاء الاصطناعيّ كود Android بـ
`allowBackup=true`، ودون ProGuard، ومع مفاتيح API مُصلَّبة في
`strings.xml`، وكود iOS يَستدعي `SecCertificateCreateWithData` بلا
تحقّق. وهذا الـ skill هو الموازنة لذلك.

## مراجع

- `checklists/android_manifest.yaml`
- `checklists/ios_keychain_ats.yaml`
- [OWASP MASVS](https://mas.owasp.org/MASVS/).
- [OWASP MASTG](https://mas.owasp.org/MASTG/).
