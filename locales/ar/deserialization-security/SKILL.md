---
id: deserialization-security
language: ar
dir: rtl
source_revision: "4c215e6f"
version: "1.0.0"
title: "أمن إلغاء التسلسل"
description: "حظر إلغاء التسلسل غير الآمن في Java و Python و .NET و PHP و Ruby و Node.js — سلاسل gadget، وقوائم سماح للأنواع، وبدائل أكثر أمانًا"
category: prevention
severity: critical
applies_to:
  - "عند توليد شيفرة تُلغي تسلسل بيانات من أي مصدر غير موثوق"
  - "عند توصيل ملفات تعريف الارتباط أو الجلسات أو قوائم الرسائل أو حمولات RPC"
  - "عند مراجعة استخدام pickle / unserialize / Marshal / ObjectInputStream / BinaryFormatter"
languages: ["java", "python", "csharp", "php", "ruby", "javascript", "typescript"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "crypto-misuse", "supply-chain-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP Deserialization Cheat Sheet"
  - "CWE-502: Deserialization of Untrusted Data"
  - "CVE-2017-9805 (Struts2 XStream)"
  - "CVE-2016-4437 (Shiro RememberMe)"
  - "CVE-2019-2725 (WebLogic XMLDecoder)"
---

# أمن إلغاء التسلسل

## القواعد (لوكلاء الذكاء الاصطناعي)

### دائمًا
- فضِّل الصيغ **الهيكلية المُتحقَّق منها بـ schema** (JSON مع مُحقِّق
  JSON Schema، أو Protobuf، أو FlatBuffers، أو MessagePack مع خريطة
  أنواع صريحة) على المُسلسِلات الأصلية متعدّدة الأشكال. لا تستحق
  مقايضة "توفير 10 أسطر من شيفرة الربط" أبدًا أن تنتج بدائية تنفيذ
  كود عن بُعد.
- حين يكون مُلغي تسلسل متعدّد الأشكال أمرًا حتميًّا، اضبط **قائمة سماح
  أنواع صارمة** على مستوى الإطار (`PolymorphicTypeValidator` لـ
  Jackson، وsafeMode لـ fastjson، و`KnownTypeAttribute` لـ .NET،
  و`Whitelist` لـ XStream). الافتراضي "any class" هو مصدر كل CVE
  حديثة لإلغاء التسلسل في Java.
- وقّع وأمّن أي ملف تعريف ارتباط أو token يحمل بيانات مُسلسلة بمفتاح
  عشوائي جديد (HMAC-SHA-256، كحدّ أدنى). لا تُلغِ التسلسل قبل التحقّق
  من HMAC أبدًا.
- شغّل مسارات شيفرة إلغاء التسلسل بأدنى الصلاحيات التي تحتاجها الصيغة
  (بدون نظام ملفات، بدون شبكة، بدون عمليات فرعية، بدون reflection) —
  مثل أنماط `ObjectInputFilter` في Java؛ وPython في نطاق أسماء
  مقيَّد.
- اعتبر كلًّا من الدوال الآتية "بدائيات إلغاء تسلسل لمدخل غير موثوق":
  Java `ObjectInputStream.readObject`، وJackson مع
  `enableDefaultTyping`، وSnakeYAML `Yaml.load()`، وXStream
  `fromXML`، وPython `pickle.load(s)` / `cPickle` / `dill` /
  `joblib.load`، و`yaml.load` (الـ Loader الافتراضي)،
  و`numpy.load(allow_pickle=True)`، و`torch.load`، وPHP
  `unserialize`، و.NET `BinaryFormatter` / `ObjectStateFormatter` /
  `NetDataContractSerializer` / `LosFormatter`، وRuby `Marshal.load`
  / `YAML.load` (Psych ≤ 3.0). إضافة إحداها إلى مسار معالجة طلب يستلزم
  مراجعة أمنية صريحة.

### أبدًا
- لا تُمرّر بايتات غير موثوقة إلى أيٍّ من البدائيات أعلاه دون غلاف
  مُصدَّق بـ HMAC. حتى مع الغلاف، فضِّل صيغة غير متعدّدة الأشكال.
- لا تستخدم Jackson في Java مع
  `objectMapper.enableDefaultTyping()` أو
  `@JsonTypeInfo(use = Id.CLASS)`. الافتراضي
  `LAMINAR_INTERNAL_DEFAULT` يُنتج سلسلة gadget بمعرّف الصنف
  (ysoserial / marshalsec).
- لا تستخدم SnakeYAML `new Yaml()` دون تعيين `SafeConstructor`
  بشكل صريح (أو `Constructor` مع allowlist). فالـ constructor
  الافتراضي هو مصدر CVE الشائعة لتنفيذ كود عن بُعد عبر YAML في Java.
- لا تستخدم Python `pickle.loads` على بيانات من مقبس شبكة أو عمود
  قاعدة بيانات أو مفتاح في Redis cache أو أي مكان يعبر حدًّا للثقة.
  لا قدر من التحقق يجعل pickle آمنًا.
- لا تستخدم Python `yaml.load(data)` (دون
  `Loader=yaml.SafeLoader`). غيّر PyYAML الافتراضي في 6.0 ليفشل
  بصوت عالٍ — لكن مسارات شيفرة قديمة ما زالت تحمل الافتراضي غير
  الآمن.
- لا تستخدم Python `torch.load(path)` على checkpoint مُنزَّل دون
  `weights_only=True` (الافتراضي في PyTorch ≥ 2.6 هو True؛ الإصدارات
  الأقدم تصل إلى pickle وتنفّذ شيفرة عشوائية).
- لا تستخدم PHP `unserialize()` على بيانات ملف تعريف ارتباط /
  POST / GET. لتنسيق PHP المُسلسَل تاريخ طويل من سلاسل gadget عبر
  الطرق السحرية (`__wakeup`، `__destruct`، `__toString`).
- لا تستخدم .NET `BinaryFormatter`، `NetDataContractSerializer`،
  `ObjectStateFormatter`، `LosFormatter` على أيّ مدخل يعبر حدًّا
  للثقة. تصنّف Microsoft `BinaryFormatter` على أنّه مهجور وغير آمن.
- لا تثق بمحتوى Ruby `Marshal.load` القادم من خارج العملية نفسها.
  ينطبق القيد ذاته على `YAML.load` في إصدارات Psych الأقدم.

### إيجابيات خاطئة معروفة
- RPC داخلي يكون فيه الطرفان تحت تحكم المُشغّل، والبيانات مُصدَّقة من
  طرف إلى طرف (mTLS + HMAC)، واختيار الصيغة عمليّ (مثلًا، خدمات
  Java تستعمل ObjectInputStream فوق مقبس TLS+mTLS-only قد يكون
  مقبولًا في بعض الـ stacks الموروثة).
- إلغاء تسلسل في وقت البناء / الإعداد لملفات شُحنت في المستودع
  (fixtures اختبار بـ pickle، إلخ) — لكن مع تمييز ذلك بوضوح وعدم
  تحميلها أبدًا من أيّ تنزيل.
- صيغ جلسات مُصدَّقة تشفيريًّا كجلسات الكوكي الموقَّعة الافتراضية في
  Rails هي استعمال مقصود لـ Marshal، لكن فقط لأن HMAC يحرس عملية
  إلغاء التسلسل.

## السياق (للبشر)

ثغرات إلغاء التسلسل هي بدائية RCE الأكثر اعتمادية في الـ stacks
المؤسّسية الحديثة. الاقتصاديات بسيطة: حين يسمح المُسلسِل بإنشاء
كائنات من أصناف اعتباطية، تكون الشيفرة قد استوردت فعلًا آلاف
الأصناف — كثير منها له آثار جانبية في رِدّ الاتصال `readObject` أو
`__reduce__` أو `__wakeup` أو `Read*`. سلسلة gadget تربط هذه الآثار
الجانبية لتُنتج RCE.

ysoserial (Java)، وysoserial.net (.NET)، وmarshalsec (Java)،
وكتالوجات gadget لـ pickle في Python أدوات ناضجة. سؤال "هل هذا قابل
للاستغلال؟" تجد جوابه دومًا: "نعم، باستخدام gadget موجودة فعلًا في
classpath لديك".

الإصلاح ليس التصفية — بل اختيار صيغة لا تسمح أصلًا بإنشاء كائنات من
أصناف اعتباطية. تشحن أغلب الخدمات الحديثة JWTs موقّعة / JSON فوق
mTLS. وحيث لا مفرّ من صيغة متعدّدة الأشكال، تكون allowlist للأنواع
وHMAC غير قابلتَين للتفاوض.

## مراجع

- `rules/unsafe_deserializers.json`
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html).
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- [ysoserial](https://github.com/frohoff/ysoserial).
- [ysoserial.net](https://github.com/pwntester/ysoserial.net).
- [marshalsec](https://github.com/frohoff/marshalsec).
