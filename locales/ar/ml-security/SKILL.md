---
id: ml-security
language: ar
dir: rtl
source_revision: "afe376a8"
version: "1.0.0"
title: "أمن ML / LLM"
description: "حقن prompt، وتسميم النماذج، وهجمات إلغاء التسلسل، وPII في بيانات التدريب، وتسرّبات أسرار في notebooks"
category: prevention
severity: high
applies_to:
  - "عند توليد كود يَستدعي API لـ LLM أو يبني وكيلًا مدفوعًا بـ LLM"
  - "عند توليد كود يُحمِّل نماذج ML من القرص / Hub / S3"
  - "عند توليد pipelines بيانات تَستوعب محتوى مستخدم لـ fine-tuning"
languages: ["python", "javascript", "typescript", "jupyter", "go"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2700
rules_path: "rules/"
related_skills: ["secret-detection", "supply-chain-security", "api-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP Top 10 for LLM Applications 2025"
  - "NIST AI 100-2 (Adversarial Machine Learning)"
  - "MITRE ATLAS (Adversarial Threat Landscape for AI Systems)"
  - "CWE-502, CWE-1039, CWE-1426"
---

# أمن ML / LLM

## القواعد (لوكلاء الذكاء الاصطناعي)

### دائمًا
- عامِل كل مدخل للنموذج — بما في ذلك مخرجات الـ tools والوثائق
  المُستَرجَعة المُعادة إلى الـ prompt — على أنّه غير موثوق. فحقن
  الـ prompt غير المباشر عبر صفحة وب أو وثيقة مُستَرجَعة هو هجوم
  LLM الأكثر شيوعًا في البريّة.
- نَقِّ وأَعِد ترميز أيّ شيء يُصدِره النموذج قبل إعطائه لنظامٍ
  تابعٍ في الاتّجاه السفليّ: بَناء SQL، أو shell، أو كاتب ملفّات،
  أو طلب HTTP، أو مُقَيِّم كود. فمُخرَج النموذج ليس أبدًا مفتاحًا
  أوّليًّا للثقة.
- افرض **schema للمُخرَج** بتوليد مُهيكَل (JSON Schema، أو نمط
  function-call، أو decoding مقيَّد) حين تَستهلك الخطوة التالية
  المُخرَج برمجيًّا. وارفض كل ما يَفشل التحقّق.
- احتفظ بقائمة بيضاء (allowlist) من tools / أسماء دوال يستطيع
  النموذج استدعاءها؛ ارفض أيّ استدعاء آخر. وطبِّق التفويض لكلّ
  tool على *المستخدم البشريّ* للوكيل، لا على النموذج وحده.
- لـ RAG: اختم الوثائق المُستَرجَعة بمصدرها (provenance)، وافصل بين
  "التعليمات" و"السياق" في الـ prompt؛ ولا تَدَع البيانات
  المُستَرجَعة تُلغي تعليمات النظام.
- عند تحميل النماذج، استخدم **safetensors** لـ PyTorch و
  Hugging Face؛ واستخدم `weights_only=True` مع `torch.load` على
  PyTorch 2.4+؛ ولا تُحمِّل أبدًا ملفّات `.pkl` / `.pt` عشوائيّة
  من مصادر غير موثوقة.
- نَظِّف PII، والاعتمادات، والأسرار من بيانات التدريب — عند
  المصدر (استيعاب البيانات)، وفي التخزين (تشفير + ضوابط وصول)،
  وفي المُخرَج (مرشِّحات / كواشف الردّ).
- ضع rate-limit / حصّة على كل endpoint مدعوم بـ LLM. وتَتَبَّع
  إنفاق tokens لكل tenant.
- تَتَبَّع كل prompt + إصدار النموذج + السياق المُستَرجَع بوصفه
  سجلّ تدقيق؛ ونَقِّ الأسرار قبل ذلك.

### أبدًا
- لا تُنفِّذ `pickle.loads` / `joblib.load` / `dill.loads` /
  `torch.load` على أداةٍ مُجلَبَةٍ في وقت التشغيل من مصدرٍ غير
  موثوق. فهذه مُفكِّكات التسلسل تُنفِّذ كودًا اعتباطيًّا بالتصميم.
- لا تَدمج مدخل المستخدم مباشرةً داخل prompt يحوي تعليمات أعلى
  ثقةً، مثل `f"You are a helpful agent. {user_input}"`. استخدم
  حدًّا بقالب، مع فصلٍ صريحٍ للدور النظاميّ.
- لا تُمرِّر سلسلة مشتقّة من LLM مباشرةً إلى `eval`، أو `exec`، أو
  `os.system`، أو `subprocess(shell=True)`، أو
  `vm.runInNewContext`، أو نداء `.raw()` لـ SQL.
- لا تُصلِّب مفاتيح API لـ OpenAI / Anthropic / Cohere داخل
  notebooks أو ملفّات المستودع. استخدم متغيّرات بيئة وskill
  `secret-detection`.
- لا تُخزِّن أمثلة بيانات تدريب تحوي PII في تخزينٍ بعيد المدى بلا
  موافقة صريحة، ونوافذ احتفاظ، وAPIs حذف.
- لا تَثِق بمُعطَيات نموذج يُورِّدها العميل (اسم النموذج، أو
  system prompt، أو قائمة tools) بلا تحقّق من جانب الخادم — فالعملاء
  سيُخفِّضون إلى نماذج أرخص / أضعف / غير مُصرَّح بها.
- لا تستخدم نموذجًا مُدرَّبًا بدقّة من قِبَل بائع خارجيّ بلا تحقّق
  من المصدر / النسب.
- لا تُخزِّن ردود LLM في cache مفهرَسة بنصّ الـ prompt وحده — فذلك
  يَمزج سياقات المستخدمين حين تَتشارَك الـ prompts بادئات.

### إيجابيات خاطئة معروفة
- notebooks البحث / red-team التي تُمارس prompts jailbreak قصدًا
  تَنتمي إلى بيئة معزولة بلا اعتمادات إنتاج.
- النماذج الأكاديميّة قبل النشر من مؤلِّفين موثوقين تُوزَّع عادةً
  بوصفها checkpoints `.pt`؛ حوِّلها إلى safetensors كخطوةٍ أولى.
- pipelines توليد البيانات التركيبيّة قد تُنتج مشروعًا مُخرَجَ
  نموذج خامًا يُرفَع لاحقًا بـ commit — تَحقَّق من وسمه ومن
  مراجعته لاكتشاف PII / أسرار مهلوسة عَرَضًا.

## السياق (للبشر)

تُجمِّع OWASP LLM Top 10 (2025) أكثر الهجمات شيوعًا في عشر فئات؛
وتُمثِّل **LLM01 Prompt Injection** و**LLM05 Improper Output
Handling** الهمَّ التشغيليّ الأكبر لأنّهما يَنطبقان على كلّ نشرٍ
وكيليٍّ تقريبًا. ويُؤطِّر NIST AI 100-2 فئات ML الخصميّ الأساسيّة
(evasion، وpoisoning، وextraction)؛ ويُقدِّم MITRE ATLAS رؤية
kill-chain.

يَفترض هذا الـ skill أنّ Devin (أو أيّ مساعد ذكاءٍ اصطناعيّ) هو
مَن يَبني التطبيق المُستخدِم لـ LLM. عامِل التطبيقَ الناتجَ على
أنّه حدٌّ أمنيّ — حتى لو كان "المستخدم" وكيلَ ذكاء اصطناعيّ آخر.

## مراجع

- `rules/prompt_injection_patterns.json`
- `rules/unsafe_deserialization.json`
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/).
- [NIST AI 100-2](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2023.pdf).
- [MITRE ATLAS](https://atlas.mitre.org/).
- [CWE-1426](https://cwe.mitre.org/data/definitions/1426.html) — Improper Validation of Generative AI Output.
