---
id: serverless-security
language: ar
dir: rtl
source_revision: "afe376a8"
version: "1.0.0"
title: "أمن serverless"
description: "تَقسية Lambda / Cloud Functions / Azure Functions: IAM، ومُهَل، وأسرار، وحَقن أحداث"
category: hardening
severity: high
applies_to:
  - "عند توليد كود AWS Lambda / GCP Cloud Functions / Azure Functions"
  - "عند توليد serverless.yml / قوالب SAM / functions framework"
  - "عند توصيل triggers من API Gateway، وEventBridge، وSQS، وS3"
languages: ["python", "javascript", "typescript", "go", "java", "yaml"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2200
rules_path: "checklists/"
related_skills: ["iac-security", "api-security", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "OWASP Serverless Top 10"
  - "AWS Well-Architected: Security Pillar — Lambda"
  - "CIS AWS Foundations Benchmark §3 (Lambda)"
  - "NIST SP 800-204 (Microservices)"
---

# أمن serverless

## القواعد (لوكلاء الذكاء الاصطناعيّ)

### دائمًا
- أعطِ كلّ function دور تنفيذ IAM خاصًّا بها بِأقلّ الصلاحيّات
  اللازمة. ولا تُشارِك أبدًا الأدوار بين الـ functions، ولا
  تُعيد استخدام دور الـ bootstrap / المطوّر.
- اضبط مُهلة function ملموسة (≤ 30s لِواجهات API متزامنة،
  و≤ 15min لِأشغال خلفيّة). الافتراضات مثل 6s أو 900s مزالق
  بِاتّجاهات مختلفة.
- اضبط حدود concurrency مَحجوزة أو مُجَهَّزة لكلّ function
  لتفادي انفجار الفواتير ومَنع مستأجر صاخب من تجويع بقيّة
  الحساب.
- اسحب الأسرار عند الـ cold-start من secrets manager (AWS
  Secrets Manager / GCP Secret Manager / Azure Key Vault) **مع
  تخزين مؤقّت**، لا من متغيّرات بيئة بِنصّ صريح.
- تَحقَّق من كلّ event payload وفق schema قبل أيّ كود يَلمسه.
  لا تَكترث Lambda أنّ الحدث وَصَل من قائمة SQS "خاصّتك" — فقد
  يكون رسالةً مسمومة.
- فَعِّل تسجيلًا مُبَنْيَنًا يُنَقِّح أنماط أسرار معروفة (فَوِّض
  ذلك إلى skill `logging-security`).
- فَعِّل تتبُّع X-Ray / OpenTelemetry وتنبيهات
  CloudWatch / Cloud Monitoring على معدّل الأخطاء، وعدد عمليّات
  الـ throttle، وزمن p95.
- استخدم VPC لِلـ functions التي تَلمس قاعدة بيانات أو خدمة
  خاصّة؛ وإلّا تَحصل الـ function على egress كامل إلى الإنترنت،
  وهذا نادرًا ما يكون مرغوبًا.

### أبدًا
- لا تَستخدم `arn:aws:iam::*:role/*` (PassRole بِبدل)، أو
  `*:*` action/resource، أو صلاحيّات `iam:*` على دور function.
- لا تَضع الأسرار في متغيّرات بيئة بِنصّ صريح (استخدم مراجع
  Secrets Manager / `aws_lambda_function.environment` مع
  `kms_key_arn`).
- لا تُمرِّر نصوصًا يتحكّم بها المستخدم إلى `exec`، أو
  `os.system`، أو `child_process`، أو
  `subprocess.Popen(shell=True)` — تَتحوّل function URLs إلى
  اختصارات RCE حالما يَنفُذ أحدهم إلى shell.
- لا تَثِق بِـ Lambda function URL أو مورد API Gateway كمصادقة.
  function URLs بـ `AUTH_TYPE=NONE` غير مُصدَّقة؛ اطلب IAM، أو
  Cognito، أو Lambda authorizer.
- لا تُعَطِّل `aws_lambda_function.code_signing_config_arn`
  لِـ functions الإنتاج؛ وَقِّع وتَحقَّق عند الـ deploy.
- لا تَستخدم الوسم `latest` لِـ functions تَستخدم صورة
  حاوية؛ ثَبِّت بِالـ digest.
- لا تَستخدم مفاتيح AWS وصول ساكنة وطويلة العمر لاستدعاء AWS
  من Lambda — استخدم دور التنفيذ.
- لا تَتخَطَّ التحقّق من حُمَل أحداث S3 / SQS / EventBridge —
  اِفترِض أنّ أيّ مُستدعٍ قد يَنشر أيّ شكل، حتى لو كان الـ
  trigger "موثوقًا".

### إيجابيّات خاطئة معروفة
- handlers موارد مُخَصَّصة لـ CloudFormation / Lambda
  (`cfn-response`) قد تَحتاج صلاحيّات واسعة بشكل مشروع لإعداد
  قصير المدى.
- اختراقات تَدفئة الـ cold-start (إرسال ping إلى الـ function
  عبر جدول CloudWatch Events) ليست بِحَدّ ذاتها مسألة أمن.
- مُكَرِّرات Step Functions بِآلاف map states ليست مشكلة
  "concurrency غير مُتتَبَّعة" إذا كان لِـ StateMachine سقف
  concurrency خاصّ بها.

## السياق (للبشر)

تُسَمِّي OWASP في Serverless Top 10 العائلات نفسها كما في Top 10
المعتاد، مع خطرَين خاصَّين بِـ serverless: **حَقن الحدث** (الحدث
نفسه يَحوي مدخلًا غير موثوق — رسالة SQS، أو object key لِـ S3 —
يَتعامل معه كود لاحق كأنّه موثوق)، و**denial-of-wallet** (مهاجم
يَستنزف concurrency لِيَنفُخ فاتورتك).

تَميل مساعدات الذكاء الاصطناعيّ إلى توليد Lambdas بـ IAM `*:*`،
وأسرار في متغيّرات البيئة، وبلا تحقُّق من الأحداث. هذا الـ skill
هو الثقل المضادّ.

## مراجع

- `checklists/lambda_hardening.yaml`
- `checklists/event_validation.yaml`
- [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/).
- [AWS Well-Architected Security Pillar — Serverless](https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/security-pillar.html).
