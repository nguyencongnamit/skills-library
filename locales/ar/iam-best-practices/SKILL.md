---
id: iam-best-practices
language: ar
dir: rtl
source_revision: "6de0becf"
version: "1.0.0"
title: "أفضل ممارسات إدارة الهويّة والوصول"
description: "تصميم IAM بأقلّ امتياز، وتدوير المفاتيح، وفرض MFA، وتولّي الأدوار، وأنماط الوصول عبر الحسابات لـ AWS / GCP / Azure / Kubernetes"
category: prevention
severity: critical
applies_to:
  - "عند توليد policies أو roles أو وثائق trust لـ IAM"
  - "عند توصيل service accounts لـ CI/CD أو workload identities"
  - "عند مراجعة إنشاء access keys أو تدويرها أو إبطالها"
  - "عند تصميم وصول عبر الحسابات أو عبر المستأجرين"
languages: ["hcl", "yaml", "json", "python", "go", "typescript"]
token_budget:
  minimal: 1100
  compact: 1500
  full: 2400
rules_path: "rules/"
related_skills: ["auth-security", "iac-security", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "NIST SP 800-53 Rev. 5 (AC-2, AC-3, AC-6, AC-17, IA-2, IA-5)"
  - "NIST SP 800-63B (Authenticator Assurance)"
  - "CIS Controls v8 (Controls 5 and 6)"
  - "AWS IAM Best Practices"
  - "Google Cloud IAM Recommender"
  - "Microsoft Azure RBAC Best Practices"
  - "CNCF Kubernetes RBAC Good Practices"
  - "OWASP Cloud Security Top 10"
---

# أفضل ممارسات إدارة الهويّة والوصول

## القواعد (لوكلاء الذكاء الاصطناعي)

### دائمًا
- امنح **الحدّ الأدنى** من الصلاحيّات الذي يحتاجه الـ workload لأداء
  مهمّته المُعلَنة (NIST AC-6). ابدأ بـ policy على أساس
  deny-by-default، ثمّ أَضِف إجراءات ملموسة بـ ARNs `Resource`
  صريحة؛ ولا تستخدم أبدًا `Action: "*"` مع `Resource: "*"`.
- فضِّل **workload identity** (IAM roles for service accounts على
  EKS، وGKE Workload Identity، وAzure Managed Identity) على access
  keys طويلة العمر. فالـ access keys الثابتة استثناء، لا الإعداد
  الافتراضيّ.
- اشترط **MFA** لكل IAM user بشريّ، وبصفة خاصّة لأيّ principal قادر
  على تولّي role مميَّز. وافرض MFA عبر شرط في policy IAM
  (`aws:MultiFactorAuthPresent: true`)، وليس على مستوى الدليل فقط.
- دوِّر access keys، وservice-account keys، ومفاتيح التوقيع وفق
  جدول موثَّق (≤ 90 يومًا). واكتشف الاعتمادات الخاملة (≥ 90 يومًا
  بلا استخدام) وعطِّلها تلقائيًّا.
- استخدم **تولّي role بـ `sts:AssumeRole` + ExternalId** للتثبّت
  من الثقة بين الحسابات. ويجب أن يكون ExternalId فريدًا لكل
  مستهلِك، ومخزَّنًا بوصفه سرًّا في الحسابين معًا.
- أصدِر اعتمادات **محصورة بالجلسة** بـ `MaxSessionDuration ≤ 1h`
  لأدوار البشر، و≤ 12h لأدوار break-glass. فالجلسات طويلة العمر
  تُلغي التدوير عمليًّا.
- افصل بين هويّات **deploy** و**runtime**. تأخذ pipeline الـ CI/CD
  role-deploy؛ ويأخذ الخدمة قيد التشغيل role-runtime متميِّزًا بلا
  أيّ صلاحيّات تُغيِّر IAM.
- في RBAC لـ Kubernetes، احصر `Role` / `RoleBinding` في namespace
  واحد؛ ولا تستخدم `ClusterRole` إلّا لكائنات على نطاق الـ cluster
  فعلًا. وراجِع روابط `cluster-admin` في كل PR.
- سَجِّل كل نداء يُغيِّر IAM (CloudTrail / Cloud Audit Logs / Azure
  Activity Log) إلى sink مقاوم للعبث. ونبِّه على تغييرات الـ policy،
  و`iam:PassRole`، و`iam:CreateAccessKey`، و`sts:AssumeRole` من
  principals غير متوقَّعة.
- لوصول **break-glass** (root، وowner، وcluster-admin)، اشترط
  موافقة خارج النطاق (مثلًا حادثة PagerDuty + تذكرة)، وأصدِر تنبيهًا
  فوريًّا عند كل استخدام.
- وسِّم كل principal لـ IAM بـ `owner`، و`environment`،
  و`purpose`. واستخدم هذه الوسوم في SCPs / policies المنظَّمة
  لتقييد نصف قطر الانفجار.

### أبدًا
- لا تستخدم حساب **root** في العمليّات اليوميّة. تَحصُل اعتمادات
  root على جهاز MFA أجهزة، وتُحفظ بلا اتصال، ولا تُستخدم إلّا
  للقائمة الصغيرة من المهامّ الحصريّة على root (مثلًا إغلاق الحساب،
  أو تغيير خطّة الدعم).
- لا تُضمِّن access keys طويلة العمر في الكود أو صور container أو
  AMIs أو متغيّرات بيئة CI حين تتوفّر workload identity.
- لا تَمنح `iam:PassRole` بـ `Resource: "*"`. ثَبِّت دائمًا ARNs
  أدوار التي يمكن للـ caller تمريرها إلى خدمات downstream.
- لا تَمنح `iam:*` أو `sts:*` لـ workload-runtime — فهذه صلاحيّات
  وقت deploy فقط.
- لا تُشارِك IAM user واحد بين بشرٍ أو خدمات متعدّدة. فـ principal
  واحد لكل هويّة هو ثابت التدقيق.
- لا تستخدم managed policy `AdministratorAccess` (أو أيّ `*:*`)
  بشكلٍ روتينيّ؛ عامِلْها مرفقًا حصريًّا لـ break-glass.
- لا تَثِق بأيّ assume-role عابر للحسابات بلا شرط `ExternalId`
  لدمج طرف ثالث (Confused Deputy: AWS Security Bulletin 2021).
- لا تُصلِّب ARNs / resource IDs لـ AWS / GCP / Azure في وثائق
  policy بلا نطاق مرتبط بوسم أو بمسار منظَّمة (حين قد يَنمو عدد
  الموارد).
- لا تُعطِّل MFA على principal لـ "حلِّ" مشكلة تسجيل دخول — دوِّر
  الجهاز، ولا تُزِل المتطلَّب.
- لا تَحفظ tokens تأكيد OIDC / SAML بعد TTL المُعلَن لها. جدِّد
  بإعادة التأكيد، لا بتخزين الـ token الأصليّ.

### إيجابيات خاطئة معروفة
- `Resource: "*"` مقبول لعمليّات قراءة محصورة طبيعيًّا بمستوى
  الحساب مثل `ec2:DescribeRegions` أو `sts:GetCallerIdentity` —
  فهذه الـ APIs لا تَقبل ARN موارد.
- service-linked roles (مثلًا `AWSServiceRoleForAutoScaling`)
  تأتي بصلاحيّات أوسع من roles المخصَّصة لديك؛ هذا بالتصميم،
  ويُديره الـ provider.
- مشغِّلو bootstrap لمرّة واحدة (Terraform-runners في حسابٍ
  جديد) غالبًا ما يحتاجون صلاحيّات مرفوعة؛ احصرهم عبر وسم / SCP،
  وألغِها بعد اكتمال الـ bootstrap.
- مُحاكيات التطوير المحلّيّ (LocalStack، ومحاكي GCS) قد تَقبل أيّ
  اعتمادات؛ هذه خاصيّة المُحاكي، لا منح حقيقيّ.

## السياق (للبشر)

إدارة الهويّة والوصول هي أساس كل ضابط أمنٍ في السحابة. وأنماط الفشل
المتكرّرة هي: policies مُتساهلة جدًّا (`*:*`)، وaccess keys طويلة
العمر مُودَعة في git، وغياب MFA على حسابات مميَّزة، وtrust policies
لـ `AssumeRole` بلا `ExternalId`. وهذه هي الأسباب الجذريّة ذاتها
الموثَّقة في حوادث Capital One (2019)، وVerkada (2021)، وUber
(2022).

والضوابط الأعلى رافعةً هي:

1. **workload identity فوق access keys.** فالـ pod في EKS الذي
   يَتولّى role عبر IRSA لا يحتاج أبدًا إلى اعتماد قد يتسرّب.
2. **MFA على كل بشريّ، مُلزَمة بـ policy.** فلم تَعُد كلمة مرور
   مُسرَّبة كافيةً للعمل.
3. **منح بأقل امتياز تُراجَع في وقت PR.** فأرخص لحظة لتقييد صلاحيّة
   هي حين تُضاف — لا بعد ستّة أشهر حين يَسأل المُدقّق.
4. **تدوير المفاتيح إجباريّ.** فالاعتمادات الثابتة تَشيخ بصمتٍ
   حتى تصير عبئًا؛ أتمت التدوير حتى لا يُتجاوَز.
5. **trust عبر الحسابات بـ ExternalId.** فطبقة هجمات Confused
   Deputy تُخفَّف بالكامل باتفاقيّة ExternalId.

يفرض هذا الـ skill تلك الضوابط حين يُولِّد مساعدو الذكاء
الاصطناعيّ policies IAM، أو وثائق trust، أو هويّات CI/CD.

## مراجع

- `rules/iam_policy_invariants.json`
- `rules/key_rotation_policy.json`
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).
- [Google Cloud IAM recommender](https://cloud.google.com/iam/docs/recommender-overview).
- [NIST SP 800-53 Rev. 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf).
- [CIS Controls v8](https://www.cisecurity.org/controls/v8).
- [CNCF Kubernetes RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).
