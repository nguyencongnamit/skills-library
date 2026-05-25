---
id: iac-security
language: ar
dir: rtl
source_revision: "afe376a8"
version: "1.0.0"
title: "أمن البنية التحتية كَكُود"
description: "قواعد تصليب لـ Terraform وCloudFormation وPulumi: state، وproviders، وdrift، والأسرار"
category: hardening
severity: high
applies_to:
  - "عند توليد Terraform / Pulumi / CloudFormation"
  - "عند مراجعة تغييرات IaC في PR"
  - "عند توصيل حساب أو workspace سحابيّ جديد"
languages: ["hcl", "yaml", "json", "typescript", "python", "go"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2500
rules_path: "checklists/"
related_skills: ["infrastructure-security", "container-security", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "CIS Benchmarks (AWS, Azure, GCP)"
  - "HashiCorp Terraform Best Practices"
  - "NIST SP 800-53 Rev. 5 (CM-6, CM-8, SC-28)"
  - "OWASP IaC Security Top 10"
---

# أمن البنية التحتية كَكُود

## القواعد (لوكلاء الذكاء الاصطناعي)

### دائمًا
- ثبِّت كل provider/module على نسخة محدّدة بدقّة أو قيد متشائم
  (`~> 5.42`)؛ ولا تستخدم أبدًا `>= 0` أو `latest` غير المثبَّت.
- اضبط **backend بعيد** بتشفير عند الرّاحة، وقفل state من جهة
  الخادم، وإصدارات (Terraform: `s3` + جدول قفل DynamoDB بـ
  `kms_key_id`؛ Pulumi: الـ backend المُدار أو `s3://?kmskey=`؛
  CloudFormation: تديره AWS).
- شفِّر كل مورد دائم افتراضيًّا بمفتاح KMS مُدار من قِبَل العميل:
  buckets S3، وحَجوم EBS، وRDS، وEFS، وDynamoDB، وSQS، وSNS،
  ومجموعات سجلّات CloudWatch.
- وسِّم كل مورد بـ `owner`، و`environment`، و`cost-center`،
  و`data-classification` عبر كتلة default tags.
- شغِّل `terraform plan` (أو `pulumi preview`،
  `aws cloudformation deploy --no-execute-changeset`) في CI، واشترط
  موافقة بشريّة قبل `apply` على stacks الإنتاج.
- أضِف مهمّة كشف drift تعمل يوميًّا وتفتح issue حين تختلف الحالة
  السحابيّة الفعليّة عن الكود (كشف drift في Terraform Cloud،
  و`pulumi refresh`، و`cfn-drift-detect`).
- استخدم Conditions في IAM لحصر كل role: `aws:SourceArn`،
  و`aws:SourceAccount`، و`aws:PrincipalOrgID`، وسياسات وصول
  TLS-only على التخزين.

### أبدًا
- لا تُصلِّب اعتمادات provider في الكود أو في `.tfvars`
  (`access_key`، و`secret_key`، و`client_secret`،
  و`service_account_key`). استخدم اتّحاد OIDC من CI، أو خدمة
  metadata الـ instance لدى provider، أو مدير أسرار.
- لا تُودِع `terraform.tfstate`، أو `terraform.tfstate.backup`، أو
  `.pulumi/`، أو أيّ `*.tfvars` يحوي أسرارًا حقيقيّة. فهي تحتوي على
  أسرار نصّيّة حتى وإن كان الكود يُشير إلى متغيّرات.
- لا تستخدم `local_exec` / `null_resource` لجلب أسرار وقت الـ apply
  وتخبئتها داخل الـ state. الـ state نصّ صريح قابل للاستعلام لمن
  يملك حقّ قراءة على الـ backend.
- لا تفتح security groups / قواعد جدار ناريّ نحو `0.0.0.0/0` على
  المنافذ 22، و3389، و3306، و5432، و1433، و6379، و27017، و9200،
  و11211 — ولا حتى "للتطوير فقط". استخدم bastion أو VPN.
- لا تَمنح سياسات IAM بصيغة `*:*` (إجراء wildcard على مورد
  wildcard). استخدم `iam:PassRole` مع ARNs مورد صريحة.
- لا تُعطِّل التحقّق من TLS لدى provider (`skip_tls_verify`،
  `insecure = true`).
- لا تستخدم `count = 0` لـ "حذفٍ ناعم" لموارد تريدها فعلًا أن
  تذهب — دمِّرها.

### إيجابيات خاطئة معروفة
- مضيفو bastion المكشوفون عمدًا على المنفذ 22 إلى الإنترنت مع
  تكوينات مُصلَّبة ليسوا في خطورة فتح RDS للعالم. وثِّق الاستثناء
  inline.
- توزيعات CloudFront العامّة، ومستمعو ALB على 80/443، وAPI
  Gateways، وعناوين دوال Lambda، المُعَدّة *عمدًا* لتكون مواجهة
  للإنترنت.
- موارد التهيئة (bucket S3 وجدول قفل DynamoDB اللذان يستخدمهما
  الـ backend ذاته) يجب أن تكون موجودة قبل أن يكون هناك state
  بعيد؛ ويُهيَّأ هذا الدور البَيْضَوي-الدجاجي عادةً بـ backend
  `local` لمرّة واحدة يُهاجَر بعدها.

## السياق (للبشر)

تتسع أخطاء IaC: قد يُطبَّق module واحد سيّئ بـ `terraform apply`
على مئات الحسابات. فئات المشاكل التي نغطّيها هنا — تسرّبات
الأسرار عبر الـ state، والتعرّض الشبكي غير المُقَيَّد، وIAM
بصيغة wildcard، والـ drift — هي بالضبط ما تُؤشِّر إليه CIS
ومراجعات well-architected لدى مزوّدي السحابة أنفسهم أكثر من
غيره. ومُساعدو الذكاء الاصطناعي مَيّالون بشكل خاصّ إلى توليد
Terraform "يَعمل على جهازي" بلا تثبيت أي شيء واستخدام state
محلّي؛ هذا الـ skill هو الثقل المعاكس.

## مراجع

- `checklists/terraform_hardening.yaml`
- `checklists/cloudformation_hardening.yaml`
- [CIS Benchmark for Amazon Web Services Foundations](https://www.cisecurity.org/benchmark/amazon_web_services).
- [Terraform Recommended Practices](https://developer.hashicorp.com/terraform/cloud-docs/recommended-practices).
- [NIST SP 800-53 Rev. 5 control catalog](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final).
