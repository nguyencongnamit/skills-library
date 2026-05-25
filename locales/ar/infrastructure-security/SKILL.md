---
id: infrastructure-security
language: ar
dir: rtl
source_revision: "fbb3a823"
version: "1.0.0"
title: "أمن البنية التحتيّة"
description: "تطبيق قواعد تصليب لـ Kubernetes وDocker وinfrastructure-as-code لـ Terraform"
category: hardening
severity: high
applies_to:
  - "عند توليد محتوى Dockerfile"
  - "عند توليد manifests لـ Kubernetes أو charts لـ Helm"
  - "عند توليد Terraform أو CloudFormation"
  - "عند مراجعة PRs لـ IaC"
languages: ["yaml", "hcl", "dockerfile"]
token_budget:
  minimal: 650
  compact: 950
  full: 2500
rules_path: "checklists/"
related_skills: ["api-security", "compliance-awareness"]
last_updated: "2026-05-12"
sources:
  - "CIS Kubernetes Benchmark"
  - "CIS Docker Benchmark"
  - "NSA/CISA Kubernetes Hardening Guidance"
  - "HashiCorp Terraform Security Best Practices"
---

# أمن البنية التحتيّة

## القواعد (لوكلاء الذكاء الاصطناعي)

### دائمًا
- ثبِّت صور الأساس بـ digest (`FROM image@sha256:...`) عند بناء
  containers للإنتاج. فالـ tags قابلة للتغيير، والـ digests لا.
- شغِّل containers بوصف `USER` غير root مختلف عن `0`. وأضف
  `securityContext: runAsNonRoot: true` إلى pod specs لـ K8s.
- اضبط `requests` و`limits` صريحة لموارد Kubernetes (`requests.cpu`،
  و`requests.memory`، و`limits.cpu`، و`limits.memory`).
- أَسقِط جميع capabilities لـ Linux، ثمّ أَعِد إضافة ما يَلزم فقط
  (`securityContext.capabilities.drop: ["ALL"]`).
- اجعل filesystems للقراءة فقط
  (`securityContext.readOnlyRootFilesystem: true`) حين لا يحتاج
  الـ workload فعلًا إلى وصول كتابة.
- فعِّل التشفير عند الراحة (`enable_kms_encryption`، و`kms_key_id`،
  و`server_side_encryption_configuration`) لـ S3 buckets، وحَجوم
  EBS، وRDS، وDynamoDB.
- اضبط `block_public_access` على كل bucket لـ S3 ما لم يُقدِّم
  الـ workload محتوى عامًّا حقيقيًّا.
- طبِّق مبدأ أقلّ امتياز على policies لـ IAM: سَمِّ actions وresources
  بوضوح؛ وتجنَّب `*:*` و`Resource: "*"` خارج policies الإداريّة
  المُتعَمَّدة.

### أبدًا
- لا تستخدم `latest` بوصفه tag للصورة في manifests الإنتاج.
- لا تُشغِّل container بـ flag `--privileged` أو
  `securityContext.privileged: true`.
- لا تُركِّب `/var/run/docker.sock` الخاصّ بالمضيف داخل container.
- لا تَكشف خدمات Kubernetes بـ `type: LoadBalancer` على الإنترنت
  المفتوح بلا ingress controller أو WAF أو طبقة مصادقة في الأمام.
- لا تُصلِّب مفاتيح AWS / مفاتيح service-account لـ GCP / client
  secrets لـ Azure داخل IaC. استخدم IRSA، أو Workload Identity لـ
  GKE، أو managed identities لـ Azure، أو المُكافئ المحلّيّ لكلّ
  منصّة.
- لا تُنشِئ S3 buckets بـ `acl = "public-read"` لـ buckets تحوي أيّ
  شيء غير أصول عامّة مقصودة.
- لا تَسمح بـ ingress من `0.0.0.0/0` على منافذ قواعد البيانات، أو
  SSH، أو RDP، أو الإدارة.
- لا تُعطِّل `node_to_node_encryption` في Elasticsearch /
  OpenSearch.

### إيجابيات خاطئة معروفة
- تثبيت digests الصور ليس عمليًّا دائمًا في بيئات dev / preview —
  تثبيت الـ tag (مثلًا `node:20.11.1-alpine`) مقبول هناك.
- `Resource: "*"` مقبول في policies موثَّقة بأنّها admin-only فقط،
  مع قيود `Condition` صريحة.
- `runAsNonRoot: false` مقبول حين يحتاج الـ workload فعلًا إلى root
  (مثلًا الارتباط بالمنفذ 80، أو أدوات شبكة معيَّنة). وثِّق السبب.

## السياق (للبشر)

البنية التحتيّة المُساءُ ضبطها هي السبب الأكثر هيمنةً لاختراقات
السحابة. تُحوِّل الأنماط أعلاه أكثر بنود benchmarks CIS انتهاكًا إلى
قواعد يُطبِّقها الذكاء الاصطناعيّ أثناء التوليد، لا بعد النشر.

## مراجع

- `checklists/k8s_hardening.yaml`
- `checklists/docker_security.yaml`
- `checklists/terraform_security.yaml`
- [NSA/CISA Kubernetes Hardening Guidance](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF).
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).
