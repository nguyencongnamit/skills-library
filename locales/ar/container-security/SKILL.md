---
id: container-security
language: ar
dir: rtl
source_revision: "afe376a8"
version: "1.0.0"
title: "أمن الحاويات"
description: "قواعد تصليب لـ Dockerfile وصور OCI ومانيفستات Kubernetes ومخططات Helm"
category: hardening
severity: high
applies_to:
  - "عند توليد Dockerfile أو بناء صورة OCI"
  - "عند توليد مانيفستات Kubernetes / Helm / Kustomize"
  - "عند مراجعة تغييرات حاويات داخل PR"
languages: ["dockerfile", "yaml", "go", "python"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2500
rules_path: "checklists/"
related_skills: ["infrastructure-security", "iac-security", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "CIS Docker Benchmark v1.6"
  - "CIS Kubernetes Benchmark v1.9"
  - "NIST SP 800-190 Application Container Security Guide"
  - "OWASP Docker Top 10"
---

# أمن الحاويات

## القواعد (لوكلاء الذكاء الاصطناعي)

### دائمًا
- استخدم **builds متعدّدة المراحل**: افصل مراحل builder/test عن صورة
  وقت التشغيل النهائية كي لا تُشحن سلاسل أدوات البناء والشيفرة المصدرية.
  يجب أن تكون المرحلة الأخيرة `FROM distroless`، `FROM scratch`،
  `FROM alpine:<digest>` أو قاعدة دنيا أخرى — مُثبَّتة بـ SHA256 digest،
  لا بمجرد tag.
- شغّل بمستخدم غير root: `USER <uid>` (UID رقمي ≥ 10000 لكي تكون
  سياسات K8s `runAsNonRoot` قابلة للفرض).
- أضف `.dockerignore` يستثني `.git` و`node_modules` و`.env` و`*.pem`
  و`*.key` و`target/` و`.terraform/` و`dist/` و`coverage/`.
- اضبط `HEALTHCHECK` صريحًا للخدمات طويلة الأمد، مع
  `livenessProbe` / `readinessProbe` / `startupProbe` مكافئة في K8s.
- اضبط `requests` و`limits` للموارد على كل حاوية (CPU و الذاكرة).
- أسقط جميع capabilities الـ Linux ثم أَعد فقط ما يلزم:
  `securityContext.capabilities.drop: [ALL]`.
- طبّق ملف seccomp (`RuntimeDefault` كحد أدنى) و AppArmor / SELinux
  حين تتوفر.
- اجعل نظام الملفات للقراءة فقط: `readOnlyRootFilesystem: true`;
  استخدم وحدات `emptyDir` للمسارات القليلة التي تحتاج كتابة.
- افحص كل صورة في CI (Trivy، Grype، Snyk، أو فاحص سجلك) وأخفِق
  البناء عند نتائج CRITICAL أو HIGH.
- اجلب صور القاعدة في مانيفستات الإنتاج بـ SHA256 digest، لا بـ tag
  متغيّر.

### أبدًا
- لا تشغّل حاويات بصلاحية root أو بـ `privileged: true` /
  `allowPrivilegeEscalation: true` خارج pods نظام محدّدة ومُدقَّقة (مثل
  ملحقات CNI).
- لا تُركّب socket الـ docker الخاص بالمضيف
  (`/var/run/docker.sock`) داخل حاوية تطبيق. فهذا فعليًا صلاحية root على
  المضيف.
- لا تُضمّن أسرارًا في طبقات الصورة عبر `ENV` أو `ARG` أو `COPY` أو
  بـ `echo` إلى ملف. حتى مع `--squash` تتسرّب طبقات BuildKit cache
  وregistry.
- لا تستخدم `latest` أو `stable` أو `slim` أو tags بلا إصدار كقاعدة
  نهائية — تصبح builds غير قابلة لإعادة الإنتاج وتلتقط CVEs بصمت.
- لا تستخدم `ADD <url>` لجلب موارد بعيدة أثناء البناء (استخدم
  `curl --fail` مع التحقق من checksum و`RUN` بدلًا من ذلك، أو وَنْدِر
  المادة).
- لا تُعطّل `automountServiceAccountToken` حين يحتاج الـ workload إلى
  واجهة K8s، لكن عطّله (`automountServiceAccountToken: false`) حين لا
  يحتاج.
- لا تستخدم `hostNetwork: true` أو `hostPID: true` أو `hostIPC: true`
  لـ pods التطبيقات.
- لا تُشغّل pods في namespace `kube-system`، ولا في أي namespace بلا
  `NetworkPolicy` وسياسة قبول PodSecurity.

### إيجابيات خاطئة معروفة
- المشغّلون (operators) الذين يحتاجون شرعًا صلاحية cluster-admin
  (kubelet، CSI drivers، CNI plugins) يحتاجون صلاحيات مرتفعة؛ مكانها
  `kube-system` أو namespace مخصّص مع تدقيق، لا في namespaces
  التطبيقات.
- نقاط Kubernetes على bare-metal تُعطّل شرعًا أحيانًا seccomp لدرايفرات
  غير متوافقة؛ وثّق الاستثناء.
- pods التصحيح اللمسية (kubectl debug، ephemeral containers) تتجاوز
  عمدًا كثيرًا من هذه الضوابط؛ لا ينبغي إبقاؤها كـ YAML في المستودع.

## السياق (للبشر)

تتسرّب الحاويات بطريقتين: تسريبات طبقات الصورة (أسرار في `ENV`،
مواد بناء تُركَت في الصورة النهائية، CVEs في القاعدة) وهروبات وقت
التشغيل (وضع privileged، docker.sock، namespaces المضيف). يصنّفها
NIST SP 800-190 كـ **مخاطر الصورة**، **مخاطر السجل**، **مخاطر المنسّق**،
**مخاطر وقت التشغيل**.

تكاد مساعدات الذكاء الاصطناعي تولّد دائمًا Dockerfiles تعمل وتُشحن —
بسرعة — لكنها افتراضًا أحادية المرحلة بـ `FROM node` / `FROM python`
و`USER root`. هذه الـ skill هي الموازن؛ ادمجها مع
`infrastructure-security` لضوابط K8s خارج الـ pod (RBAC، admission،
سلسلة التوريد).

## مراجع

- `checklists/dockerfile_hardening.yaml`
- `checklists/k8s_pod_security.yaml`
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes).
- [NIST SP 800-190](https://csrc.nist.gov/publications/detail/sp/800-190/final).
