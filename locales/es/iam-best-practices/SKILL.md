---
id: iam-best-practices
language: es
source_revision: "6de0becf"
version: "1.0.0"
title: "Mejores prácticas de Identity & Access Management"
description: "Diseño IAM con mínimo privilegio, rotación de claves, enforcement de MFA, asunción de roles y patrones de acceso entre cuentas para AWS / GCP / Azure / Kubernetes"
category: prevention
severity: critical
applies_to:
  - "al generar policies, roles o documentos de trust de IAM"
  - "al cablear service accounts de CI/CD o workload identities"
  - "al revisar creación, rotación o revocación de access keys"
  - "al diseñar acceso cross-account o cross-tenant"
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

# Mejores prácticas de Identity & Access Management

## Reglas (para agentes de IA)

### SIEMPRE
- Otorgar los permisos **mínimos** necesarios para el trabajo declarado del
  workload (NIST AC-6). Empezar con una policy deny-by-default y agregar
  acciones concretas con ARNs `Resource` explícitos; nunca `Action: "*"`
  combinado con `Resource: "*"`.
- Preferir **workload identity** (IAM roles para service accounts en EKS,
  Workload Identity en GKE, Managed Identity en Azure) sobre access keys
  de larga vida. Las access keys estáticas son la excepción, no el default.
- Requerir **MFA** para cada usuario IAM humano, especialmente cualquier
  principal que pueda asumir un role privilegiado. Forzar MFA vía una
  condición en la policy IAM (`aws:MultiFactorAuthPresent: true`), no
  sólo un setting a nivel directorio.
- Rotar access keys, service-account keys y signing keys con un calendario
  documentado (≤ 90 días). Detectar credenciales inactivas (≥ 90 días sin
  usar) y deshabilitarlas automáticamente.
- Usar **asunción de role con `sts:AssumeRole` + ExternalId** para trust
  entre cuentas. El ExternalId debe ser único por consumidor y estar
  guardado como secreto en ambas cuentas.
- Emitir credenciales **scoped por sesión** con `MaxSessionDuration ≤ 1h`
  para roles humanos y ≤ 12h para roles break-glass. Las sesiones de
  larga vida derrotan la rotación.
- Separar identidades de **deploy** y de **runtime**. El pipeline de CI/CD
  recibe un role de deploy; el servicio en ejecución recibe un role de
  runtime distinto sin permisos que muten IAM.
- Para Kubernetes RBAC, acotar `Role` / `RoleBinding` a un único
  namespace; usar `ClusterRole` sólo para objetos verdaderamente
  cluster-wide. Auditar los bindings de `cluster-admin` en cada PR.
- Loguear cada llamada que muta IAM (CloudTrail / Cloud Audit Logs /
  Azure Activity Log) a un sink a prueba de tampering. Alertar ante
  cambios de policy, `iam:PassRole`, `iam:CreateAccessKey` y
  `sts:AssumeRole` desde principals inesperados.
- Para acceso **break-glass** (root, owner, cluster-admin), requerir una
  aprobación out-of-band (por ej. incidente en PagerDuty + ticket) y
  emitir una alerta inmediata en cada uso.
- Etiquetar cada principal IAM con `owner`, `environment` y `purpose`.
  Usar estas tags en SCPs / org policies para acotar el blast radius.

### NUNCA
- Usar la cuenta **root** para operaciones del día a día. Las credenciales
  root reciben un dispositivo MFA de hardware, se guardan offline, y se
  usan sólo para el pequeño conjunto de tareas que sólo root puede hacer
  (por ej. cerrar la cuenta, cambiar el plan de soporte).
- Embeber access keys de larga vida en código fuente, imágenes de
  container, AMIs o variables de entorno de CI cuando hay una workload
  identity disponible.
- Otorgar `iam:PassRole` con `Resource: "*"`. Pinear siempre los ARNs de
  los roles que el caller puede pasar a servicios downstream.
- Otorgar `iam:*` o `sts:*` a un workload de runtime — esos son permisos
  sólo para deploy.
- Compartir un mismo IAM user entre múltiples humanos o servicios. Un
  principal por identidad es el invariante de auditoría.
- Usar la managed policy `AdministratorAccess` (o cualquier `*:*`) de
  forma rutinaria; tratarla como un attachment exclusivo de break-glass.
- Confiar en cualquier assume-role cross-account sin condición
  `ExternalId` para integraciones de terceros (Confused Deputy: AWS
  Security Bulletin 2021).
- Hardcodear ARNs / resource IDs de AWS / GCP / Azure en documentos de
  policy sin un alcance correspondiente basado en tags o ruta de
  organización (cuando el número de recursos puede crecer).
- Deshabilitar MFA en un principal para "arreglar" un problema de
  login — rotar el dispositivo, no remover el requisito.
- Persistir tokens de aserción OIDC / SAML más allá de su TTL declarado.
  Refrescar por re-aserción, no guardando el token original.

### FALSOS POSITIVOS CONOCIDOS
- `Resource: "*"` es aceptable para operaciones de lectura cuyo alcance
  es intrínsecamente la cuenta, como `ec2:DescribeRegions` o
  `sts:GetCallerIdentity` — esas APIs no aceptan un ARN de recurso.
- Los service-linked roles (por ej. `AWSServiceRoleForAutoScaling`)
  vienen con permisos más amplios que tus roles custom; eso es por
  diseño y lo gestiona el provider.
- Operadores de bootstrap de una sola vez (Terraform runners en una
  cuenta nueva) suelen necesitar permisos elevados; acotar por tag /
  SCP y revocar cuando el bootstrap termina.
- Emuladores locales de desarrollo (LocalStack, emulador de GCS)
  pueden aceptar cualquier credencial; es una propiedad del emulador,
  no un grant real.

## Contexto (para humanos)

Identity & access management es la base de cada control de seguridad
en la nube. Los modos de falla recurrentes son: policies demasiado
permisivas (`*:*`), access keys de larga vida commiteadas a git,
ausencia de MFA en cuentas privilegiadas y trust policies de
`AssumeRole` sin `ExternalId`. Son las mismas causas raíz
documentadas en las brechas de Capital One (2019), Verkada (2021) y
Uber (2022).

Los controles de alto leverage son:

1. **Workload identity por encima de access keys.** Un pod en EKS que
   asume un role vía IRSA nunca necesita una credencial que se pueda
   filtrar.
2. **MFA en cada humano, forzado por policy.** Una contraseña filtrada
   por sí sola ya no alcanza para actuar.
3. **Grants de mínimo privilegio revisados en tiempo de PR.** El
   momento más barato para acotar un permiso es cuando se está
   agregando — no cuando un auditor lo pregunta seis meses después.
4. **Rotación de claves obligatoria.** Las credenciales estáticas
   envejecen silenciosamente hasta volverse un pasivo; automatizar la
   rotación para que no se saltee.
5. **Trust cross-account con ExternalId.** La clase de ataque Confused
   Deputy queda totalmente mitigada por una convención de ExternalId.

Este skill hace cumplir esos controles cuando los asistentes IA
generan policies IAM, documentos de trust o identidades de CI/CD.

## Referencias

- `rules/iam_policy_invariants.json`
- `rules/key_rotation_policy.json`
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).
- [Google Cloud IAM recommender](https://cloud.google.com/iam/docs/recommender-overview).
- [NIST SP 800-53 Rev. 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf).
- [CIS Controls v8](https://www.cisecurity.org/controls/v8).
- [CNCF Kubernetes RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).
