---
id: infrastructure-security
language: es
source_revision: "fbb3a823"
version: "1.0.0"
title: "Seguridad de infraestructura"
description: "Aplicar reglas de hardening para Kubernetes, Docker e infrastructure-as-code en Terraform"
category: hardening
severity: high
applies_to:
  - "al generar contenido de Dockerfile"
  - "al generar manifiestos de Kubernetes o charts de Helm"
  - "al generar Terraform o CloudFormation"
  - "al revisar PRs de IaC"
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

# Seguridad de infraestructura

## Reglas (para agentes de IA)

### SIEMPRE
- Pinear imágenes base por digest (`FROM image@sha256:...`) al construir
  contenedores para producción. Los tags son mutables; los digests no.
- Correr contenedores como un `USER` no-root distinto de `0`. Agregar
  `securityContext: runAsNonRoot: true` a los pod specs de K8s.
- Setear `requests` Y `limits` explícitos de recursos de Kubernetes
  (`requests.cpu`, `requests.memory`, `limits.cpu`, `limits.memory`).
- Soltar todas las capabilities de Linux y volver a agregar sólo las
  requeridas (`securityContext.capabilities.drop: ["ALL"]`).
- Marcar los filesystems como read-only
  (`securityContext.readOnlyRootFilesystem: true`) cuando el workload no
  necesita legítimamente acceso de escritura.
- Habilitar cifrado en reposo (`enable_kms_encryption`, `kms_key_id`,
  `server_side_encryption_configuration`) en buckets S3, volúmenes EBS,
  RDS, DynamoDB.
- Setear `block_public_access` en cada bucket S3 a menos que el workload
  genuinamente sirva contenido público.
- Aplicar el principio de mínimo privilegio a las policies de IAM:
  nombrar acciones y recursos explícitos; evitar `*:*` y `Resource: "*"`
  fuera de policies de admin intencionales.

### NUNCA
- Usar `latest` como tag de imagen en manifiestos de producción.
- Correr un contenedor con flag `--privileged` o
  `securityContext.privileged: true`.
- Montar el `/var/run/docker.sock` del host dentro de un contenedor.
- Exponer servicios de Kubernetes con `type: LoadBalancer` directamente
  a internet sin un ingress controller, WAF o capa de autenticación
  delante.
- Hardcodear claves de AWS / claves de service-account de GCP / client
  secrets de Azure en IaC. Usar IRSA, Workload Identity de GKE, managed
  identities de Azure, o el equivalente nativo de la plataforma.
- Crear buckets S3 con `acl = "public-read"` para buckets que contengan
  algo distinto a assets intencionalmente públicos.
- Permitir ingress de `0.0.0.0/0` en puertos de base de datos, SSH, RDP
  o admin.
- Deshabilitar `node_to_node_encryption` en Elasticsearch / OpenSearch.

### FALSOS POSITIVOS CONOCIDOS
- Pinear digests de imagen no siempre es práctico en entornos de dev /
  preview — pinear por tag (por ej. `node:20.11.1-alpine`) es aceptable
  ahí.
- `Resource: "*"` es aceptable en policies que estén documentadas como
  admin-only con constraints `Condition` explícitos.
- `runAsNonRoot: false` es aceptable cuando el workload genuinamente
  requiere root (por ej. bindear al puerto 80, ciertas herramientas de
  red). Documentar el por qué.

## Contexto (para humanos)

La infraestructura mal configurada es la causa dominante de brechas en
la nube. Los patrones de arriba codifican los items más violados de los
benchmarks CIS como reglas que la IA aplica durante la generación, no
después del deploy.

## Referencias

- `checklists/k8s_hardening.yaml`
- `checklists/docker_security.yaml`
- `checklists/terraform_security.yaml`
- [NSA/CISA Kubernetes Hardening Guidance](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF).
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).
