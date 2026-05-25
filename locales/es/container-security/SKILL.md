---
id: container-security
language: es
source_revision: "afe376a8"
version: "1.0.0"
title: "Seguridad de contenedores"
description: "Reglas de endurecimiento para Dockerfile, imágenes OCI, manifests de Kubernetes y charts de Helm"
category: hardening
severity: high
applies_to:
  - "al generar un Dockerfile o una build de imagen OCI"
  - "al generar manifests de Kubernetes / Helm / Kustomize"
  - "al revisar cambios de contenedor en PR"
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

# Seguridad de contenedores

## Reglas (para agentes de IA)

### SIEMPRE
- Usar **builds multi-stage**: separar las etapas de builder/test de la
  imagen final de runtime para que las toolchains de build y el código
  fuente no se envíen. La última etapa debe ser `FROM distroless`,
  `FROM scratch`, `FROM alpine:<digest>` u otra base mínima — fijada por
  digest SHA256, no solo por tag.
- Ejecutar como usuario no root: `USER <uid>` (UID numérico >= 10000 para
  que las políticas K8s `runAsNonRoot` sean aplicables).
- Añadir un `.dockerignore` que excluya `.git`, `node_modules`, `.env`,
  `*.pem`, `*.key`, `target/`, `.terraform/`, `dist/`, `coverage/`.
- Definir `HEALTHCHECK` explícito para servicios long-running y los
  correspondientes `livenessProbe` / `readinessProbe` / `startupProbe`
  en K8s.
- Definir `requests` y `limits` de recursos en cada contenedor (CPU y
  memoria).
- Eliminar todas las capabilities Linux y volver a añadir solo lo
  necesario: `securityContext.capabilities.drop: [ALL]`.
- Aplicar un perfil seccomp (`RuntimeDefault` como mínimo) y AppArmor /
  SELinux donde estén disponibles.
- Marcar el filesystem como read-only: `readOnlyRootFilesystem: true`;
  usar volúmenes `emptyDir` para los pocos paths que deban ser
  escribibles.
- Escanear cada imagen en CI (Trivy, Grype, Snyk o el escáner del
  registry) y fallar la build en hallazgos CRITICAL o HIGH.
- Pull de imágenes base por digest SHA256 en manifests de producción, no
  por tag mutable.

### NUNCA
- Ejecutar contenedores como root o con `privileged: true` /
  `allowPrivilegeEscalation: true` fuera de pods de sistema explícitos y
  auditados (p. ej. plugins CNI).
- Montar el socket de docker del host (`/var/run/docker.sock`) dentro de
  un contenedor de aplicación. Es efectivamente root en el host.
- Incrustar secretos en capas de imagen vía `ENV`, `ARG`, `COPY`, o
  `echo`-ándolos a un archivo. Incluso con `--squash`, los layers de
  BuildKit cache y registry filtran.
- Usar `latest`, `stable`, `slim` o tags sin versión como base final —
  las builds se vuelven irreproducibles y silenciosamente recogen CVEs.
- Usar `ADD <url>` para descargar recursos remotos durante el build
  (usar `curl --fail` con verificación de checksum y `RUN` en su lugar,
  o vendorizar el artefacto).
- Desactivar `automountServiceAccountToken` cuando el workload necesita
  la API de K8s, pero SÍ desactivarlo (`automountServiceAccountToken:
  false`) cuando no.
- Usar `hostNetwork: true`, `hostPID: true` o `hostIPC: true` para pods
  de aplicación.
- Ejecutar pods en el namespace `kube-system`, o en cualquier namespace
  sin una `NetworkPolicy` y una política de admisión PodSecurity.

### FALSOS POSITIVOS CONOCIDOS
- Operadores que legítimamente necesitan acceso cluster-admin (kubelet,
  drivers CSI, plugins CNI) requieren privilegios elevados; pertenecen
  a `kube-system` o a un namespace dedicado con auditing, no a
  namespaces de aplicación.
- Nodos Kubernetes bare-metal a veces legítimamente desactivan `seccomp`
  para drivers no compatibles; documentar la excepción.
- Pods de debug one-shot (kubectl debug, ephemeral containers) eluden
  intencionadamente muchos de estos controles; no deberían persistirse
  como YAML en el repo.

## Contexto (para humanos)

Los contenedores filtran de dos formas: filtraciones de capa de imagen
(secretos en `ENV`, artefactos de build dejados en la imagen final,
CVEs de base vulnerable) y escapes en runtime (modo privilegiado,
docker.sock, namespaces del host). NIST SP 800-190 enmarca esto como
**riesgos de imagen**, **riesgos de registry**, **riesgos de orquestador**
y **riesgos de runtime**.

Los asistentes de IA casi siempre generan Dockerfiles que funcionan y se
envían — rápido — pero por defecto usan single-stage `FROM node` /
`FROM python` y `USER root`. Esta skill es el contrapeso; emparéjala con
`infrastructure-security` para controles K8s más allá del pod (RBAC,
admission, supply chain).

## Referencias

- `checklists/dockerfile_hardening.yaml`
- `checklists/k8s_pod_security.yaml`
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes).
- [NIST SP 800-190](https://csrc.nist.gov/publications/detail/sp/800-190/final).
