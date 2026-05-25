---
id: container-security
language: de
source_revision: "afe376a8"
version: "1.0.0"
title: "Container-Sicherheit"
description: "Härtungsregeln für Dockerfile, OCI-Images, Kubernetes-Manifests und Helm-Charts"
category: hardening
severity: high
applies_to:
  - "beim Erzeugen eines Dockerfile oder OCI-Image-Builds"
  - "beim Erzeugen von Kubernetes-/Helm-/Kustomize-Manifests"
  - "beim Reviewen von Container-Änderungen im PR"
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

# Container-Sicherheit

## Regeln (für KI-Agenten)

### IMMER
- **Multi-Stage-Builds** verwenden: Builder-/Test-Stages vom finalen
  Runtime-Image trennen, damit Build-Toolchains und Quellcode nicht
  ausgeliefert werden. Die letzte Stage sollte `FROM distroless`,
  `FROM scratch`, `FROM alpine:<digest>` oder eine andere minimale Base
  sein — per SHA256-Digest gepinnt, nicht nur per Tag.
- Als Non-Root-User laufen: `USER <uid>` (numerische UID >= 10000, damit
  K8s-`runAsNonRoot`-Policies durchsetzbar sind).
- Eine `.dockerignore` hinzufügen, die `.git`, `node_modules`, `.env`,
  `*.pem`, `*.key`, `target/`, `.terraform/`, `dist/`, `coverage/`
  ausschließt.
- Explizite `HEALTHCHECK` für langlaufende Services setzen und passende
  `livenessProbe` / `readinessProbe` / `startupProbe` in K8s.
- Resource-`requests` und `limits` an jedem Container (CPU und Memory)
  setzen.
- Alle Linux-Capabilities droppen und nur das Nötige wieder hinzufügen:
  `securityContext.capabilities.drop: [ALL]`.
- Ein Seccomp-Profil anwenden (mindestens `RuntimeDefault`) und
  AppArmor / SELinux, wo verfügbar.
- Filesystem read-only markieren: `readOnlyRootFilesystem: true`;
  `emptyDir`-Volumes für die wenigen Pfade verwenden, die schreibbar sein
  müssen.
- Jedes Image in CI scannen (Trivy, Grype, Snyk oder der Registry-
  Scanner) und Builds bei CRITICAL- oder HIGH-Findings scheitern lassen.
- Base-Images in Production-Manifests per SHA256-Digest ziehen, nicht
  per mutable Tag.

### NIE
- Container als root oder mit `privileged: true` /
  `allowPrivilegeEscalation: true` außerhalb expliziter, auditierter
  System-Pods (z. B. CNI-Plugins) laufen lassen.
- Den Host-Docker-Socket (`/var/run/docker.sock`) in einen
  Application-Container mounten. Das ist effektiv Root auf dem Host.
- Secrets in Image-Layern via `ENV`, `ARG`, `COPY` oder per `echo` in
  eine Datei einbetten. Selbst bei `--squash` leaken BuildKit-Cache und
  Registry-Layer.
- `latest`, `stable`, `slim` oder unversionierte Tags als finale
  Image-Base verwenden — Builds werden non-reproducible und ziehen still
  CVEs hinein.
- `ADD <url>` benutzen, um Remote-Resourcen während des Builds zu holen
  (stattdessen `curl --fail` mit Checksum-Verify und `RUN`, oder das
  Artefakt vendoren).
- `automountServiceAccountToken` deaktivieren, wenn der Workload die
  K8s-API braucht, aber AKTIVIERT lassen ist falsch — deaktivieren
  (`automountServiceAccountToken: false`), wenn er sie nicht braucht.
- `hostNetwork: true`, `hostPID: true` oder `hostIPC: true` für
  Application-Pods verwenden.
- Pods im `kube-system`-Namespace laufen lassen oder in einem Namespace
  ohne `NetworkPolicy` und PodSecurity-Admission-Policy.

### BEKANNTE FALSCH-POSITIVE
- Operatoren, die legitim Cluster-Admin-Zugriff brauchen (Kubelet,
  CSI-Drivers, CNI-Plugins), benötigen erhöhte Privilegien; sie gehören
  in `kube-system` oder in einen eigenen, auditierten Namespace, nicht
  in Application-Namespaces.
- Bare-Metal-Kubernetes-Nodes deaktivieren manchmal legitim `seccomp`
  für inkompatible Drivers; die Ausnahme dokumentieren.
- One-Shot-Debug-Pods (kubectl debug, Ephemeral Containers) umgehen
  viele dieser Kontrollen absichtlich; sie sollten nicht als YAML im
  Repo persistiert werden.

## Kontext (für Menschen)

Container leaken auf zwei Wegen: Image-Layer-Leaks (Secrets in `ENV`,
in der finalen Image hinterlassene Build-Artefakte, anfällige Base-CVEs)
und Runtime-Escapes (Privileged Mode, docker.sock, Host-Namespaces).
NIST SP 800-190 rahmt das als **Image-Risiken**, **Registry-Risiken**,
**Orchestrator-Risiken** und **Runtime-Risiken**.

KI-Assistenten generieren fast immer Dockerfiles, die laufen und
shippen — schnell — aber per Default Single-Stage `FROM node` /
`FROM python` und `USER root`. Dieser Skill ist das Gegengewicht; paare
ihn mit `infrastructure-security` für K8s-Kontrollen jenseits des Pods
(RBAC, Admission, Supply Chain).

## Referenzen

- `checklists/dockerfile_hardening.yaml`
- `checklists/k8s_pod_security.yaml`
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes).
- [NIST SP 800-190](https://csrc.nist.gov/publications/detail/sp/800-190/final).
