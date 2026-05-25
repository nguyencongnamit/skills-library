---
id: container-security
version: "1.0.0"
title: "Container Security"
description: "Hardening rules for Dockerfile, OCI images, Kubernetes manifests, and Helm charts"
category: hardening
severity: high
applies_to:
  - "when generating a Dockerfile or OCI image build"
  - "when generating Kubernetes / Helm / Kustomize manifests"
  - "when reviewing container changes in PR"
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

# Container Security

## Rules (for AI agents)

### ALWAYS
- Use **multi-stage builds**: separate builder/test stages from the final runtime
  image so build toolchains and source aren't shipped. The last stage should be
  `FROM distroless`, `FROM scratch`, `FROM alpine:<digest>`, or another minimal
  base — pinned by SHA256 digest, not just tag.
- Run as a non-root user: `USER <uid>` (numeric UID >= 10000 for K8s `runAsNonRoot`
  policies to be enforceable).
- Add a `.dockerignore` excluding `.git`, `node_modules`, `.env`, `*.pem`, `*.key`,
  `target/`, `.terraform/`, `dist/`, `coverage/`.
- Set explicit `HEALTHCHECK` for long-running services and matching
  `livenessProbe` / `readinessProbe` / `startupProbe` in K8s.
- Set resource `requests` and `limits` on every container (CPU and memory).
- Drop all Linux capabilities then add back only what's needed:
  `securityContext.capabilities.drop: [ALL]`.
- Apply a seccomp profile (`RuntimeDefault` at minimum) and AppArmor / SELinux
  where available.
- Mark filesystem read-only: `readOnlyRootFilesystem: true`; use `emptyDir`
  volumes for the few paths that must be writable.
- Scan every image in CI (Trivy, Grype, Snyk, or your registry's scanner) and
  fail builds on CRITICAL or HIGH severity findings.
- Pull base images by SHA256 digest in production manifests, not by mutable tag.

### NEVER
- Run containers as root or with `privileged: true` / `allowPrivilegeEscalation:
  true` outside of explicit, audited system pods (e.g., CNI plugins).
- Mount the host docker socket (`/var/run/docker.sock`) inside an application
  container. It's effectively root on the host.
- Embed secrets in image layers via `ENV`, `ARG`, `COPY`, or by `echo`-ing them
  to a file. Even if `--squash`'d, BuildKit cache and registry layers leak.
- Use `latest`, `stable`, `slim`, or unversioned tags as the final image base —
  builds become non-reproducible and quietly pick up CVEs.
- Use `ADD <url>` to fetch remote resources during build (use `curl --fail` with
  a checksum verify and `RUN` instead, or vendor the artifact).
- Disable `automountServiceAccountToken` when the workload needs the K8s API,
  but DO disable it (`automountServiceAccountToken: false`) when it doesn't.
- Use `hostNetwork: true`, `hostPID: true`, or `hostIPC: true` for application
  pods.
- Run pods in the `kube-system` namespace, or any namespace without a
  `NetworkPolicy` and PodSecurity admission policy.

### KNOWN FALSE POSITIVES
- Operators that legitimately need cluster-admin access (kubelet, CSI drivers,
  CNI plugins) require elevated privileges; they belong in `kube-system` or a
  dedicated namespace with auditing, not in application namespaces.
- Bare-metal Kubernetes nodes sometimes legitimately disable `seccomp` for
  drivers that aren't compatible; document the exception.
- One-shot debugging pods (kubectl debug, ephemeral containers) intentionally
  bypass many of these controls; they should not be persisted as YAML in the
  repo.

## Context (for humans)

Containers leak two ways: image-layer leaks (secrets in `ENV`, build artifacts
left in the final image, vulnerable base CVEs) and runtime escapes (privileged
mode, docker.sock, host namespaces). NIST SP 800-190 frames these as **image
risks**, **registry risks**, **orchestrator risks**, and **runtime risks**.

AI assistants almost always generate Dockerfiles that work and ship — fast — but
they default to a single-stage `FROM node` / `FROM python` and `USER root`. This
skill is the counterweight; pair it with `infrastructure-security` for K8s
controls beyond the pod (RBAC, admission, supply chain).

## References

- `checklists/dockerfile_hardening.yaml`
- `checklists/k8s_pod_security.yaml`
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes).
- [NIST SP 800-190](https://csrc.nist.gov/publications/detail/sp/800-190/final).
