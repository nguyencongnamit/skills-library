---
id: container-security
language: pt-BR
source_revision: "afe376a8"
version: "1.0.0"
title: "Segurança de contêineres"
description: "Regras de endurecimento para Dockerfile, imagens OCI, manifests Kubernetes e charts Helm"
category: hardening
severity: high
applies_to:
  - "ao gerar um Dockerfile ou build de imagem OCI"
  - "ao gerar manifests Kubernetes / Helm / Kustomize"
  - "ao revisar mudanças de contêiner em PR"
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

# Segurança de contêineres

## Regras (para agentes de IA)

### SEMPRE
- Use **builds multi-stage**: separe estágios de builder/test da imagem
  final de runtime para que toolchains de build e código-fonte não
  sejam embarcados. O último estágio deve ser `FROM distroless`,
  `FROM scratch`, `FROM alpine:<digest>` ou outra base mínima — fixada
  por digest SHA256, não apenas por tag.
- Rode como usuário não-root: `USER <uid>` (UID numérico >= 10000 para
  que policies K8s `runAsNonRoot` possam ser enforçadas).
- Inclua um `.dockerignore` excluindo `.git`, `node_modules`, `.env`,
  `*.pem`, `*.key`, `target/`, `.terraform/`, `dist/`, `coverage/`.
- Defina `HEALTHCHECK` explícito para serviços long-running e
  `livenessProbe` / `readinessProbe` / `startupProbe` correspondentes
  no K8s.
- Defina `requests` e `limits` de recursos em todo contêiner (CPU e
  memória).
- Dropar todas as capabilities do Linux e adicionar de volta apenas o
  necessário: `securityContext.capabilities.drop: [ALL]`.
- Aplique um profile seccomp (`RuntimeDefault` no mínimo) e AppArmor /
  SELinux onde disponível.
- Marque o filesystem como read-only: `readOnlyRootFilesystem: true`;
  use volumes `emptyDir` para os poucos paths que precisam ser
  graváveis.
- Escaneie cada imagem no CI (Trivy, Grype, Snyk ou o scanner do seu
  registry) e falhe builds em achados CRITICAL ou HIGH.
- Puxe imagens base por digest SHA256 em manifests de produção, não
  por tag mutável.

### NUNCA
- Rode contêineres como root ou com `privileged: true` /
  `allowPrivilegeEscalation: true` fora de pods de sistema explícitos
  e auditados (ex.: plugins CNI).
- Monte o socket Docker do host (`/var/run/docker.sock`) dentro de um
  contêiner de aplicação. É efetivamente root no host.
- Embarque segredos em camadas de imagem via `ENV`, `ARG`, `COPY` ou
  ecoando para um arquivo. Mesmo com `--squash`, cache do BuildKit e
  camadas do registry vazam.
- Use `latest`, `stable`, `slim` ou tags sem versão como base final —
  builds ficam não-reprodutíveis e silenciosamente engolem CVEs.
- Use `ADD <url>` para buscar recursos remotos durante o build (use
  `curl --fail` com verificação de checksum e `RUN`, ou vendore o
  artefato).
- Desabilite `automountServiceAccountToken` quando o workload precisa
  da API K8s — mas DESABILITE-o (`automountServiceAccountToken: false`)
  quando ele não precisa.
- Use `hostNetwork: true`, `hostPID: true` ou `hostIPC: true` para
  pods de aplicação.
- Rode pods no namespace `kube-system`, ou em qualquer namespace sem
  `NetworkPolicy` e policy de admissão PodSecurity.

### FALSOS POSITIVOS CONHECIDOS
- Operators que legitimamente precisam de acesso cluster-admin
  (kubelet, drivers CSI, plugins CNI) exigem privilégios elevados;
  pertencem ao `kube-system` ou a um namespace dedicado com auditoria,
  não a namespaces de aplicação.
- Nós Kubernetes bare-metal às vezes legitimamente desabilitam
  `seccomp` para drivers não compatíveis; documente a exceção.
- Pods de debug one-shot (kubectl debug, ephemeral containers)
  intencionalmente burlam muitos desses controles; não devem ser
  persistidos como YAML no repo.

## Contexto (para humanos)

Contêineres vazam por duas vias: vazamentos de camada de imagem
(segredos em `ENV`, artefatos de build deixados na imagem final, CVEs
na base) e escapes em runtime (privileged mode, docker.sock, namespaces
do host). NIST SP 800-190 enquadra isso como **riscos de imagem**,
**riscos de registry**, **riscos de orquestrador** e **riscos de
runtime**.

Assistentes de IA quase sempre geram Dockerfiles que funcionam e vão
para produção — rápido — mas por padrão usam single-stage
`FROM node` / `FROM python` e `USER root`. Esta skill é o contrapeso;
combine com `infrastructure-security` para controles K8s além do pod
(RBAC, admission, supply chain).

## Referências

- `checklists/dockerfile_hardening.yaml`
- `checklists/k8s_pod_security.yaml`
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes).
- [NIST SP 800-190](https://csrc.nist.gov/publications/detail/sp/800-190/final).
