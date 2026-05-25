---
id: container-security
language: fr
source_revision: "afe376a8"
version: "1.0.0"
title: "Sécurité des conteneurs"
description: "Règles de durcissement pour Dockerfile, images OCI, manifests Kubernetes et charts Helm"
category: hardening
severity: high
applies_to:
  - "lors de la génération d'un Dockerfile ou d'un build d'image OCI"
  - "lors de la génération de manifests Kubernetes / Helm / Kustomize"
  - "lors de la revue de changements de conteneur en PR"
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

# Sécurité des conteneurs

## Règles (pour les agents IA)

### TOUJOURS
- Utiliser des **builds multi-stage** : séparer les étapes builder/test
  de l'image runtime finale pour que les toolchains de build et le code
  source ne soient pas embarqués. La dernière étape doit être
  `FROM distroless`, `FROM scratch`, `FROM alpine:<digest>` ou une autre
  base minimale — épinglée par digest SHA256, pas seulement par tag.
- Exécuter en utilisateur non-root : `USER <uid>` (UID numérique >= 10000
  pour que les policies K8s `runAsNonRoot` puissent être appliquées).
- Ajouter un `.dockerignore` excluant `.git`, `node_modules`, `.env`,
  `*.pem`, `*.key`, `target/`, `.terraform/`, `dist/`, `coverage/`.
- Définir un `HEALTHCHECK` explicite pour les services long-running et
  les `livenessProbe` / `readinessProbe` / `startupProbe` correspondants
  côté K8s.
- Définir `requests` et `limits` de ressources sur chaque conteneur
  (CPU et mémoire).
- Dropper toutes les capabilities Linux puis ne rajouter que ce qui est
  nécessaire : `securityContext.capabilities.drop: [ALL]`.
- Appliquer un profil seccomp (`RuntimeDefault` au minimum) et
  AppArmor / SELinux quand disponible.
- Marquer le système de fichiers en read-only :
  `readOnlyRootFilesystem: true` ; utiliser des volumes `emptyDir` pour
  les quelques chemins qui doivent être en écriture.
- Scanner chaque image en CI (Trivy, Grype, Snyk ou le scanner du
  registry) et faire échouer les builds sur findings CRITICAL ou HIGH.
- Tirer les images de base par digest SHA256 dans les manifests de prod,
  pas par tag mutable.

### JAMAIS
- Exécuter des conteneurs en root ou avec `privileged: true` /
  `allowPrivilegeEscalation: true` en dehors de pods système explicites
  et audités (p. ex. plugins CNI).
- Monter la socket Docker de l'hôte (`/var/run/docker.sock`) dans un
  conteneur d'application. C'est en pratique root sur l'hôte.
- Embarquer des secrets dans les couches d'image via `ENV`, `ARG`,
  `COPY`, ou en `echo`-ant dans un fichier. Même avec `--squash`, le
  cache BuildKit et les couches du registry fuient.
- Utiliser `latest`, `stable`, `slim` ou des tags sans version comme
  base finale — les builds deviennent non-reproductibles et embarquent
  silencieusement des CVEs.
- Utiliser `ADD <url>` pour récupérer des ressources distantes pendant
  le build (utiliser `curl --fail` avec vérification de checksum et
  `RUN` à la place, ou vendoriser l'artefact).
- Désactiver `automountServiceAccountToken` quand le workload a besoin
  de l'API K8s — mais le désactiver
  (`automountServiceAccountToken: false`) quand il n'en a pas besoin.
- Utiliser `hostNetwork: true`, `hostPID: true` ou `hostIPC: true` pour
  des pods d'application.
- Faire tourner des pods dans le namespace `kube-system`, ou dans tout
  namespace sans `NetworkPolicy` ni policy d'admission PodSecurity.

### FAUX POSITIFS CONNUS
- Les operators qui ont légitimement besoin d'accès cluster-admin
  (kubelet, CSI drivers, plugins CNI) requièrent des privilèges
  élevés ; ils appartiennent à `kube-system` ou à un namespace dédié
  audité, pas aux namespaces d'application.
- Les nœuds Kubernetes bare-metal désactivent parfois légitimement
  `seccomp` pour des drivers non compatibles ; documenter
  l'exception.
- Les pods de debug one-shot (kubectl debug, ephemeral containers)
  contournent intentionnellement beaucoup de ces contrôles ; ils ne
  devraient pas être persistés en YAML dans le repo.

## Contexte (pour les humains)

Les conteneurs fuient de deux manières : fuites de couches d'image
(secrets dans `ENV`, artefacts de build laissés dans l'image finale,
CVEs vulnérables de la base) et évasions runtime (privileged mode,
docker.sock, namespaces hôte). NIST SP 800-190 cadre cela comme
**risques d'image**, **risques de registry**, **risques d'orchestrateur**
et **risques runtime**.

Les assistants IA génèrent presque toujours des Dockerfiles qui
marchent et shippent — vite — mais par défaut en single-stage
`FROM node` / `FROM python` et `USER root`. Cette skill est le
contrepoids ; à coupler avec `infrastructure-security` pour les
contrôles K8s au-delà du pod (RBAC, admission, supply chain).

## Références

- `checklists/dockerfile_hardening.yaml`
- `checklists/k8s_pod_security.yaml`
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes).
- [NIST SP 800-190](https://csrc.nist.gov/publications/detail/sp/800-190/final).
