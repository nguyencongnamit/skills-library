---
id: infrastructure-security
language: fr
source_revision: "fbb3a823"
version: "1.0.0"
title: "Sécurité de l'infrastructure"
description: "Appliquer des règles de durcissement pour Kubernetes, Docker et l'infrastructure-as-code Terraform"
category: hardening
severity: high
applies_to:
  - "lors de la génération de contenu de Dockerfile"
  - "lors de la génération de manifests Kubernetes ou de charts Helm"
  - "lors de la génération de Terraform ou CloudFormation"
  - "lors de la revue de PRs IaC"
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

# Sécurité de l'infrastructure

## Règles (pour les agents IA)

### TOUJOURS
- Épingler les images de base par digest (`FROM image@sha256:...`)
  lors du build de containers pour la production. Les tags sont
  mutables ; les digests non.
- Faire tourner les containers avec un `USER` non-root différent de
  `0`. Ajouter `securityContext: runAsNonRoot: true` aux pod specs
  K8s.
- Définir des `requests` ET `limits` Kubernetes explicites
  (`requests.cpu`, `requests.memory`, `limits.cpu`,
  `limits.memory`).
- Drop toutes les capabilities Linux et ne rajouter que celles
  requises (`securityContext.capabilities.drop: ["ALL"]`).
- Marquer les filesystems en read-only
  (`securityContext.readOnlyRootFilesystem: true`) quand le workload
  n'a légitimement pas besoin d'accès en écriture.
- Activer le chiffrement au repos (`enable_kms_encryption`,
  `kms_key_id`, `server_side_encryption_configuration`) pour les
  buckets S3, volumes EBS, RDS, DynamoDB.
- Mettre `block_public_access` sur chaque bucket S3 sauf si le
  workload sert vraiment du contenu public.
- Appliquer le principe de moindre privilège aux policies IAM :
  nommer des actions et ressources explicites ; éviter `*:*` et
  `Resource: "*"` en dehors de policies admin volontaires.

### JAMAIS
- Utiliser `latest` comme tag d'image dans les manifests de
  production.
- Lancer un container avec le flag `--privileged` ou
  `securityContext.privileged: true`.
- Monter le `/var/run/docker.sock` de l'hôte dans un container.
- Exposer des services Kubernetes en `type: LoadBalancer`
  directement sur internet sans ingress controller, WAF ni couche
  d'authentification devant.
- Mettre en dur des clés AWS / clés de service-account GCP / client
  secrets Azure dans l'IaC. Utiliser IRSA, GKE Workload Identity,
  les managed identities Azure, ou l'équivalent natif de la
  plateforme.
- Créer des buckets S3 avec `acl = "public-read"` pour des buckets
  contenant autre chose que des assets volontairement publics.
- Autoriser un ingress `0.0.0.0/0` sur des ports de base de données,
  SSH, RDP ou d'admin.
- Désactiver `node_to_node_encryption` sur Elasticsearch /
  OpenSearch.

### FAUX POSITIFS CONNUS
- Le pinning par digest d'image n'est pas toujours pratique en
  environnement dev / preview — le pinning par tag (p. ex.
  `node:20.11.1-alpine`) y est acceptable.
- `Resource: "*"` est acceptable dans des policies documentées
  admin-only avec des contraintes `Condition` explicites.
- `runAsNonRoot: false` est acceptable quand le workload requiert
  légitimement root (p. ex. binder le port 80, certains outils
  réseau). Documenter pourquoi.

## Contexte (pour les humains)

L'infrastructure mal configurée est la cause dominante des fuites
cloud. Les patterns ci-dessus codifient les items de benchmark CIS
les plus violés en règles que l'IA applique pendant la génération,
pas après le déploiement.

## Références

- `checklists/k8s_hardening.yaml`
- `checklists/docker_security.yaml`
- `checklists/terraform_security.yaml`
- [NSA/CISA Kubernetes Hardening Guidance](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF).
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).
