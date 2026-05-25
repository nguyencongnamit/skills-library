---
id: cicd-security
language: fr
source_revision: "4c215e6f"
version: "1.0.0"
title: "Sécurité des pipelines CI/CD"
description: "Durcir GitHub Actions, GitLab CI et pipelines similaires contre les attaques de chaîne d'approvisionnement, l'exfiltration de secrets et les abus de type pwn-request"
category: prevention
severity: critical
applies_to:
  - "lors de l'écriture ou de la revue de fichiers de workflow CI/CD"
  - "lors de l'ajout d'une action / image / script tiers à un pipeline"
  - "lors du câblage de credentials cloud ou registry dans le CI"
  - "lors du triage d'un compromis de pipeline suspecté"
languages: ["yaml", "shell", "*"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "checklists/"
related_skills: ["supply-chain-security", "secret-detection", "container-security"]
last_updated: "2026-05-13"
sources:
  - "OpenSSF Scorecard — Pinned-Dependencies / Token-Permissions"
  - "SLSA v1.0 Build Track"
  - "GitHub Security Lab — Preventing pwn requests"
  - "StepSecurity — tj-actions/changed-files attack analysis"
  - "CWE-1395: Dependency on Vulnerable Third-Party Component"
---

# Sécurité des pipelines CI/CD

## Règles (pour les agents IA)

### TOUJOURS
- Épingler chaque GitHub Action tierce par **SHA de commit** (40
  caractères complets), pas par tag — les tags peuvent être republiés.
  Idem pour les références `include:` de GitLab CI et les workflows
  réutilisables. Renovate / Dependabot peuvent maintenir les épinglages
  SHA à jour.
- Déclarer `permissions:` au niveau du workflow ou du job et limiter par
  défaut à `contents: read`. Accorder les scopes supplémentaires
  (`id-token: write`, `packages: write`, etc.) job par job, jamais
  workflow-wide.
- Utiliser **OIDC** (`id-token: write` + trust policy du fournisseur
  cloud) pour des credentials cloud à courte durée. Ne jamais stocker des
  clés AWS / GCP / Azure de longue durée comme GitHub Secrets.
- Traiter `pull_request_target`, `workflow_run` et tout job
  `pull_request` qui utilise `actions/checkout` avec
  `ref: ${{ github.event.pull_request.head.ref }}` comme **contexte de
  confiance sur du code non fiable**. Soit ne les lance pas, soit
  exécute-les sans secrets et sans jeton d'écriture.
- Faire passer toute expression non fiable (`${{ github.event.* }}`)
  d'abord par une variable d'environnement ; ne jamais l'interpoler
  directement dans le corps `run:` — c'est le sink canonique
  d'injection de script de GitHub Actions.
- Signer les artefacts de release (Sigstore / cosign) et publier des
  attestations de provenance SLSA. Vérifier la provenance dans tout
  pipeline consommateur qui télécharge l'artefact.
- Mettre `runs-on` sur une image de runner durcie et épingler la version
  du runner. StepSecurity Harden-Runner en mode audit (ou un pare-feu
  d'egress équivalent) est recommandé pour tout workflow manipulant des
  secrets.
- Traiter `npm install`, `pip install`, `go install`, `cargo install` et
  `docker pull` invoqués en CI comme exécution de code non fiable.
  Exécuter avec `--ignore-scripts` (npm/yarn), lockfiles épinglés,
  allowlists de registry et jetons à privilège minimum par job.

### JAMAIS
- Épingler une action tierce par tag flottant (`@v1`, `@main`,
  `@latest`). L'incident tj-actions/changed-files de mars 2025 a
  exfiltré des secrets de plus de 23 000 dépôts précisément parce que
  les consommateurs utilisaient des tags flottants.
- `curl | bash` (ou `wget -O- | sh`) un script d'installation en CI. Le
  compromis du bash uploader de Codecov en 2021 a exfiltré les variables
  d'env vers un attaquant pendant ~10 semaines parce que des milliers de
  pipelines exécutaient `bash <(curl https://codecov.io/bash)`. Toujours
  télécharger, vérifier le checksum, puis exécuter.
- Echoyer des secrets dans les logs, même en cas d'échec. Utiliser
  `::add-mask::` pour tout secret calculé à l'exécution et vérifier via
  la recherche dans les logs du workflow GitHub.
- Permettre l'exécution des workflows sur des PRs depuis un fork avec
  `pull_request_target` si un job touche un jeton à scope d'écriture ou
  un secret. La combinaison est le pattern canonique "pwn request"
  documenté par GitHub Security Lab.
- Cacher de l'état mutable (p. ex. `~/.npm`, `~/.cargo`, `~/.gradle`)
  avec uniquement `os` comme clé. Un hit de cache inter-jobs est une
  surface d'attaque inter-tenants — keyer par hash de lockfile et
  scoper sur la ref du workflow.
- Faire confiance aux téléchargements d'artefacts depuis des runs de
  workflow arbitraires sans vérifier le workflow source + le SHA de
  commit. L'empoisonnement de build-cache passe par la réutilisation
  d'artefacts non scopés.
- Stocker des secrets dans des variables de dépôt (`vars.*`) — elles
  sont en clair pour quiconque a un accès lecture. Seuls les
  `secrets.*` sont protégés par les règles de secret scanning + scope.

### FAUX POSITIFS CONNUS
- Les actions first-party de la même organisation que vous miroirisez
  ou forkez en interne peuvent légitimement être épinglées par tag si
  l'org impose des tags signés + branch-protection sur le dépôt de
  l'action.
- Les pipelines de données publiques qui ne manipulent aucun secret et
  ne produisent aucun artefact signé (p. ex. checkers de liens
  nocturnes) n'ont pas besoin d'OIDC ni de provenance SLSA, et peuvent
  utiliser des tags flottants sans impact pratique.
- `pull_request_target` est légitime pour des bots de label / triage
  qui n'appellent que l'API GitHub avec les scopes minimaux requis, ne
  checkoutent pas le code du PR, et n'exposent pas de secrets dans
  l'environnement.

## Contexte (pour les humains)

Le CI/CD est aujourd'hui la cible chaîne-d'approvisionnement la plus
lucrative. Un pipeline exécute du code de confiance contre des
credentials de confiance et des registries de confiance — le
compromettre une fois donne accès à chaque consommateur en aval de
chaque artefact qu'il produit. Le compromis Codecov 2021, l'incident
SolarWinds 2021, l'empoisonnement du pipeline de release d'Ultralytics
PyPI en 2024 et l'exfiltration massive tj-actions/changed-files en 2025
reposaient tous sur des modifications non authentifiées de scripts ou
d'actions consommés par CI.

La plupart des défenses sont mécaniques : épingler par SHA, minimiser
les permissions, utiliser OIDC, signer les artefacts, vérifier la
provenance. Le difficile, c'est de les appliquer à l'échelle d'une
organisation. OpenSSF Scorecard automatise les vérifications pour les
défenses mécaniques et s'intègre avec branch protection.

Cette skill insiste sur les faiblesses de patterns de conception (pwn
requests, injection de script, curl-pipe-bash, tags flottants,
téléchargement d'artefacts non vérifiés) parce que ce sont les patterns
que le YAML de workflow généré par IA réinvente le plus souvent.

## Références

- `checklists/github_actions_hardening.yaml`
- `checklists/gitlab_ci_hardening.yaml`
- [OpenSSF Scorecard](https://github.com/ossf/scorecard).
- [SLSA v1.0 Build Track](https://slsa.dev/spec/v1.0/levels).
- [GitHub Security Lab — Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/).
- [StepSecurity — tj-actions/changed-files attack analysis](https://www.stepsecurity.io/blog/tj-actions-changed-files-attack-analysis).
- [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html).
