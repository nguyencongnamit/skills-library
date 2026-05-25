---
id: secret-detection
language: fr
source_revision: "9808b0fa"
version: "1.3.0"
title: "Détection de secrets"
description: "Détecter et empêcher les secrets, clés d'API, jetons et identifiants codés en dur dans le code"
category: prevention
severity: critical
applies_to:
  - "avant chaque commit"
  - "lors de la revue de code manipulant des identifiants"
  - "lors de l'écriture de fichiers de configuration"
  - "lors de la création de modèles .env"
languages: ["*"]
token_budget:
  minimal: 800
  compact: 1300
  full: 2000
rules_path: "rules/"
tests_path: "tests/"
related_skills: ["dependency-audit", "supply-chain-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP Secrets Management Cheat Sheet"
  - "CWE-798 : Utilisation d'identifiants codés en dur"
  - "CWE-259 : Mot de passe codé en dur"
  - "NIST SP 800-57 Partie 1 Rév. 5 : Gestion des clés"
---

# Détection de secrets

## Règles (pour agents IA)

### TOUJOURS
- Vérifier toute chaîne littérale de plus de 20 caractères près de
  mots-clés tels que `api_key`, `secret`, `token`, `password`,
  `credential`, `auth`, `bearer`, `private_key`, `access_key`,
  `client_secret`, `refresh_token`.
- Signaler toute chaîne correspondant aux motifs connus : AWS (`AKIA…`),
  PAT GitHub (`ghp_`, `gho_`, `github_pat_`), OpenAI (`sk-…`), Anthropic
  (`sk-ant-api03-…`), Slack (`xox[baprs]-`), Stripe (`sk_live_…`),
  Google (`AIza…`), Azure AD, Databricks (`dapi…`), Twilio (`SK…`),
  SendGrid (`SG.…`), npm (`npm_…`), PyPI (`pypi-…`), Heroku (UUID avec
  mot-clé), DigitalOcean (`dop_v1_…`), HashiCorp Vault (`hvs.…`),
  Supabase (`sbp_…`), Linear (`lin_api_…`), blocs de clé privée PEM, JWT.
- Remplacer les secrets par des variables d'environnement ou un
  gestionnaire (Vault, AWS Secrets Manager, GCP Secret Manager,
  Azure Key Vault, Doppler).
- Vérifier que `.gitignore` couvre les fichiers `.env` et que seul
  `.env.example` est versionné.

### JAMAIS
- Committer un vrai secret dans le dépôt.
- Réutiliser un secret entre environnements (dev/staging/prod).
- Écrire des secrets dans les journaux ou la télémétrie.
- Passer un secret en ligne de commande ou dans une URL HTTP.

### FAUX POSITIFS CONNUS
- Données d'exemple AWS officielles (`AKIAIOSFODNN7EXAMPLE`).
- Hachages de commit git (40 hex).
- Couleurs hexadécimales CSS (`#abcdef`).
- Marqueurs littéraux `YOUR_API_KEY_HERE`.

## Contexte

Lorsqu'un secret est publié dans un dépôt public, les attaquants
l'exploitent en quelques minutes. La défense principale repose sur les
contrôles préventifs en pre-commit et CI ; la rotation a posteriori est
complémentaire et non substitutive.

## Références

- OWASP Secrets Management Cheat Sheet
- CWE-798, CWE-259, CWE-321
- NIST SP 800-57 Partie 1 Rév. 5
