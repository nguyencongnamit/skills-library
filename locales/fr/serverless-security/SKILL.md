---
id: serverless-security
language: fr
source_revision: "afe376a8"
version: "1.0.0"
title: "Sécurité serverless"
description: "Durcissement Lambda / Cloud Functions / Azure Functions : IAM, timeouts, secrets, event injection"
category: hardening
severity: high
applies_to:
  - "lors de la génération de code AWS Lambda / GCP Cloud Functions / Azure Functions"
  - "lors de la génération de serverless.yml / templates SAM / functions framework"
  - "lors du câblage de triggers API Gateway, EventBridge, SQS, S3"
languages: ["python", "javascript", "typescript", "go", "java", "yaml"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2200
rules_path: "checklists/"
related_skills: ["iac-security", "api-security", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "OWASP Serverless Top 10"
  - "AWS Well-Architected: Security Pillar — Lambda"
  - "CIS AWS Foundations Benchmark §3 (Lambda)"
  - "NIST SP 800-204 (Microservices)"
---

# Sécurité serverless

## Règles (pour les agents IA)

### TOUJOURS
- Donner à chaque function son propre IAM execution role avec le
  minimum de permissions nécessaires. Ne jamais partager des roles
  entre functions ; ne jamais réutiliser le role de bootstrap / du
  développeur.
- Mettre un timeout concret de function (≤ 30s pour des APIs
  synchrones, ≤ 15min pour des jobs de background). Les défauts
  comme 6s ou 900s sont des footguns dans des directions
  différentes.
- Mettre des limites de concurrency réservée ou provisionnée par
  function pour éviter les bill blow-outs et empêcher qu'un tenant
  bruyant n'affame le reste du compte.
- Pull les secrets au cold-start depuis un secret manager (AWS
  Secrets Manager / GCP Secret Manager / Azure Key Vault) **avec
  caching**, pas depuis des environment variables en clair.
- Valider chaque event payload contre un schema avant tout code
  qui le touche. Lambda se fiche que l'event soit arrivé de « ta »
  SQS queue — ça peut être un poison message.
- Activer un logging structuré qui redacte les patterns de secret
  connus (déléguer au skill `logging-security`).
- Activer le tracing X-Ray / OpenTelemetry et des alertes
  CloudWatch / Cloud Monitoring sur taux d'erreur, count de
  throttles, durée p95.
- Utiliser un VPC pour les functions qui touchent une base de
  données ou un service privé ; sinon la function a un egress
  internet complet, ce qui est rarement souhaitable.

### JAMAIS
- Utiliser `arn:aws:iam::*:role/*` (PassRole en wildcard), `*:*`
  action/resource ou des permissions `iam:*` sur un role de
  function.
- Mettre des secrets dans des environment variables en clair
  (utiliser des références Secrets Manager /
  `aws_lambda_function.environment` avec `kms_key_arn`).
- Passer des strings contrôlés par l'utilisateur à `exec`,
  `os.system`, `child_process`, `subprocess.Popen(shell=True)` —
  les function URLs deviennent des raccourcis vers RCE quand
  quelqu'un shelle.
- Faire confiance à la Lambda function URL ou à la resource API
  Gateway comme authentification. Les function URLs avec
  `AUTH_TYPE=NONE` sont non authentifiées ; exiger IAM, Cognito ou
  un Lambda authorizer.
- Désactiver `aws_lambda_function.code_signing_config_arn` pour
  des functions de production ; signer et vérifier au deploy.
- Utiliser le tag `latest` pour des functions à image de
  container ; pinner par digest.
- Utiliser des access keys AWS statiques à longue durée pour
  appeler AWS depuis Lambda — utiliser l'execution role.
- Sauter la validation des event payloads S3 / SQS / EventBridge
  — supposer que n'importe quel caller peut poster n'importe
  quelle shape, même si le trigger est « de confiance ».

### FAUX POSITIFS CONNUS
- Les custom resource handlers de CloudFormation / Lambda
  (`cfn-response`) ont parfois légitimement besoin de permissions
  larges pour du setup à durée courte.
- Les hacks de warmer de cold-start (pinger la function avec un
  schedule CloudWatch Events) ne sont pas, en soi, un problème de
  sécurité.
- Les iterators Step Functions avec des milliers de map states ne
  sont pas un problème de « concurrency non suivie » si la
  StateMachine a son propre cap de concurrency.

## Contexte (pour les humains)

Le Serverless Top 10 d'OWASP nomme les mêmes familles que le Top
10 régulier plus deux risques spécifiques au serverless :
**event injection** (l'event lui-même contient de l'input non
confiance — un message SQS, un object key S3 — que du code
downstream traite comme confiance) et **denial-of-wallet** (un
attaquant épuise ta concurrency pour faire monter ta facture).

Les assistants IA tendent à générer des Lambdas avec un IAM
`*:*`, des secrets en environment variables, et sans validation
d'events. Ce skill est le contrepoids.

## Références

- `checklists/lambda_hardening.yaml`
- `checklists/event_validation.yaml`
- [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/).
- [AWS Well-Architected Security Pillar — Serverless](https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/security-pillar.html).
