---
id: iac-security
language: fr
source_revision: "afe376a8"
version: "1.0.0"
title: "Sécurité de l'Infrastructure-as-Code"
description: "Règles de durcissement pour Terraform, CloudFormation et Pulumi : state, providers, drift, secrets"
category: hardening
severity: high
applies_to:
  - "lors de la génération de Terraform / Pulumi / CloudFormation"
  - "lors de la revue de modifications IaC en PR"
  - "lors du câblage d'un nouveau compte cloud ou workspace"
languages: ["hcl", "yaml", "json", "typescript", "python", "go"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2500
rules_path: "checklists/"
related_skills: ["infrastructure-security", "container-security", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "CIS Benchmarks (AWS, Azure, GCP)"
  - "HashiCorp Terraform Best Practices"
  - "NIST SP 800-53 Rev. 5 (CM-6, CM-8, SC-28)"
  - "OWASP IaC Security Top 10"
---

# Sécurité de l'Infrastructure-as-Code

## Règles (pour les agents IA)

### TOUJOURS
- Épingler chaque provider/module à une version exacte ou à une
  contrainte pessimiste (`~> 5.42`) ; jamais `>= 0` ni un `latest`
  non épinglé.
- Configurer un **backend distant** avec chiffrement au repos,
  verrouillage du state côté serveur et versionnement (Terraform :
  `s3` + table de verrouillage DynamoDB avec `kms_key_id` ; Pulumi :
  le backend managé ou `s3://?kmskey=` ; CloudFormation : géré par
  AWS).
- Chiffrer par défaut chaque ressource persistante avec une clé KMS
  gérée par le client : buckets S3, volumes EBS, RDS, EFS, DynamoDB,
  SQS, SNS, log groups CloudWatch.
- Tagger chaque ressource avec `owner`, `environment`, `cost-center`
  et `data-classification` via un bloc de default tags.
- Lancer `terraform plan` (ou `pulumi preview`,
  `aws cloudformation deploy --no-execute-changeset`) en CI et
  exiger une approbation humaine avant l'`apply` sur les stacks de
  production.
- Ajouter un job de détection de drift qui s'exécute
  quotidiennement et ouvre un issue lorsque l'état réel du cloud
  diverge du code (Terraform Cloud drift detection,
  `pulumi refresh`, `cfn-drift-detect`).
- Utiliser des IAM Conditions pour cadrer chaque rôle :
  `aws:SourceArn`, `aws:SourceAccount`, `aws:PrincipalOrgID`, et
  des policies d'accès TLS-only sur le stockage.

### JAMAIS
- Mettre en dur des credentials de provider dans le code ou dans
  `.tfvars` (`access_key`, `secret_key`, `client_secret`,
  `service_account_key`). Utiliser une fédération OIDC depuis le
  CI, le service de métadonnées d'instance du provider, ou un
  secret manager.
- Committer `terraform.tfstate`, `terraform.tfstate.backup`,
  `.pulumi/`, ou tout `*.tfvars` contenant des vrais secrets. Ils
  contiennent des secrets en clair même si le code référence des
  variables.
- Utiliser `local_exec` / `null_resource` pour récupérer des
  secrets au moment de l'apply et les planquer dans le state. Le
  state est du clair interrogeable par quiconque a un accès en
  lecture au backend.
- Ouvrir des security groups / règles de firewall vers `0.0.0.0/0`
  pour les ports 22, 3389, 3306, 5432, 1433, 6379, 27017, 9200,
  11211 — même pas pour « c'est juste de la dev ». Passer par un
  bastion ou un VPN.
- Accorder des policies IAM `*:*` (action wildcard sur ressource
  wildcard). Utiliser `iam:PassRole` avec des ARN de ressource
  explicites.
- Désactiver la vérification TLS du provider (`skip_tls_verify`,
  `insecure = true`).
- Utiliser `count = 0` pour « supprimer en douceur » des ressources
  dont vous voulez vraiment vous débarrasser — détruisez-les.

### FAUX POSITIFS CONNUS
- Les bastion hosts intentionnellement exposés sur le port 22 à
  internet avec des configurations durcies ne sont pas le même
  risque qu'un RDS ouvert au monde. Documenter l'exception inline.
- Les distributions CloudFront publiques, les listeners ALB en
  80/443, les API Gateways et les URLs de fonctions Lambda qui
  *sont* censés être accessibles depuis internet.
- Les ressources de bootstrap (le bucket S3 et la table de
  verrouillage DynamoDB que le backend lui-même utilise) doivent
  exister avant que le state distant existe ; ce dilemme de la
  poule et de l'œuf se bootstrappe en général via un backend
  `local` qu'on migre ensuite.

## Contexte (pour les humains)

Les erreurs IaC passent à l'échelle : un seul mauvais module se
fait `terraform apply` sur des centaines de comptes. Les classes
de problèmes qu'on couvre ici — fuites de secrets via le state,
exposition réseau sans borne, IAM en wildcard, drift — sont
exactement ce que CIS et les revues well-architected des cloud
providers eux-mêmes signalent le plus. Les assistants IA sont
particulièrement enclins à générer du Terraform « ça marche sur ma
machine » qui n'épingle rien et utilise un state local ; ce skill
est le contrepoids.

## Références

- `checklists/terraform_hardening.yaml`
- `checklists/cloudformation_hardening.yaml`
- [CIS Benchmark for Amazon Web Services Foundations](https://www.cisecurity.org/benchmark/amazon_web_services).
- [Terraform Recommended Practices](https://developer.hashicorp.com/terraform/cloud-docs/recommended-practices).
- [NIST SP 800-53 Rev. 5 control catalog](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final).
