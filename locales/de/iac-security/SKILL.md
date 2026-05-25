---
id: iac-security
language: de
source_revision: "afe376a8"
version: "1.0.0"
title: "Infrastructure-as-Code-Sicherheit"
description: "Härtungsregeln für Terraform, CloudFormation und Pulumi: State, Provider, Drift, Secrets"
category: hardening
severity: high
applies_to:
  - "beim Erzeugen von Terraform / Pulumi / CloudFormation"
  - "beim Review von IaC-Änderungen im PR"
  - "beim Verdrahten eines neuen Cloud-Accounts oder Workspaces"
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

# Infrastructure-as-Code-Sicherheit

## Regeln (für KI-Agenten)

### IMMER
- Jeden Provider/jedes Modul auf eine exakte Version oder eine
  pessimistische Einschränkung pinnen (`~> 5.42`); nie `>= 0` oder
  ungepinntes `latest`.
- Ein **Remote Backend** mit Verschlüsselung im Ruhezustand,
  serverseitigem State-Locking und Versionierung konfigurieren
  (Terraform: `s3` + DynamoDB-Lock-Tabelle mit `kms_key_id`;
  Pulumi: das Managed Backend oder `s3://?kmskey=`;
  CloudFormation: von AWS verwaltet).
- Jede persistente Ressource standardmässig mit einem
  Customer-Managed-KMS-Key verschlüsseln: S3-Buckets, EBS-Volumes,
  RDS, EFS, DynamoDB, SQS, SNS, CloudWatch-Log-Groups.
- Jede Ressource via Default-Tags-Block mit `owner`, `environment`,
  `cost-center` und `data-classification` taggen.
- `terraform plan` (oder `pulumi preview`,
  `aws cloudformation deploy --no-execute-changeset`) in CI laufen
  lassen und vor dem `apply` auf Produktions-Stacks ein menschliches
  Approval verlangen.
- Einen Drift-Detection-Job hinzufügen, der täglich läuft und ein
  Issue öffnet, wenn der tatsächliche Cloud-State vom Code abweicht
  (Terraform Cloud Drift Detection, `pulumi refresh`,
  `cfn-drift-detect`).
- IAM-Conditions verwenden, um jede Rolle einzugrenzen:
  `aws:SourceArn`, `aws:SourceAccount`, `aws:PrincipalOrgID` und
  TLS-only-Access-Policies auf Storage.

### NIE
- Provider-Credentials im Code oder in `.tfvars` hardcoden
  (`access_key`, `secret_key`, `client_secret`,
  `service_account_key`). OIDC-Federation aus CI, den
  Instance-Metadata-Service des Providers oder einen Secret-
  Manager verwenden.
- `terraform.tfstate`, `terraform.tfstate.backup`, `.pulumi/` oder
  beliebige `*.tfvars`, die echte Secrets enthalten, einchecken. Sie
  enthalten Klartext-Secrets, selbst wenn der Code Variablen
  referenziert.
- `local_exec` / `null_resource` verwenden, um Secrets zur Apply-
  Zeit zu holen und im State abzulegen. State ist abfragbarer
  Klartext für jeden mit Lesezugriff auf das Backend.
- Security Groups / Firewall-Regeln auf `0.0.0.0/0` für die Ports
  22, 3389, 3306, 5432, 1433, 6379, 27017, 9200, 11211 öffnen —
  auch nicht für "nur Dev". Bastion oder VPN verwenden.
- IAM-Policies mit `*:*` (Wildcard-Action auf Wildcard-Resource)
  vergeben. `iam:PassRole` mit expliziten Resource-ARNs verwenden.
- Provider-TLS-Verifikation deaktivieren (`skip_tls_verify`,
  `insecure = true`).
- `count = 0` verwenden, um Ressourcen "soft-zu-löschen", die du
  eigentlich loswerden willst — zerstöre sie.

### BEKANNTE FALSCH-POSITIVE
- Bastion-Hosts, die absichtlich auf Port 22 mit gehärteten
  Konfigurationen ins Internet exponiert sind, sind nicht dasselbe
  Risiko wie eine RDS-Instanz, die für die Welt offen ist. Die
  Ausnahme inline dokumentieren.
- Öffentliche CloudFront-Distributions, ALB-Listener auf 80/443,
  API Gateways und Lambda-Function-URLs, die *bewusst*
  internetseitig sein sollen.
- Bootstrap-Ressourcen (der S3-Bucket und die DynamoDB-Lock-Tabelle,
  die das Backend selbst verwendet) müssen existieren, bevor es
  Remote-State geben kann; dieses Henne-Ei-Problem wird üblicher-
  weise einmalig mit einem `local`-Backend gebootstrappt, das dann
  migriert wird.

## Kontext (für Menschen)

IaC-Fehler skalieren: ein einziges schlechtes Modul wird mit
`terraform apply` in Hunderte Accounts ausgerollt. Die Problem-
klassen, die wir hier abdecken — State-Secret-Leaks, ungebremste
Netz-Exposition, Wildcard-IAM, Drift — sind genau das, was CIS und
die Well-Architected-Reviews der Cloud-Anbieter selbst am häufigsten
markieren. KI-Assistenten neigen besonders dazu, Terraform à la
"funktioniert auf meinem Rechner" zu generieren, das nichts pinnt
und Local-State verwendet; dieser Skill ist das Gegengewicht.

## Referenzen

- `checklists/terraform_hardening.yaml`
- `checklists/cloudformation_hardening.yaml`
- [CIS Benchmark for Amazon Web Services Foundations](https://www.cisecurity.org/benchmark/amazon_web_services).
- [Terraform Recommended Practices](https://developer.hashicorp.com/terraform/cloud-docs/recommended-practices).
- [NIST SP 800-53 Rev. 5 control catalog](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final).
