---
id: serverless-security
language: de
source_revision: "afe376a8"
version: "1.0.0"
title: "Serverless-Security"
description: "Lambda / Cloud Functions / Azure Functions härten: IAM, Timeouts, Secrets, Event-Injection"
category: hardening
severity: high
applies_to:
  - "beim Generieren von AWS-Lambda- / GCP-Cloud-Functions- / Azure-Functions-Code"
  - "beim Generieren von serverless.yml / SAM-Templates / functions framework"
  - "beim Verdrahten von API-Gateway-, EventBridge-, SQS-, S3-Triggern"
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

# Serverless-Security

## Regeln (für KI-Agenten)

### IMMER
- Jeder Function ihre eigene IAM-Execution-Role mit den minimal
  nötigen Berechtigungen geben. Rollen nie zwischen Functions
  teilen; nie die Bootstrap- / Entwickler-Rolle wiederverwenden.
- Konkretes Function-Timeout setzen (≤ 30s für synchrone APIs,
  ≤ 15min für Background-Jobs). Defaults wie 6s oder 900s sind
  Footguns in verschiedene Richtungen.
- Reservierte oder provisioned Concurrency-Limits pro Function
  setzen, um Bill-Blow-outs zu vermeiden und zu verhindern, dass
  ein lauter Tenant den Rest des Accounts aushungert.
- Secrets beim Cold-Start aus einem Secret Manager (AWS Secrets
  Manager / GCP Secret Manager / Azure Key Vault) **mit Caching**
  ziehen, nicht aus Plaintext-Environment-Variables.
- Jedes Event-Payload gegen ein Schema validieren, bevor Code es
  anfasst. Lambda interessiert nicht, dass das Event aus „deiner"
  SQS-Queue kam — es könnte eine Poison-Message sein.
- Strukturiertes Logging aktivieren, das bekannte Secret-Patterns
  redigiert (an den Skill `logging-security` delegieren).
- X-Ray-/OpenTelemetry-Tracing und CloudWatch-/Cloud-Monitoring-
  Alerts auf Error-Rate, Throttle-Count, Duration p95 aktivieren.
- Eine VPC für Functions verwenden, die eine private Datenbank oder
  Service erreichen; sonst bekommt die Function vollen Internet-
  Egress, was selten erwünscht ist.

### NIE
- `arn:aws:iam::*:role/*` (Wildcard-PassRole), `*:*` Action/Resource
  oder `iam:*`-Berechtigungen auf einer Function-Role verwenden.
- Secrets in Environment-Variables im Plaintext ablegen (Secrets-
  Manager-Referenzen / `aws_lambda_function.environment` mit
  `kms_key_arn` verwenden).
- Vom Benutzer kontrollierte Strings an `exec`, `os.system`,
  `child_process`, `subprocess.Popen(shell=True)` weitergeben —
  Function URLs werden zu RCE-Shortcuts, sobald jemand shellt.
- Der Lambda Function URL oder dem API-Gateway-Resource als
  Authentifizierung vertrauen. Function URLs mit `AUTH_TYPE=NONE`
  sind unauthentifiziert; IAM, Cognito oder einen Lambda-Authorizer
  voraussetzen.
- `aws_lambda_function.code_signing_config_arn` für Produktions-
  Functions deaktivieren; beim Deploy signieren und verifizieren.
- Das `latest`-Image-Tag für Container-Image-Functions verwenden;
  per Digest pinnen.
- Langlebige statische AWS-Access-Keys zum Aufruf von AWS aus
  Lambda verwenden — die Execution-Role nutzen.
- Validierung von S3- / SQS- / EventBridge-Event-Payloads
  überspringen — annehmen, jeder Caller könne jede Shape posten,
  auch wenn der Trigger „vertrauenswürdig" ist.

### BEKANNTE FALSCH-POSITIVE
- Custom-CloudFormation- / Lambda-Resource-Handler (`cfn-response`)
  brauchen manchmal legitim breite Berechtigungen für kurzlebiges
  Setup.
- Cold-Start-Warmer-Hacks (die Function per CloudWatch-Events-
  Schedule anpingen) sind selbst kein Security-Issue.
- Step-Functions-Iteratoren mit Tausenden Map-States sind kein
  Problem „unverfolgter Concurrency", wenn die StateMachine ihren
  eigenen Concurrency-Cap hat.

## Kontext (für Menschen)

Das OWASP Serverless Top 10 nennt dieselben Familien wie das
reguläre Top 10 plus zwei serverless-spezifische Risiken:
**Event-Injection** (das Event selbst enthält nicht-vertrauten Input
— eine SQS-Message, einen S3-Object-Key — den downstream Code als
vertraut behandelt) und **Denial-of-Wallet** (ein Angreifer
erschöpft deine Concurrency, um deine Rechnung hochzutreiben).

KI-Assistenten neigen dazu, Lambdas mit `*:*`-IAM, Environment-
Variable-Secrets und keiner Event-Validierung zu generieren. Dieser
Skill ist das Gegengewicht.

## Referenzen

- `checklists/lambda_hardening.yaml`
- `checklists/event_validation.yaml`
- [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/).
- [AWS Well-Architected Security Pillar — Serverless](https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/security-pillar.html).
