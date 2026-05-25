---
id: serverless-security
language: es
source_revision: "afe376a8"
version: "1.0.0"
title: "Seguridad serverless"
description: "Endurecimiento de Lambda / Cloud Functions / Azure Functions: IAM, timeouts, secrets, event injection"
category: hardening
severity: high
applies_to:
  - "al generar código de AWS Lambda / GCP Cloud Functions / Azure Functions"
  - "al generar serverless.yml / plantillas SAM / functions framework"
  - "al cablear triggers de API Gateway, EventBridge, SQS, S3"
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

# Seguridad serverless

## Reglas (para agentes de IA)

### SIEMPRE
- Dar a cada función su propio IAM execution role con los permisos
  mínimos necesarios. Nunca compartir roles entre funciones; nunca
  reutilizar el role de bootstrap / del desarrollador.
- Setear un timeout concreto de función (≤ 30s para APIs síncronas,
  ≤ 15min para jobs de background). Defaults como 6s o 900s son
  footguns en direcciones distintas.
- Setear límites de concurrency reservada o provisionada por función
  para evitar bill blow-outs y para impedir que un tenant ruidoso
  starve al resto de la cuenta.
- Pull secrets en cold-start desde un secret manager (AWS Secrets
  Manager / GCP Secret Manager / Azure Key Vault) **con caching**,
  no desde environment variables en plaintext.
- Validar cada event payload contra un schema antes de cualquier
  código que lo toque. A Lambda no le importa que el event haya
  llegado de "tu" SQS queue — podría ser un poison message.
- Habilitar logging estructurado que redacte patrones de secret
  conocidos (delegar al skill `logging-security`).
- Habilitar tracing X-Ray / OpenTelemetry y alertas CloudWatch /
  Cloud Monitoring sobre tasa de error, count de throttles, duración
  p95.
- Usar una VPC para funciones que toquen una base de datos o
  servicio privado; si no, la función obtiene salida full a internet,
  lo cual rara vez es deseable.

### NUNCA
- Usar `arn:aws:iam::*:role/*` (PassRole con wildcard), `*:*`
  action/resource, o permisos `iam:*` en un role de función.
- Poner secrets en environment variables en plaintext (usar
  referencias de Secrets Manager / `aws_lambda_function.environment`
  con `kms_key_arn`).
- Pasar strings controlados por usuario a `exec`, `os.system`,
  `child_process`, `subprocess.Popen(shell=True)` — function URLs
  se convierten en shortcuts a RCE cuando alguien shellea.
- Confiar en la Lambda function URL o en el recurso de API Gateway
  como autenticación. Function URLs con `AUTH_TYPE=NONE` están sin
  autenticar; requerir IAM, Cognito, o un Lambda authorizer.
- Deshabilitar `aws_lambda_function.code_signing_config_arn` para
  funciones de producción; firmar y verificar en deploy.
- Usar el tag `latest` para funciones de imagen de container;
  pinear por digest.
- Usar AWS access keys estáticas de larga vida para llamar a AWS
  desde Lambda — usar el execution role.
- Saltarse la validación de payloads de S3 / SQS / EventBridge —
  asumir que cualquier caller puede postear cualquier forma, incluso
  si el trigger es "confiable".

### FALSOS POSITIVOS CONOCIDOS
- Handlers de custom resources de CloudFormation / Lambda
  (`cfn-response`) a veces legítimamente necesitan permisos amplios
  para setup de corta duración.
- Hacks de calentamiento de cold-start (pingear la función con un
  schedule de CloudWatch Events) no son, en sí mismos, un problema
  de seguridad.
- Iteradores Step Functions con miles de map states no son un
  problema de "concurrency no rastreada" si el StateMachine tiene
  su propio cap de concurrency.

## Contexto (para humanos)

El Serverless Top 10 de OWASP nombra las mismas familias que el
Top 10 normal más dos riesgos específicos del serverless:
**event injection** (el event en sí mismo contiene input no
confiable — un mensaje SQS, un object key de S3 — que código
downstream trata como confiable) y **denial-of-wallet** (un
atacante exhaure tu concurrency para hacer subir tu bill).

Los asistentes de IA tienden a generar Lambdas con IAM `*:*`,
secrets en environment variables, y sin validación de events.
Este skill es el contrapeso.

## Referencias

- `checklists/lambda_hardening.yaml`
- `checklists/event_validation.yaml`
- [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/).
- [AWS Well-Architected Security Pillar — Serverless](https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/security-pillar.html).
