---
id: serverless-security
language: pt-BR
source_revision: "afe376a8"
version: "1.0.0"
title: "Segurança serverless"
description: "Hardening de Lambda / Cloud Functions / Azure Functions: IAM, timeouts, segredos, event injection"
category: hardening
severity: high
applies_to:
  - "ao gerar código de AWS Lambda / GCP Cloud Functions / Azure Functions"
  - "ao gerar serverless.yml / templates SAM / functions framework"
  - "ao ligar triggers de API Gateway, EventBridge, SQS, S3"
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

# Segurança serverless

## Regras (para agentes de IA)

### SEMPRE
- Dê a cada function seu próprio IAM execution role com as
  permissões mínimas necessárias. Nunca compartilhe roles entre
  functions; nunca reutilize o role de bootstrap / dev.
- Defina um timeout concreto na function (≤ 30s para APIs
  síncronas, ≤ 15min para jobs em background). Defaults como 6s
  ou 900s são footguns em direções diferentes.
- Defina limites de concurrency reservada ou provisionada por
  function para evitar bill blow-outs e impedir que um tenant
  barulhento mate o resto da conta de fome.
- Puxe segredos no cold-start de um secrets manager (AWS Secrets
  Manager / GCP Secret Manager / Azure Key Vault) **com cache**,
  não de environment variables em texto claro.
- Valide todo event payload contra um schema antes de qualquer
  código que o toque. O Lambda não liga que o event veio da
  "sua" SQS queue — pode ser uma poison message.
- Habilite logging estruturado que redacta patterns de segredo
  conhecidos (delegue para o skill `logging-security`).
- Habilite tracing X-Ray / OpenTelemetry e alerts no
  CloudWatch / Cloud Monitoring para taxa de erro, contagem de
  throttle, duração p95.
- Use uma VPC para functions que tocam um banco ou serviço
  privado; do contrário, a function ganha egress completo para a
  internet, o que raramente é desejável.

### NUNCA
- Use `arn:aws:iam::*:role/*` (PassRole wildcard), `*:*`
  action/resource, ou permissões `iam:*` num role de function.
- Coloque segredos em environment variables em texto claro (use
  referências do Secrets Manager /
  `aws_lambda_function.environment` com `kms_key_arn`).
- Passe strings controladas por usuário para `exec`,
  `os.system`, `child_process`, `subprocess.Popen(shell=True)` —
  function URLs viram atalho para RCE quando alguém shelleia.
- Confie na Lambda function URL ou no resource do API Gateway
  como autenticação. Function URLs com `AUTH_TYPE=NONE` são não
  autenticadas; exija IAM, Cognito ou um Lambda authorizer.
- Desabilite `aws_lambda_function.code_signing_config_arn` para
  functions de produção; assine e verifique no deploy.
- Use a tag `latest` para functions de container image; pin por
  digest.
- Use AWS access keys estáticas de longa duração para chamar a
  AWS de dentro do Lambda — use o execution role.
- Pule validação de payloads de S3 / SQS / EventBridge — assuma
  que qualquer caller pode postar qualquer formato, mesmo se o
  trigger é "confiável".

### FALSOS POSITIVOS CONHECIDOS
- Handlers customizados de resource do CloudFormation / Lambda
  (`cfn-response`) às vezes legitimamente precisam de permissões
  amplas para setup de curta duração.
- Hacks de aquecer cold-start (pingar a function via schedule do
  CloudWatch Events) não são, por si só, um problema de
  segurança.
- Iteradores do Step Functions com milhares de map states não
  são um problema de "concurrency não rastreada" se a
  StateMachine tem o próprio cap de concurrency.

## Contexto (para humanos)

O Serverless Top 10 do OWASP nomeia as mesmas famílias do Top 10
comum mais dois riscos específicos de serverless: **event
injection** (o próprio event contém input não confiável — uma
mensagem SQS, um object key do S3 — que código downstream trata
como confiável) e **denial-of-wallet** (um atacante esgota sua
concurrency para fazer sua conta explodir).

Assistentes de IA tendem a gerar Lambdas com IAM `*:*`, segredos
em environment variable e sem validação de event. Esse skill é o
contrapeso.

## Referências

- `checklists/lambda_hardening.yaml`
- `checklists/event_validation.yaml`
- [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/).
- [AWS Well-Architected Security Pillar — Serverless](https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/security-pillar.html).
