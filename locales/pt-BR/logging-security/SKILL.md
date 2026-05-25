---
id: logging-security
language: pt-BR
source_revision: "afe376a8"
version: "1.0.0"
title: "Segurança de logging"
description: "Prevenir vazamentos de segredo/PII em logs, ataques de log-injection, ausência de audit trail e retenção fraca"
category: prevention
severity: high
applies_to:
  - "ao gerar chamadas a logger ou schemas de logging estruturado"
  - "ao configurar log shippers, sinks, retenção e controles de acesso"
  - "ao revisar requisitos de audit logging"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2400
rules_path: "rules/"
related_skills: ["secret-detection", "error-handling-security", "compliance-awareness"]
last_updated: "2026-05-13"
sources:
  - "OWASP Logging Cheat Sheet"
  - "CWE-532 — Insertion of Sensitive Information into Log File"
  - "CWE-117 — Improper Output Neutralization for Logs"
  - "NIST SP 800-92 (Guide to Computer Security Log Management)"
---

# Segurança de logging

## Regras (para agentes de IA)

### SEMPRE
- Logue em um **formato estruturado** (JSON ou logfmt) com nomes
  de campo estáveis. Inclua `timestamp`, `service`, `version`,
  `level`, `trace_id`, `span_id`, `user_id` (quando autenticado),
  `request_id`, `event`.
- Passe cada mensagem de log por um **redactor** antes de chegar
  ao sink: senhas, tokens, API keys, cookies, URLs completas
  contendo `?token=`, padrões comuns de PII (estilo SSN, estilo
  cartão de crédito, opcionalmente e-mail).
- Sanitize newlines / caracteres de controle de qualquer string
  controlada pelo usuário antes de loggar (CWE-117): substitua
  `\n`, `\r`, `\t` para que um atacante não consiga injetar
  linhas de log falsas.
- Logue eventos relevantes para segurança como **registros de
  auditoria imutáveis**: sucesso/falha de login, desafios de MFA,
  troca de senha, troca de role, conceder/revogar acesso,
  exportação de dados, ação de admin. Registros de auditoria
  recebem retenção mais longa e acesso mais estrito.
- Defina retenção por categoria de dado, não global: curta para
  debug, longa para auditoria, nada de PII após o consentimento
  expirar.
- Envie logs para um store centralizado e append-only (Cloud
  Logging, CloudWatch, Elastic, Loki) com acesso de leitura
  restrito a engenharia / SecOps.
- Alerte sobre logs faltando de um serviço (falha silenciosa) e
  sobre anomalias de volume (pico 10× ou queda 10×).

### NUNCA
- Logue bodies completos de request / response em INFO. Bodies
  regularmente contêm senhas, tokens, PII e arquivos enviados.
- Logue headers `Authorization`, headers `Cookie` /
  `Set-Cookie`, tokens em query-string, nem qualquer campo
  chamado `password`, `secret`, `token`, `key`, `private` ou
  `credential` — nem mesmo após "ofuscar" com `***`.
- Logue statements SQL já bindados completos com os valores dos
  parâmetros; logue em vez disso o template + *nomes* dos
  parâmetros + um identificador hasheado do valor.
- Permita que usuários sem privilégio leiam logs crus contendo
  dados de outros usuários.
- Use `print()` / `console.log` / `fmt.Println` puro em serviços
  de produção; use o logger configurado para que redação e
  estrutura sejam aplicadas de forma uniforme.
- Desabilite o logging de tentativas de autenticação falhas para
  "reduzir ruído" — detecção de brute-force depende desses
  registros.
- Logue para um único arquivo em disco local em produção; esses
  logs se perdem quando o pod / container / VM morre.

### FALSOS POSITIVOS CONHECIDOS
- Logs de health-check ou probe do load balancer podem
  legitimamente ser sub-amostrados / suprimidos no load
  balancer para economizar volume.
- Um valor de `request_id` que pareça um token não é um token —
  redactors que casam padrões podem sobre-redigir; whiteliste
  prefixos sabidamente seguros (ex.: seus IDs de correlação
  `req_`).
- Logs de acesso a APIs públicas anônimas sem headers de auth
  não são um problema de privacidade per se; IPs de cliente
  podem ainda ser PII sob a LGPD/GDPR.

## Contexto (para humanos)

Logs são o lugar mais comum onde segredos terminam em texto
claro — dumps de request, traces de exceção, prints de debug,
telemetria de SDKs de terceiros. O OWASP Logging Cheat Sheet
cobre as regras operacionais; NIST SP 800-92 cobre o lado de
retenção / centralização / audit trail. Os requisitos de audit
trail aparecem em SOC 2 CC7.2, PCI-DSS 10, HIPAA §164.312(b) e
ISO 27001 A.12.4.

Este skill é o parceiro de `secret-detection` (que escaneia o
fonte) e `error-handling-security` (que sanitiza a resposta
externa). Logs ficam entre os dois e vazam nas duas direções.

## Referências

- `rules/redaction_patterns.json`
- `rules/audit_event_schema.json`
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
- [CWE-532](https://cwe.mitre.org/data/definitions/532.html).
- [CWE-117](https://cwe.mitre.org/data/definitions/117.html).
- [NIST SP 800-92](https://csrc.nist.gov/publications/detail/sp/800-92/final).
