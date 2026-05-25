---
id: error-handling-security
language: pt-BR
source_revision: "afe376a8"
version: "1.0.0"
title: "Segurança no tratamento de erros"
description: "Sem stack traces / SQL / paths / versões de framework nas respostas ao cliente; erros genéricos para fora, erros estruturados nos logs"
category: prevention
severity: medium
applies_to:
  - "ao gerar handlers de erro HTTP / GraphQL / RPC"
  - "ao gerar blocos exception / panic / rescue"
  - "ao configurar páginas de erro default do framework"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 900
  full: 1900
rules_path: "rules/"
related_skills: ["api-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP Error Handling Cheat Sheet"
  - "CWE-209 — Generation of Error Message Containing Sensitive Information"
  - "CWE-754 — Improper Check for Unusual or Exceptional Conditions"
---

# Segurança no tratamento de erros

## Regras (para agentes de IA)

### SEMPRE
- Capture exceções na fronteira (handler HTTP, método RPC, consumer
  de mensagens). Logue com contexto completo no lado servidor;
  retorne um erro sanitizado para fora.
- Respostas de erro externas incluem: um código de erro estável, uma
  mensagem curta legível por humanos e um ID de correlação /
  request. Elas nunca incluem: stack trace, fragmento de SQL, path
  de arquivo, hostname interno, banner de versão do framework.
- Logue erros no nível adequado: `ERROR` / `WARN` para falhas
  acionáveis; `INFO` para resultados de negócio esperados; `DEBUG`
  para detalhe de diagnóstico (e apenas quando explicitamente
  habilitado).
- Retorne respostas de erro uniformes em toda a superfície da API —
  mesma forma, mesmo conjunto de códigos — para que atacantes não
  consigam inferir comportamento a partir de variações de erro
  (ex.: login: mesma mensagem e mesmo timing para "usuário
  errado" vs "senha errada").
- Desabilite as páginas de erro default do framework em produção
  (`app.debug = False` / `Rails.env.production?` /
  `Environment=Production` / `DEBUG=False`). Substitua por uma
  página 5xx que retorne apenas o ID de correlação.
- Use um helper centralizado de renderização de erro para que as
  regras de sanitização vivam em um único lugar, sem duplicação.

### NUNCA
- Renderize `traceback.format_exc()`, `e.toString()`,
  `printStackTrace()`, `panic` ou páginas de debug do framework para
  o cliente em produção.
- Ecoe queries / parâmetros SQL em mensagens de erro —
  `IntegrityError: duplicate key value violates unique constraint
  "users_email_key"` informa ao atacante o nome da tabela e da
  coluna.
- Vaze informação de presença de registro: `User not found` vs
  `Invalid password` permite enumerar contas. Use uma única
  mensagem para ambos.
- Vaze paths do filesystem (`/var/www/app/src/handlers.py`) ou
  banners de versão (`X-Powered-By: Express/4.17.1`).
- Trate `try / except: pass` como tratamento de erro; ou a exceção é
  esperada (logue + continue) ou não é (deixe propagar).
- Use respostas de erro 4xx para validar a forma do input — bots
  iteram sobre parâmetros e usam o body da resposta para aprender o
  schema. Retorne um 400 uniforme mais um ID de correlação para
  input malformado.
- Envie detalhes completos de erro (incluindo PII) a serviços de
  error tracking de terceiros sem um scrubber. Redija `password`,
  `Authorization`, `Cookie`, `Set-Cookie`, `token`, `secret` e
  padrões comuns de PII.

### FALSOS POSITIVOS CONHECIDOS
- Páginas de erro voltadas para desenvolvedores em `localhost` /
  `*.local` estão OK.
- Um punhado de endpoints de API (debug, admin, RPC interno) pode
  legitimamente retornar mais detalhe; eles precisam exigir callers
  autenticados e autorizados e nunca devem ser alcançáveis pela
  internet.
- Health checks e smoke tests de CI expõem detalhe
  intencionalmente quando invocados de dentro do cluster.

## Contexto (para humanos)

CWE-209 é texto pequeno mas impacto grande: é assim que atacantes
passam de "este serviço existe" para "este serviço roda Spring 5.2
em Tomcat 9 com uma tabela PostgreSQL chamada `users` e uma coluna
chamada `email_normalized`". Cada detalhe extra na mensagem de erro
reduz o custo do próximo ataque.

Esta skill é deliberadamente estreita e se conjuga com
`logging-security` (o lado *log* da mesma operação) e
`api-security` (a forma da resposta).

## Referências

- `rules/error_response_template.json`
- `rules/redaction_patterns.json`
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html).
- [CWE-209](https://cwe.mitre.org/data/definitions/209.html).
