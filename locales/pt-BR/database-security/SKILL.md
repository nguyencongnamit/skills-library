---
id: database-security
language: pt-BR
source_revision: "afe376a8"
version: "1.0.0"
title: "Segurança de banco de dados"
description: "Prevenir SQL injection, mau uso de ORM, vazamento de credenciais; exigir usuários de DB com privilégio mínimo e migrations seguras"
category: prevention
severity: critical
applies_to:
  - "ao gerar SQL ou strings de query raw"
  - "ao gerar código de modelos / queries de ORM"
  - "ao gerar arquivos de migration de banco de dados"
  - "ao configurar strings de conexão ou pooling"
languages: ["sql", "python", "javascript", "typescript", "go", "ruby", "java", "kotlin", "csharp"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2500
rules_path: "rules/"
related_skills: ["secret-detection", "api-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP SQL Injection Prevention Cheat Sheet"
  - "OWASP Database Security Cheat Sheet"
  - "CWE-89: Improper Neutralization of Special Elements in an SQL Command"
  - "CIS PostgreSQL / MySQL Benchmarks"
---

# Segurança de banco de dados

## Regras (para agentes de IA)

### SEMPRE
- Use queries parametrizadas / prepared statements para qualquer SQL
  que toque valores controlados pelo usuário. Passe valores como
  parâmetros, nunca por concatenação ou formatação de string (`%s`,
  `+`, template literals).
- Use a API segura de query do ORM. Em SQLAlchemy:
  `session.execute(text(":id"), {"id": user_id})`. Em Django: métodos
  do ORM, `Model.objects.filter(...)`. Em Sequelize / Prisma /
  SQLAlchemy core: builders `.where({ ... })`. Em Go:
  `db.QueryContext(ctx, "select ... where id = $1", id)`.
- Valide que nomes de colunas / tabelas identificadores — que não
  podem ser parametrizados — venham de uma allowlist hardcoded, não
  de input do usuário.
- Use um usuário de banco dedicado por aplicação com os grants
  mínimos necessários. Apps web que só leem não devem ter
  `INSERT`/`UPDATE`/`DELETE`. Jobs de migration rodam como usuário
  separado com permissão de `DDL`.
- Habilite Row-Level Security (Postgres `CREATE POLICY` / Supabase
  RLS / Azure SQL RLS) para tabelas multi-tenant e ajuste o contexto
  do tenant por sessão.
- Puxe credenciais de DB de um secret manager ou variável de ambiente
  injetada no start — nunca de um `database.yml` / `.env`
  versionado. Faça rotação periódica.
- Use TLS até o banco de dados (`sslmode=require` para Postgres,
  `requireSSL=true` para MySQL, conexão criptografada para MSSQL).
  Faça pinning da CA onde o driver suportar.
- Connection pooling tem um tamanho máximo que cabe dentro do
  `max_connections` do DB, com back-pressure saudável na aplicação.

### NUNCA
- Concatene input do usuário em SQL: `"SELECT * FROM users WHERE
  name='" + name + "'"`. Mesmo se você "escapar" na mão — drivers
  escapam corretamente apenas quando você binda pela API de
  parâmetros.
- Use métodos raw do ORM (`.raw()`, `.objects.raw()`,
  `.query(text(...))`) com interpolação f-string de input do
  usuário.
- Rode workloads da aplicação como superusuário do banco / `root` /
  `postgres` / `sa`. Crie um usuário de serviço.
- Desabilite TLS para o banco (`sslmode=disable`, `useSSL=false`).
- Armazene segredos, PII ou blobs grandes em colunas JSON sem
  criptografia em repouso e plano de rotação de chaves.
- Rode migrations destrutivas (DROP TABLE, DROP COLUMN, ALTER COLUMN
  mudando tipo em tabelas populadas) inline com deploys sem plano
  expand–contract e backup com restore verificado.
- Bind a um listener de banco exposto à internet sem allowlist;
  bancos ficam em rede privada e são acessados via bastion / VPN /
  private link.
- Logue statements SQL inteiros com valores bindados em nível INFO —
  valores bindados são quase sempre sensíveis.

### FALSOS POSITIVOS CONHECIDOS
- Ferramentas de reporting que rodam SQL ad-hoc escrito por analistas
  legitimamente interpolam identificadores; devem rodar contra uma
  réplica read-only com usuário separado cujos grants impeçam dano.
- Alguns ORMs (Django, SQLAlchemy 1.x) usam placeholders `%s` como
  *marcadores de parâmetro*, não como placeholders de format-string
  do Python — isso é seguro.
- Queries de health-check (`SELECT 1`) são intencionalmente triviais.

## Contexto (para humanos)

SQL injection está em #1 ou #2 em todo OWASP Top 10 há quinze anos e
não saiu de lá porque o modo de falha é *fácil por padrão*: qualquer
linguagem com concatenação de string permite produzir uma query.
Assistentes de IA geram alegremente código "funciona-em-dev" que
interpola input do usuário — particularmente para colunas de
ordenação, filtros dinâmicos e paginação.

Esta skill combina naturalmente com `api-security` (que guarda a
rota) e `secret-detection` (que guarda a string de conexão).

## Referências

- `rules/sql_injection_sinks.json`
- `rules/orm_safe_patterns.json`
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — SQL Injection.
- [PostgreSQL Row-Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).
