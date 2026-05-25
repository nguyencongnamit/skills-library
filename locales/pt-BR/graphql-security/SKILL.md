---
id: graphql-security
language: pt-BR
source_revision: "4c215e6f"
version: "1.0.0"
title: "Segurança de GraphQL"
description: "Defender APIs GraphQL: limites de profundidade/complexidade, introspection em produção, abuso de batching/aliasing, autorização em nível de campo, persisted queries"
category: prevention
severity: high
applies_to:
  - "ao gerar schemas, resolvers ou config de servidor GraphQL"
  - "ao configurar autenticação/autorização em um endpoint GraphQL"
  - "ao adicionar um gateway de API GraphQL público"
  - "ao revisar a exposição do endpoint /graphql"
languages: ["javascript", "typescript", "python", "go", "java", "kotlin", "csharp", "ruby"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "auth-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP GraphQL Cheat Sheet"
  - "CWE-400: Uncontrolled Resource Consumption"
  - "Apollo GraphQL Production Checklist"
  - "graphql-armor (Escape technologies)"
---

# Segurança de GraphQL

## Regras (para agentes de IA)

### SEMPRE
- Imponha uma **profundidade máxima** de query (típico: 7–10) e
  uma **complexidade** (custo) de query no servidor. Uma query
  aninhada em 5 níveis contra uma relação many-to-many pode
  retornar bilhões de nós; sem limite de custo, um único cliente
  derruba o banco.
- Desabilite **introspection** em produção. Introspection torna o
  reconhecimento trivial; clientes legítimos já têm o schema
  embutido via codegen ou um artefato `.graphql`.
- Use **persisted queries** (hashes de operação em allowlist) para
  qualquer API pública / de alto tráfego. GraphQL anônimo
  arbitrário é o equivalente GraphQL de `eval(req.body)`.
- Aplique **autorização em nível de campo** nos resolvers, não
  apenas no endpoint. GraphQL agrega muitos campos em uma só
  resposta HTTP — um único `@auth` faltando em um campo sensível
  vaza dados em toda a query.
- Limite o número de **aliases** por request (típico: 15) e o
  número de **operações por batch** (típico: 5). Apollo / Relay
  ambos permitem queries em batch — sem limites, isso é um
  primitivo de amplificação de N páginas da API.
- Rejeite definições de **fragmentos circulares** cedo (a maioria
  dos servidores rejeita, mas executors customizados não). Um
  fragmento auto-referenciante causa custo exponencial em
  parse-time.
- Retorne erros genéricos aos clientes (`INTERNAL_SERVER_ERROR`,
  `UNAUTHORIZED`) e roteie stack traces / trechos de SQL apenas
  para os logs do servidor. Os erros padrão do Apollo vazam
  internals do schema e da query.
- Configure um limite de tamanho de request (típico: 100 KiB) e um
  timeout de request (típico: 10 s) na camada HTTP na frente do
  servidor GraphQL. Uma query GraphQL de 1 MiB não tem uso
  legítimo.

### NUNCA
- Exponha introspection de `/graphql` em endpoint de produção. O
  playground GraphQL (GraphiQL, Apollo Sandbox) também deve estar
  desabilitado em builds de produção.
- Confie na profundidade / complexidade de uma query porque
  "nossos clientes só mandam queries bem-formadas". Qualquer
  atacante pode montar à mão um request para `/graphql`.
- Permita que diretivas `@skip(if: ...)` / `@include(if: ...)`
  controlem checagens de autorização. Diretivas rodam após a
  autorização na maioria dos executors, mas ordens customizadas de
  diretivas já produziram bypasses de authz.
- Implemente padrões N+1 em resolvers (uma query no banco por
  registro pai). Use DataLoader ou fetch baseado em join. N+1 é
  tanto bug de performance quanto amplificador de DoS.
- Permita uploads de arquivos via multipart GraphQL
  (`apollo-upload-server`, `graphql-upload`) sem limites de
  tamanho, validação de MIME e scan de vírus fora de banda. O
  CVE-2020-7754 de 2020 (`graphql-upload`) mostrou como um
  multipart malformado pode derrubar o servidor.
- Cacheie respostas GraphQL só por URL. POST `/graphql` sempre usa
  a mesma URL; o cache deve indexar por hash de operação +
  variáveis + claims de auth para evitar vazamentos entre tenants.
- Exponha mutations que aceitem objetos `input:` em JSON não
  confiável sem validação de schema. Tipos GraphQL são obrigatórios
  na camada do schema, mas os tipos `JSON` / `Scalar` os burlam
  por completo.

### FALSOS POSITIVOS CONHECIDOS
- Endpoints internos de admin GraphQL atrás de VPN autenticada
  podem legitimamente deixar introspection ligada por ergonomia de
  desenvolvimento.
- Persisted queries com allowlist estática tornam as checagens de
  profundidade / complexidade redundantes nessas operações —
  mantenha as checagens para qualquer operação que não esteja na
  allowlist (i.e., operações por uma flag `disabled`).
- APIs públicas, apenas leitura, podem usar limites de custo muito
  altos com caching agressivamente configurado na camada CDN; o
  trade-off é documentado por endpoint.

## Contexto (para humanos)

GraphQL dá aos clientes uma linguagem de query. Essa linguagem é
Turing-completa na prática — profundidade, aliasing, fragmentos e
unions combinam-se para formar computação quase arbitrária contra
o grafo de resolvers. Tratar `/graphql` como um único endpoint com
controles simples de WAF / rate-limit é inadequado.

A era 2022-2024 dos incidentes GraphQL (Hyatt, pesquisa Slack
vinda do Apollo, vários casos de account-takeover via batching)
giraram todos em torno ou de autorização ausente em nível de
campo, ou de análise de custo ausente. graphql-armor (Escape) e
as regras de validação embutidas no Apollo fornecem middleware
pronto para a maioria deles — usem.

## Referências

- `rules/graphql_safe_config.json`
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html).
- [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
- [Apollo Production Checklist](https://www.apollographql.com/docs/apollo-server/security/production-checklist/).
- [graphql-armor](https://escape.tech/graphql-armor/).
