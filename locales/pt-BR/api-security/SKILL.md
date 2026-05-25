---
id: api-security
language: pt-BR
source_revision: "fbb3a823"
version: "1.0.0"
title: "Segurança de API"
description: "Aplicar os padrões do OWASP API Top 10 a autenticação, autorização e validação de entrada"
category: prevention
severity: high
applies_to:
  - "ao gerar handlers HTTP"
  - "ao gerar resolvers GraphQL"
  - "ao gerar métodos de serviço gRPC"
  - "ao revisar alterações em endpoints de API"
languages: ["*"]
token_budget:
  minimal: 500
  compact: 750
  full: 2300
rules_path: "checklists/"
related_skills: ["secure-code-review", "secret-detection"]
last_updated: "2026-05-12"
sources:
  - "OWASP API Security Top 10 2023"
  - "OWASP Authentication Cheat Sheet"
  - "OAuth 2.0 Security Best Current Practice (RFC 9700)"
---

# Segurança de API

## Regras (para agentes de IA)

### SEMPRE
- Exigir autenticação em todo endpoint não público. Por padrão, autenticado; as
  rotas genuinamente públicas são marcadas explicitamente.
- Aplicar autorização no nível do objeto — confirmar que o sujeito autenticado
  realmente tem acesso ao ID do recurso solicitado, não apenas que está logado
  (isso neutraliza a classe OWASP API1 BOLA / IDOR).
- Validar todas as entradas da requisição contra um schema explícito (JSON
  Schema, Pydantic, Zod, struct tags do validator/v10). Rejeitar cedo; nunca
  propagar entrada não confiável para camadas internas.
- Aplicar limites de taxa no nível da rota para endpoints de autenticação,
  reset de senha e qualquer operação cara.
- Usar access tokens de curta duração (≤ 1 hora) com refresh tokens, não bearer
  tokens de longa duração.
- Devolver mensagens de erro genéricas externamente (`invalid credentials`) e
  registrar os detalhes internamente — evitar vazar qual dos dois (usuário ou
  senha) estava errado.
- Incluir `Cache-Control: no-store` em respostas com dados pessoais ou
  sensíveis.

### NUNCA
- Usar IDs inteiros sequenciais em URLs para recursos acessíveis entre
  inquilinos. Use UUIDs ou IDs opacos não adivinháveis.
- Confiar em cabeçalhos `Authorization` sem verificar assinatura e expiração.
- Aceitar JWTs com algoritmo `none`. Fixe o algoritmo esperado no momento da
  verificação.
- Fazer mass-assignment do corpo da requisição direto para modelos ORM
  (`User(**request.json)`) — isso habilita escalada de privilégios quando o
  modelo possui campos admin que o usuário não deveria controlar.
- Desabilitar proteção CSRF em endpoints que alteram estado e são usados por
  navegadores.
- Devolver stack traces ou páginas de erro do framework ao cliente em produção.
- Usar `HTTP GET` para qualquer operação que altere estado — GET deve ser
  seguro e idempotente.

### FALSOS POSITIVOS CONHECIDOS
- Endpoints de sites de marketing públicos servindo tráfego anônimo
  legitimamente não têm autenticação nem rate limit além do load balancer.
- IDs sequenciais em paths são aceitáveis para recursos genuinamente públicos
  não vinculados a inquilinos (ex.: slugs de posts de blog, catálogo público
  de produtos).
- Endpoints de health check (`/healthz`, `/ready`) ignoram autenticação de
  forma intencional.

## Contexto (para humanos)

O OWASP API Top 10 difere do Top 10 web sobretudo porque APIs têm defaults
mais fracos: frequentemente pulam CSRF, expõem IDs de objetos diretamente e
tendem a confiar em estado do lado do cliente fornecido pelo desenvolvedor.
Esta skill codifica os erros mais comuns de alto impacto.

## Referências

- `checklists/auth_patterns.yaml`
- `checklists/input_validation.yaml`
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-introduction/).
- [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700).
