---
id: cors-security
language: pt-BR
source_revision: "afe376a8"
version: "1.0.0"
title: "Segurança CORS"
description: "Configuração CORS estrita: nada de wildcard com credentials, origens em allowlist, cache de preflight razoável, headers expostos mínimos"
category: prevention
severity: high
applies_to:
  - "ao gerar middleware CORS ou configuração do framework"
  - "ao conectar headers CORS no API Gateway / CloudFront / Nginx"
  - "ao revisar um endpoint cross-origin exposto ao navegador"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1000
  full: 2000
rules_path: "rules/"
related_skills: ["frontend-security", "api-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP HTML5 Security Cheat Sheet — CORS"
  - "CWE-942 — Permissive Cross-domain Policy with Untrusted Domains"
  - "Fetch Living Standard (CORS)"
---

# Segurança CORS

## Regras (para agentes de IA)

### SEMPRE
- Use uma **allowlist** de origens, não `*`. Reflita o header `Origin`
  recebido apenas quando casar com uma entrada conhecida da
  configuração (ou com uma regex pré-compilada de hostnames controlados
  pelo operador).
- Se as respostas incluem credentials (cookies, `Authorization`),
  ajuste `Access-Control-Allow-Credentials: true` **e** garanta que
  `Access-Control-Allow-Origin` seja uma única string de origem
  específica — nunca `*`.
- Inclua `Vary: Origin` em respostas cujo corpo depende do `Origin` da
  requisição, para que caches não sirvam a resposta de uma origem para
  outra.
- Restrinja o `Access-Control-Allow-Methods` do preflight aos métodos
  que o endpoint de fato aceita; restrinja `Access-Control-Allow-Headers`
  aos headers efetivamente consumidos.
- Defina `Access-Control-Max-Age` num valor razoável (≤ 86400 em
  produção) para amortizar a latência do preflight sem cristalizar uma
  allowlist ruim.
- Mantenha a allowlist em código (ou em arquivo de config versionado),
  não derivada de banco de dados — para que atacantes não consigam
  adicionar a própria origem inserindo uma linha.

### NUNCA
- Defina `Access-Control-Allow-Origin: *` junto com
  `Access-Control-Allow-Credentials: true`. A spec Fetch proíbe isso
  por uma razão — navegadores recusam a resposta, mas o problema maior
  é que um proxy / cache upstream pode já tê-la vazado.
- Reflita o header `Origin` sem checagem por allowlist
  (`Access-Control-Allow-Origin: <Origin>` para toda origem
  recebida). Equivale a `*` para credentials, com comportamento de
  cache pior.
- Aceite `null` como Origin. `null` é o que o Chrome envia de iframes
  em sandbox, URIs `data:` e `file://` — nenhum deles deveria ter
  acesso com credentials à sua API.
- Aceite subdomínios arbitrários com regex tipo `.*\.example\.com$`
  sem considerar subdomain takeover. Fixe subdomínios específicos;
  trate `*.example.com` como decisão deliberada acoplada a controles
  de propriedade dos subdomínios.
- Exponha headers internos via `Access-Control-Expose-Headers`.
  Restrinja ao mínimo que o frontend realmente precisa.
- Use CORS como autorização. CORS é uma política de *navegador*; não
  para server-to-server, curl ou clientes não-navegador. Autentique a
  requisição direito.

### FALSOS POSITIVOS CONHECIDOS
- APIs verdadeiramente públicas e não autenticadas (ex.: open data,
  endpoints de CDN de marketing) podem usar legitimamente
  `Access-Control-Allow-Origin: *` *sem* credentials.
- Ferramentas internas de admin restritas a uma rede privada podem
  usar uma única origem fixa; a preocupação com wildcard não se aplica
  porque não há chamadores cross-origin.
- Algumas integrações (Stripe.js, Plaid, Auth0) esperam headers CORS
  específicos — leia a seção CORS de cada provider antes de relaxar a
  baseline.

## Contexto (para humanos)

CORS é amplamente mal compreendido como um controle de segurança. Não
é — é um *relaxamento* da same-origin policy. O controle de segurança
é autenticação. Configuração incorreta de CORS importa porque, quando
combinada com cookies ou headers `Authorization`, dá a origens não
confiáveis a capacidade de fazer requisições cross-origin com
credentials e ler a resposta.

Esta skill é curta por design — a matriz de combinações ruins é finita
e as regras são duras.

## Referências

- `rules/cors_safe_config.json`
- [OWASP CORS Origin Header Scrutiny](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny).
- [CWE-942](https://cwe.mitre.org/data/definitions/942.html).
- [Fetch — CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol).
