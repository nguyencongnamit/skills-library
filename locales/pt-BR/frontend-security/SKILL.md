---
id: frontend-security
language: pt-BR
source_revision: "afe376a8"
version: "1.0.0"
title: "Segurança de frontend"
description: "Hardening no lado do navegador: XSS, CSP, CORS, SRI, DOM clobbering, sandboxing de iframe, Trusted Types"
category: prevention
severity: high
applies_to:
  - "ao gerar templates HTML / JSX / Vue / Svelte"
  - "ao configurar headers de resposta em uma web app"
  - "ao adicionar tags de script de terceiros ou recursos de CDN"
languages: ["html", "javascript", "typescript", "tsx", "jsx", "vue", "svelte"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2800
rules_path: "rules/"
related_skills: ["cors-security", "auth-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP XSS Prevention Cheat Sheet"
  - "OWASP Content Security Policy Cheat Sheet"
  - "CWE-79: Improper Neutralization of Input During Web Page Generation"
  - "MDN Trusted Types"
---

# Segurança de frontend

## Regras (para agentes de IA)

### SEMPRE
- Trate todos os dados de usuário/URL/storage como não confiáveis.
  Renderize via escape do framework (`{}` em JSX/Vue/Svelte,
  `{{ }}` em templating). Para HTML cru use um sanitizer auditado
  (DOMPurify) com allowlist estrita.
- Envie um header `Content-Security-Policy` estrito. Baseline
  mínima de produção: `default-src 'self'; script-src 'self'
  'nonce-<random>'; object-src 'none'; base-uri 'self';
  frame-ancestors 'none'; form-action 'self';
  upgrade-insecure-requests`. Use nonces ou hashes — nunca
  `'unsafe-inline'` em `script-src`.
- Defina `Strict-Transport-Security: max-age=63072000;
  includeSubDomains; preload`,
  `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer-when-downgrade` ou mais estrito, e
  `Permissions-Policy` para desligar features não usadas.
- Adicione `integrity="sha384-..." crossorigin="anonymous"` em
  cada `<script>` e `<link rel="stylesheet">` carregado de um CDN.
- Adicione `sandbox="allow-scripts allow-same-origin"` (apenas os
  atributos necessários) a cada `<iframe>`. Por padrão, sem flags
  de allow.
- Use cookies com `Secure; HttpOnly; SameSite=Lax` (ou `Strict`
  para fluxos sensíveis). Prefixo `__Host-` quando não há
  compartilhamento entre subdomínios.
- Habilite Trusted Types onde o navegador suportar
  (`Content-Security-Policy: require-trusted-types-for 'script'`)
  para que atribuições a sinks do DOM (`innerHTML`,
  `setAttribute('src', ...)` para scripts) precisem passar por uma
  policy tipada.

### NUNCA
- Use `dangerouslySetInnerHTML`, `v-html`, `{@html ...}`,
  `innerHTML =` ou `document.write` com input não confiável.
- Use `eval`, `new Function`, `setTimeout(string)`,
  `setInterval(string)` ou `Function('return x')`.
- Injete input de usuário em `href`, `src`, `formaction`, `action`
  ou qualquer atributo que carregue URL sem validar o esquema
  (bloqueie `javascript:`, `data:`, `vbscript:`).
- Use `target="_blank"` sem `rel="noopener noreferrer"` — vaza
  `window.opener`.
- Confie em nós do DOM apenas pelo id. DOM clobbering: um
  `<input name="config">` controlado pelo atacante sombreia
  `window.config`.
- Use `postMessage` sem checar `event.origin` contra uma allowlist.
- Armazene JWTs, refresh tokens ou PII em `localStorage` /
  `sessionStorage` — qualquer XSS os exfiltra. Prefira cookies
  HttpOnly.
- Leia ou escreva `document.cookie` em JavaScript para cookies de
  auth — eles deveriam ser HttpOnly de qualquer jeito.

### FALSOS POSITIVOS CONHECIDOS
- Ferramentas internas de admin que deliberadamente renderizam
  Markdown / texto rico de autores confiáveis podem usar
  `dangerouslySetInnerHTML` após um passe de sanitizer; documente a
  chamada do sanitizer inline.
- Extensões de navegador às vezes precisam de `'unsafe-eval'` no
  CSP da extensão; o CSP da web app voltada ao usuário deve mesmo
  assim proibi-lo.
- Conexões WebSocket para endpoints não-same-origin estão ok quando
  o servidor valida o origin.

## Contexto (para humanos)

O OWASP XSS Prevention Cheat Sheet continua sendo a referência
autorizada para as regras de escape; CSP é a camada de defesa em
profundidade que transforma um escape esquecido em relatório logado
em vez de uma sessão roubada. Trusted Types é o padrão mais novo,
forçado pelo navegador, que move a pergunta "isso passou por um
sanitizer?" do audit em runtime para o sistema de tipos.

Frontends gerados por IA tendem a ir para `innerHTML` e
`dangerouslySetInnerHTML` porque são mais curtos; este skill é o
contrapeso.

## Referências

- `rules/csp_defaults.json`
- `rules/xss_sinks.json`
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html).
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Cross-site scripting.
- [Trusted Types (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API).
