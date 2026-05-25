---
id: ssrf-prevention
language: pt-BR
source_revision: "4c215e6f"
version: "1.0.0"
title: "Prevenção de SSRF"
description: "Defesa contra Server-Side Request Forgery: bloqueio de metadata cloud, filtragem de IPs internas, defesa contra DNS rebinding, fetching de URL baseado em allowlist"
category: prevention
severity: critical
applies_to:
  - "ao gerar código que faz fetch de uma URL fornecida pelo cliente"
  - "ao ligar webhooks, image proxies, PDF renderers, oEmbed fetchers"
  - "ao rodar em qualquer ambiente cloud com instance metadata service"
  - "ao revisar um wrapper de URL parsing ou de HTTP client"
languages: ["*"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "cors-security", "infrastructure-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP SSRF Prevention Cheat Sheet"
  - "CWE-918: Server-Side Request Forgery"
  - "Capital One 2019 breach post-mortem (IMDSv1 SSRF)"
  - "AWS IMDSv2 documentation"
  - "PortSwigger Web Security Academy — SSRF labs"
---

# Prevenção de SSRF

## Regras (para agentes de IA)

### SEMPRE
- Valide **toda** URL trazida em nome de um cliente por uma
  **allowlist** de hosts esperados. A allowlist é a única defesa
  durável — block-lists são contornáveis via tricks de encoding,
  IPv6 dual-stack e DNS rebinding.
- Resolva o hostname **uma vez**, valide o IP resolvido contra
  sua block-list de ranges privados / reservados / link-local,
  depois conecte naquele IP pinado usando SNI. Senão um atacante
  consegue fazer race entre a validação e o connect via DNS
  rebind (`time-of-check / time-of-use`).
- Bloqueie na camada de rede **e** na camada de aplicação. Cortar
  egress para `169.254.169.254`, `[fd00:ec2::254]`,
  `metadata.google.internal` e `100.100.100.200` em qualquer
  serviço que não precise legitimamente do metadata service.
- Force **IMDSv2** no AWS EC2 (session-token, hop-limit=1). O
  IMDSv1 — o pattern que o breach do Capital One em 2019 explorou
  — precisa estar desabilitado no nível da instância.
- Desabilite redirects HTTP por padrão em fetchers server-side
  (ou siga apenas um número pequeno e limitado, re-validando a
  nova URL contra a allowlist em cada hop). O bypass de SSRF
  mais comum é `https://allowed.example.com` retornando um 302
  para `http://169.254.169.254/...`.
- Use um HTTP client separado e restrito para URLs *controladas
  pelo usuário* vs URLs *internas*. Usar o client errado precisa
  falhar fechado (ex.: via distinção de tipo em Go / Rust /
  TypeScript).
- Parse URLs com um único parser bem conhecido (`net/url.Parse`
  do Go, `urllib.parse` do Python, `new URL()` do JavaScript).
  Parsers diferenciais entre WHATWG e RFC-3986 são uma classe
  documentada de bypass de SSRF.

### NUNCA
- Confie em um hostname / IP fornecido pelo usuário. Sempre
  resolva de novo no seu resolver confiável e cheque o endereço
  resolvido de novo.
- Conecte numa URL com base no hostname quando o protocolo
  permite redirects — `gopher://`, `dict://`, `file://`,
  `jar://`, `netdoc://`, `ldap://` são todos amplificadores
  comuns de SSRF. Restrinja a `http://` e `https://` (e
  `ftp://` só se realmente precisar).
- Confie em `0.0.0.0`, `127.0.0.1`, `[::]`, `[::1]`, `localhost`
  ou `*.localhost.test` — todos chegam na instância local. A
  lista também precisa incluir link-local `169.254.0.0/16`,
  IPv6 mapeado de IPv4 `::ffff:127.0.0.1` e IPv6 ULA `fc00::/7`.
- Use a string de URL do usuário em uma linha de log ou response
  de erro — pode ser o oráculo de reflexão de SSRF que
  transforma SSRF cego em SSRF de exfiltração de dados.
- Rode um sidecar / proxy de bloqueio de metadata como **única**
  defesa — um atacante que ache um pseudo-URL de
  Unix-domain-socket ou um hostname mal configurado consegue
  rotear em volta do proxy. A allowlist em nível de aplicação
  continua sendo necessária.
- Permita IDN / Punycode em URLs do usuário sem normalização —
  ataques de homógrafo IDN driblam checks ingênuos de string-
  allowlist (`gооgle.com` com o cirílico ≠ `google.com`).

### FALSOS POSITIVOS CONHECIDOS
- Integrações server-to-server onde os dois lados são
  controlados pelo operator e a URL é hardcoded na config (não
  fornecida pelo usuário) — a allowlist aqui é a própria config
  estática.
- Calls service-to-service locais do cluster Kubernetes — esses
  não passam por input do usuário, mas atenção a qualquer
  network policy cross-namespace.
- Webhooks de saída **para** o cliente (ex.: webhooks de Slack,
  Discord, Microsoft Teams). Valide que o host da URL está na
  allowlist documentada da integração, não arbitrária.

## Contexto (para humanos)

SSRF é hoje o vetor de acesso inicial de fato para breaches em
cloud. A cadeia é: uma URL fornecida pelo usuário → o server
faz fetch → o server tem credenciais implícitas (IAM via cloud
metadata, APIs internas de admin, endpoints RPC) → o atacante
rouba as credenciais. O breach do Capital One em 2019 (80M
registros de cliente) foi caso de manual de SSRF + exfiltração
via IMDSv1. As correções são simples e bem documentadas; os
patterns reaparecem porque fetching de URL é um cantinho
pequeno da maior parte dos codebases.

Esse skill enfatiza as classes DNS-rebinding e redirect-bypass
porque é aí que os validators de URL gerados por IA mais
falham — bloquear 169.254.169.254 de modo óbvio é fácil de
adicionar, mas o pattern allow-only-after-resolve-and-pin
exige mais raciocínio.

## Referências

- `rules/ssrf_sinks.json`
- `rules/cloud_metadata_endpoints.json`
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
- [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
- [Capital One 2019 breach DOJ filing](https://www.justice.gov/usao-wdwa/press-release/file/1188626/download).
- [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html).
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf).
