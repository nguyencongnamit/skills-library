---
id: protocol-security
language: pt-BR
source_revision: "afe376a8"
version: "1.0.0"
title: "Segurança de protocolos"
description: "TLS 1.2+, mTLS, validação de certificado, HSTS, credenciais de canal gRPC, checks de Origin em WebSocket"
category: hardening
severity: critical
applies_to:
  - "ao gerar clientes e servidores HTTP / gRPC / WebSocket / SMTP / de banco de dados"
  - "ao gerar configuração TLS em código ou config de plataforma"
  - "ao gerar auth serviço-a-serviço"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2400
rules_path: "rules/"
related_skills: ["crypto-misuse", "frontend-security", "api-security"]
last_updated: "2026-05-13"
sources:
  - "NIST SP 800-52 Rev. 2 (TLS Guidelines)"
  - "RFC 8446 — TLS 1.3"
  - "RFC 6797 — HSTS"
  - "OWASP Transport Layer Security Cheat Sheet"
  - "CWE-295, CWE-326, CWE-319, CWE-757"
---

# Segurança de protocolos

## Regras (para agentes de IA)

### SEMPRE
- Padrão **TLS 1.3** para novos clientes e servidores; permita TLS
  1.2 só para interop com peers legados. Desabilite TLS 1.0/1.1,
  SSLv2/v3.
- Valide o certificado do servidor: cadeia até uma CA confiável,
  nome bate com o hostname esperado (ou SAN), não expirado, não
  revogado (OCSP stapling habilitado).
- Habilite HSTS nas respostas HTTP para tudo que for servido sobre
  HTTPS: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.
  Adicione o host à HSTS preload list quando estiver estável.
- Use **mutual TLS** (mTLS) para tráfego serviço-a-serviço dentro
  de um trust domain (mesh: Istio / Linkerd; standalone: SPIFFE /
  SPIRE para identidade).
- Para clientes/servidores gRPC, use `grpc.secure_channel` /
  `grpc.SslCredentials` / `credentials.NewTLS` — nunca
  `insecure_channel` em produção.
- Para servidores WebSocket, valide o header `Origin` contra uma
  allowlist e autentique o handshake (cookies + token CSRF, ou um
  bearer em query-string usado só no upgrade e re-validado).
- Para tokens serviço-a-serviço, prefira **SPIFFE IDs**
  (`spiffe://trust-domain/...`) com certs de workload de curta
  duração em vez de API keys de longa duração.
- Pinne o certificado (pinning de public key) para clientes
  mobile / desktop de alto risco que falam com o backend do
  operador.

### NUNCA
- Desabilite a verificação de certificado (`InsecureSkipVerify: true`,
  `verify=False`, `rejectUnauthorized: false`,
  `CURLOPT_SSL_VERIFYPEER=0`). O único uso aceitável é em um teste
  unitário que roda contra um cert efêmero de localhost.
- Implemente um `X509TrustManager` / `HostnameVerifier` /
  `URLSessionDelegate` / `ServerCertificateValidationCallback`
  customizado que retorne "trusted" incondicionalmente.
- Misture recursos HTTP e HTTPS na mesma página (mixed content) —
  navegadores modernos vão bloquear sub-recursos, mas APIs ainda
  ficam vulneráveis a downgrade MITM.
- Envie tokens / senhas sobre HTTP plano — nem mesmo em localhost
  em dev, a não ser que o ambiente de dev esteja documentado como
  não relevante para segurança.
- Use `grpc.insecure_channel(...)` em código de produção.
- Confie no header `Host` / `X-Forwarded-Host` / `Forwarded` sem
  uma allowlist; URLs absolutas construídas a partir de `Host`
  habilitam host-header injection e password-reset poisoning.
- Encaminhe headers `Authorization` / `Cookie` recebidos cegamente
  entre origins no seu service mesh — re-derive identidade a
  partir de mTLS ou de um service token.
- Habilite TLS renegotiation em clientes que você controla; pinne
  para `tls.NoRenegotiation` onde estiver disponível.

### FALSOS POSITIVOS CONHECIDOS
- Servidores de dev só em localhost com certs self-signed e
  documentação explícita estão OK; testes de CI contra certs
  efêmeros assinados por CA estão OK.
- Um pequeno número de integrações enterprise legadas exige TLS
  1.2 com um cipher específico; documente a exceção e isole a
  integração atrás de um proxy.
- Endpoints públicos só-leitura (ex.: status pages) podem ser
  legitimamente servidos sobre HTTP por questão de cacheabilidade,
  embora HTTPS continue preferível.

## Contexto (para humanos)

NIST SP 800-52 Rev. 2 é a referência autoritativa de TLS do governo
dos EUA; RFC 8446 é o próprio TLS 1.3. O modo de falha recorrente em
code review é **`InsecureSkipVerify`** (ou seus equivalentes em
cada linguagem) — geralmente introduzido "pra fazer os testes
passarem" e nunca revertido.

Este skill combina naturalmente com `crypto-misuse` (escolha de
algoritmo) e `auth-security` (emissão de token).

## Referências

- `rules/tls_defaults.json`
- `rules/cert_validation_sinks.json`
- [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final).
- [RFC 8446 — TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446).
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html).
- [CWE-295](https://cwe.mitre.org/data/definitions/295.html) — Improper Certificate Validation.
