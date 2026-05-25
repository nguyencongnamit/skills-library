---
id: auth-security
language: pt-BR
source_revision: "afe376a8"
version: "1.0.0"
title: "Segurança de autenticação e autorização"
description: "JWT, OAuth 2.0 / OIDC, gerenciamento de sessão, CSRF, hashing de senha e exigência de MFA"
category: prevention
severity: critical
applies_to:
  - "ao gerar fluxos de login / signup / reset de senha"
  - "ao gerar emissão ou verificação de JWT"
  - "ao gerar código de cliente ou servidor OAuth 2.0 / OIDC"
  - "ao configurar cookies de sessão, tokens CSRF, MFA"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1300
  full: 2700
rules_path: "rules/"
related_skills: ["api-security", "crypto-misuse", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "OWASP Authentication Cheat Sheet"
  - "OWASP Session Management Cheat Sheet"
  - "RFC 6749 — OAuth 2.0"
  - "RFC 7519 — JSON Web Token"
  - "RFC 9700 — OAuth 2.0 Security BCP"
  - "NIST SP 800-63B (Authenticator Assurance)"
---

# Segurança de autenticação e autorização

## Regras (para agentes de IA)

### SEMPRE
- Para verificação de JWT, fixe o algoritmo esperado (`RS256`, `EdDSA` ou
  `ES256`) e verifique `iss`, `aud`, `exp`, `nbf` e `iat`. Rejeite
  `alg=none` e qualquer algoritmo inesperado.
- Para clientes públicos OAuth 2.0 (SPA / mobile / CLI), use o **fluxo
  authorization code com PKCE** (S256). Nunca o implicit flow. Nunca o
  resource owner password credentials grant.
- Cookies de sessão: `Secure; HttpOnly; SameSite=Lax` (ou `Strict` para
  fluxos sensíveis). Use o prefixo `__Host-` quando não houver
  compartilhamento de subdomínio.
- Rotacione o identificador de sessão no login e em mudança de privilégios.
  Atrele a sessão ao user agent apenas como sinal fraco — nunca como única
  verificação.
- Hash de senhas com argon2id (m=64 MiB, t=3, p=1) e um salt aleatório por
  usuário. Bcrypt cost ≥ 12 ou scrypt N≥2^17 são alternativas aceitáveis
  para sistemas legados. PBKDF2-SHA256 requer ≥ 600.000 iterações (mínimo
  OWASP 2023).
- Exija comprimento de senha ≥ 12 caracteres sem regras de composição;
  permita Unicode; verifique senhas candidatas contra uma lista de senhas
  vazadas (HIBP / API k-anonymity do pwned-passwords).
- Implemente lockout de conta *ou* rate limiting para tentativas de senha
  (NIST SP 800-63B §5.2.2: no máximo 100 falhas em 30 dias).
- Implemente proteção CSRF para requisições modificadoras de estado
  alcançáveis a partir de uma sessão de navegador: synchronizer token,
  double-submit cookie ou `SameSite=Strict` para endpoints de alto risco.
- Exija MFA / step-up para operações administrativas, mudanças de senha,
  mudanças de dispositivo MFA, mudanças de cobrança.
- Para OIDC, valide o `nonce` enviado contra o `nonce` do ID token; valide
  `at_hash` / `c_hash` quando presentes.

### NUNCA
- Use `Math.random()` (ou qualquer RNG que não seja CSPRNG) para gerar IDs
  de sessão, tokens de reset, códigos de recuperação MFA ou chaves de API.
- Aceite JWT `alg=none`; ou aceite HS256 de um cliente quando o emissor
  assina com RS256 (ataque clássico de confusão de algoritmo).
- Compare senhas ou hashes de token com `==` / `strcmp`; use um comparador
  de tempo constante.
- Armazene senhas de forma reversível (cifradas em vez de hasheadas). O
  armazenamento precisa ser unidirecional.
- Vaze qual deles (usuário ou senha) estava errado. Devolva uma mensagem
  genérica "invalid credentials".
- Coloque access tokens, refresh tokens ou IDs de sessão em query strings
  de URL — eles vazam em logs, cabeçalhos Referer e histórico do navegador.
- Use `localStorage` / `sessionStorage` para guardar refresh tokens de
  longa duração. Use cookies HttpOnly.
- Confie em papéis / claims fornecidos pelo cliente na camada de API —
  re-derive o sujeito autenticado e consulte autorização do lado do
  servidor a cada requisição.
- Emita access tokens de longa duração (>1 hora); apoie-se em refresh
  tokens com rotação.
- Use o implicit flow ou o password grant.

### FALSOS POSITIVOS CONHECIDOS
- Tokens serviço-a-serviço com TTLs longos são por vezes aceitáveis quando
  armazenados em um secret manager e atrelados a uma identidade de
  workload específica.
- Auth "magic link" em desenvolvimento local sem hashing de senha para
  usuários efêmeros de dev está OK se estiver atrás de uma env flag e
  desativado em produção.
- Tokens em query de URL são toleráveis em *um* lugar — o retorno do
  authorization code do OAuth — porque o valor é de curta duração e uso
  único.

## Contexto (para humanos)

Falhas de autenticação aparecem consistentemente no OWASP Top 10
(A07:2021 — Identification and Authentication Failures). Os modos comuns
são: armazenamento fraco de senhas, tokens previsíveis, ausência de MFA,
má configuração de JWT e fixação de sessão. RFC 9700 (OAuth 2.0 Security
BCP) e NIST SP 800-63B são as referências autoritativas da receita.

Assistentes de IA tendem a entregar auth "funciona em dev": JWTs HS256
com segredos hardcoded, `bcrypt.hash` com cost padrão 10, sem PKCE,
tokens em localStorage. Esta skill pega cada um desses.

## Referências

- `rules/jwt_safe_config.json`
- `rules/oauth_flows.json`
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
- [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700).
