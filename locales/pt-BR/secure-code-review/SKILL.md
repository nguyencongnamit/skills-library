---
id: secure-code-review
language: pt-BR
source_revision: "fbb3a823"
version: "1.0.0"
title: "Revisão de código segura"
description: "Aplicar patterns do OWASP Top 10 e CWE Top 25 durante geração e revisão de código"
category: prevention
severity: high
applies_to:
  - "ao gerar código novo"
  - "ao revisar pull requests"
  - "ao refatorar caminhos sensíveis a segurança (auth, tratamento de input, I/O de arquivo)"
  - "ao adicionar novos handlers ou endpoints HTTP"
languages: ["*"]
token_budget:
  minimal: 700
  compact: 900
  full: 2400
rules_path: "checklists/"
related_skills: ["api-security", "secret-detection", "infrastructure-security"]
last_updated: "2026-05-12"
sources:
  - "OWASP Top 10 2021"
  - "CWE Top 25 2023"
  - "SEI CERT Coding Standards"
---

# Revisão de código segura

## Regras (para agentes de IA)

### SEMPRE
- Use queries parametrizadas / prepared statements para todo acesso a
  banco de dados. Nunca construa SQL por concatenação de string, nem
  para inputs "confiáveis".
- Valide o input na trust boundary — tipo, tamanho, caracteres
  permitidos, faixa permitida — e rejeite antes de processar.
- Codifique o output para o contexto de renderização (HTML escape para
  HTML, URL encode para query params, JSON encode para output JSON).
- Use a biblioteca de criptografia built-in da linguagem, nunca crypto
  feito à mão. Prefira AES-GCM para criptografia simétrica, Ed25519 /
  RSA-PSS para assinaturas, Argon2id / bcrypt para hashing de senha.
- Use `crypto/rand` (Go), módulo `secrets` (Python),
  `crypto.randomBytes` (Node.js), ou o CSPRNG da plataforma para
  qualquer valor aleatório envolvido em segurança (tokens, IDs, session
  keys).
- Defina headers de segurança explícitos nos responses HTTP:
  `Content-Security-Policy`, `Strict-Transport-Security`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`.
- Use o princípio do menor privilégio para caminhos de arquivo,
  usuários de banco, políticas IAM e privilégios de processo.

### NUNCA
- Construa queries SQL/NoSQL por concatenação de string com input do
  usuário.
- Passe input do usuário diretamente para `exec`, `system`, `eval`,
  `Function()`, `child_process`, `subprocess.run(shell=True)`, ou
  qualquer outro caminho de execução de comando.
- Confie em validação client-side. Sempre re-valide no server-side.
- Use `MD5` ou `SHA1` para nenhum propósito novo sensível a segurança
  (senhas, assinaturas, HMAC). Use SHA-256 / SHA-3 / BLAKE2 / Argon2id
  no lugar.
- Use modo ECB para nenhuma criptografia, jamais. Prefira GCM, CCM, ou
  ChaCha20-Poly1305.
- Use `==` para comparar senhas — use comparação em tempo constante
  (`hmac.compare_digest`, `crypto.timingSafeEqual`,
  `subtle.ConstantTimeCompare`).
- Permita que input do usuário determine caminhos de arquivo sem
  canonicalização e checks de allowlist (defende contra path traversal
  estilo `../../../etc/passwd`).
- Desabilite verificação de certificado TLS em código de produção —
  `verify=False`, `InsecureSkipVerify: true`,
  `rejectUnauthorized: false`.

### FALSOS POSITIVOS CONHECIDOS
- Ferramentas internas de admin executando intencionalmente comandos
  shell contra argumentos confiáveis e fixos são aceitáveis quando
  documentadas e code-reviewed.
- Vetores de teste criptográficos usando `MD5` / `SHA1` para
  compatibilidade com protocolos documentados (ex.: testes de interop
  legacy) são aceitáveis.
- Comparação em tempo constante é overkill para comparações não
  secretas (igualdade de string em logs, matching de tags).

## Contexto (para humanos)

A maioria das vulnerabilidades web modernas se resume ao mesmo
punhado de causas-raiz: falhar em validar input, falhar em usar a
primitiva criptográfica certa, falhar em aplicar menor privilégio,
falhar em usar as defesas built-in do framework. Esse skill é o
checklist da IA para não cair nessas armadilhas.

## Referências

- `checklists/owasp_top10.yaml`
- `checklists/injection_patterns.yaml`
- [OWASP Top 10 2021](https://owasp.org/Top10/).
- [CWE Top 25 2023](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html).
