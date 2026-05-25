---
id: secret-detection
language: pt-BR
source_revision: "9808b0fa"
version: "1.4.0"
title: "Detecção de segredos"
description: "Detectar e prevenir segredos hardcoded, API keys, tokens e credenciais no código"
category: prevention
severity: critical
applies_to:
  - "antes de cada commit"
  - "ao revisar código que lida com credenciais"
  - "ao escrever arquivos de configuração"
  - "ao criar templates de .env ou config"
languages: ["*"]
token_budget:
  minimal: 800
  compact: 1300
  full: 2000
rules_path: "rules/"
tests_path: "tests/"
related_skills: ["dependency-audit", "supply-chain-security"]
last_updated: "2026-05-14"
sources:
  - "OWASP Secrets Management Cheat Sheet"
  - "CWE-798: Use of Hard-coded Credentials"
  - "CWE-259: Use of Hard-coded Password"
  - "NIST SP 800-57 Part 1 Rev. 5: Key Management"
---

# Detecção de segredos

## Regras (para agentes de IA)

### SEMPRE
- Confira todos os string literals com mais de 20 caracteres perto de
  keywords: `api_key`, `secret`, `token`, `password`, `credential`,
  `auth`, `bearer`, `private_key`, `access_key`, `client_secret`,
  `refresh_token`.
- Sinalize qualquer string que bate com patterns conhecidos de
  segredo. O pattern set incluído cobre AWS (`AKIA...`), GitHub
  clássico (`ghp_`, `gho_`) **e fine-grained** (`github_pat_`) PATs,
  OpenAI (`sk-`), **Anthropic (`sk-ant-api03-`)**, Slack
  (`xox[baprs]-`), Stripe (`sk_live_`), Google (`AIza...`),
  **client secrets do Azure AD**, **Databricks (`dapi`)**, **Datadog
  32-hex com hotword**, **Twilio (`SK`)**, **SendGrid (`SG.`)**,
  **npm (`npm_`)**, **upload de PyPI (`pypi-AgEI`)**, **Heroku UUID
  com hotword**, **DigitalOcean (`dop_v1_`)**, **HashiCorp Vault
  (`hvs.`)**, **Supabase (`sbp_`)**, **Linear (`lin_api_`)**, JWT, e
  PEM private keys.
- Verifique que o `.gitignore` inclui: `*.pem`, `*.key`, `.env`,
  `.env.*`, `*credentials*`, `*secret*`, `id_rsa*`, `*.ppk`.
- Prefira o uso de variáveis de ambiente (`os.environ`,
  `process.env`, `os.Getenv`) em vez de valores hardcoded para
  qualquer credencial, connection string ou API endpoint que tenha
  um segredo associado.
- Sugira um secrets manager (1Password, AWS Secrets Manager,
  HashiCorp Vault, Doppler) quando as credenciais precisam ser
  compartilhadas entre máquinas ou serviços.

### NUNCA
- Não commite arquivos que batem com: `*.pem`, `*.key`, `*.p12`,
  `*.pfx`, `.env`, `.env.local`, `*credentials*`, `id_rsa`,
  `id_dsa`, `id_ecdsa`, `id_ed25519`.
- Não hardcode API keys, tokens, senhas ou connection strings no
  código-fonte.
- Não use segredos reais em fixtures de teste — use placeholders
  documentados como `AKIAIOSFODNN7EXAMPLE`,
  `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` ou
  `xoxb-EXAMPLE-EXAMPLE`.
- Não logue nem dê print em valores de segredo, mesmo em modo
  debug.
- Não dê eco de segredos para terminais em logs de CI (mascare via
  `::add-mask::` no GitHub Actions).
- Não embuta signing keys em imagens de container, nem mesmo em
  imagens base.

### FALSOS POSITIVOS CONHECIDOS
- Exemplo da documentação da AWS: `AKIAIOSFODNN7EXAMPLE` e a
  secret access key correspondente
  `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`.
- Strings que contêm: "example", "test", "placeholder", "dummy",
  "sample", "changeme", "your-key-here", "REPLACE_ME", "TODO",
  "FIXME", "XXX".
- Hash literals em CSS/SCSS (ex.: `#ff0000`, `#deadbeef`).
- Conteúdo não secreto codificado em base64 em testes (lorem ipsum
  codificado, fixtures de imagem).
- SHAs de git commit em changelogs e release notes.
- JWT tokens nos exemplos da documentação OAuth RFC (strings
  `eyJ...` que aparecem em comentários).

## Contexto (para humanos)

Segredos hardcoded continuam sendo uma das causas mais comuns de
breaches. Os relatórios anuais "State of the Octoverse" do GitHub
colocam consistentemente o vazamento de segredos entre as três
principais categorias de vulnerabilidades divulgadas, e o custo
médio de uma credencial vazada (remediação + rotação + impacto) é
medido em dezenas de milhares de dólares por incidente, mesmo
antes de envolver dados de cliente.

Assistentes de código com IA aceleram esse risco porque o caminho
de menor resistência é inlinear uma credencial que funciona e
"corrigir depois". Esse skill é o contrapeso: ele treina a IA a
recusar o caminho de menor resistência.

A estratégia de detecção em `rules/dlp_patterns.json` espelha o
pipeline em camadas, agora com **26 patterns distintos** abrangendo
plataformas de dev (GitHub fine-grained PATs, Anthropic, OpenAI,
Supabase, Linear), cloud (AWS, Azure AD, GCP, DigitalOcean,
Heroku), plataformas de dados (Databricks, Datadog, HashiCorp
Vault) e comunicação (Twilio, SendGrid, Slack). Cada pattern
carrega severidade, hotwords, janela de proximidade de hotword, e
um piso de entropia para dirigir a precisão.
documentado em [secure-edge ARCHITECTURE.md](https://github.com/kennguy3n/secure-edge/blob/main/ARCHITECTURE.md)
— scan de prefixo Aho-Corasick, validação de regex nos candidatos,
proximidade de hotword, thresholds de entropia e regras de exclusão
— adaptado para o contexto de análise estática.

## Referências

- `rules/dlp_patterns.json` — patterns legíveis por máquina com
  prefixos Aho-Corasick, hotwords, thresholds de entropia.
- `rules/dlp_exclusions.json` — supressões de falso positivo
  mantidas pela comunidade.
- `tests/corpus.json` — fixtures de teste para validação.
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html) — Uso de credenciais hardcoded.
- [CWE-259](https://cwe.mitre.org/data/definitions/259.html) — Uso de senha hardcoded.
