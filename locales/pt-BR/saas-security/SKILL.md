---
id: saas-security
language: pt-BR
source_revision: "f231fd47"
version: "1.0.0"
title: "Segurança de aplicações SaaS"
description: "Detectar tokens, misconfigurações e red flags de admin nas principais plataformas SaaS (GWS, Atlassian, Notion, HubSpot, Salesforce, BambooHR, Workday, Odoo, plataformas de chat, Zoom, Calendly, NetSuite)"
category: prevention
severity: critical
applies_to:
  - "ao plugar uma API key ou token OAuth de SaaS no código"
  - "ao revisar um connector / webhook / bridge SCIM de SaaS"
  - "ao fazer triagem de atividade suspeita de admin SaaS"
  - "ao escrever infra que faz proxy de tráfego SaaS"
  - "ao responder a uma pergunta de segurança relacionada a SaaS"
languages: ["*"]
token_budget:
  minimal: 1800
  compact: 2500
  full: 3000
rules_path: "rules/"
related_skills: ["secret-detection", "iam-best-practices", "auth-security", "supply-chain-security"]
last_updated: "2026-05-14"
sources:
  - "Google Workspace Admin SDK security guidance"
  - "Atlassian Cloud Security Best Practices"
  - "Salesforce Security Implementation Guide"
  - "HubSpot Private App authentication docs"
  - "Slack OAuth & token type reference"
  - "Microsoft Teams app permission model"
  - "Zoom App Marketplace security review"
  - "BambooHR API & Single Sign-On hardening"
  - "Workday Integration System Security framework"
  - "NetSuite Token-Based Authentication (TBA) guide"
  - "Notion API integration token model"
  - "Lark/Feishu Open Platform security guidelines"
  - "Calendly Webhook V2 signature spec"
  - "CWE-798: Use of Hard-coded Credentials"
  - "CWE-284: Improper Access Control"
  - "CWE-1392: Use of Default Credentials"
---

# Segurança de aplicações SaaS

## Regras (para agentes de IA)

### SEMPRE
- Guarde API tokens de SaaS, OAuth secrets, webhook signing keys e
  arquivos JSON de service-account em um **secrets manager** (Vault,
  AWS Secrets Manager, GCP Secret Manager, Doppler, 1Password
  Connect) — nunca inline, nunca `os.Setenv`-de-source, nunca em
  variáveis de repo de CI (só `secrets.*`).
- Para integrações SaaS **baseadas em OAuth** (Google Workspace,
  Microsoft 365, Slack, Atlassian Cloud, HubSpot, Zoom, Notion,
  Lark, Calendly, NetSuite OAuth 2.0, Salesforce Connected Apps):
  persista `refresh_token` criptografado-em-repouso, faça refresh
  dos access tokens antes da expiração, e guarde o client secret
  num caminho server-only (nunca em bundles JS/mobile).
- Para **callbacks de webhook HMAC** (Slack `X-Slack-Signature`,
  Calendly V2 `Calendly-Webhook-Signature`, HubSpot v3
  `X-HubSpot-Signature-v3`, plataformas estilo Stripe, Zoom
  verification token, Teams outgoing webhook HMAC, Lark
  `X-Lark-Signature`, Notion verification token): valide a
  assinatura e a janela de timestamp (default 5 min) em cada
  request recebido **antes** de parsear o body ou confiar em
  qualquer campo.
- Pinne as base URLs das APIs SaaS nos hostnames de produção do
  vendor (`api.atlassian.com`, `api.hubapi.com`,
  `api.calendly.com`, `*.zoom.us`, `slack.com/api`,
  `graph.microsoft.com`, `api.bamboohr.com`, `wd*.myworkday.com`,
  `*.salesforce.com`/`*.force.com`, `api.notion.com`,
  `open.larksuite.com`/`open.feishu.cn`, `*.netsuite.com`). Rejeite
  respostas de hostnames inesperados — isso pega tentativas de
  DNS-takeover e proxy de account-takeover.
- Trate endpoints **SCIM** e **directory-sync** como
  security-sensitive: exija mutual TLS ou JWT bearer assinado,
  rate-limit, e logue cada write de usuário/grupo num sink à prova
  de adulteração.
- Use **scopes de menor privilégio** em cada app SaaS que você
  criar. Salesforce Connected Apps: evite `full`/`refresh_token` a
  menos que seja necessário. Slack bot tokens: liste só os scopes
  que você chama. Google Workspace OAuth: peça
  `.../auth/admin.directory.user.readonly` em vez de
  `admin.directory.user` se não escrever. HubSpot Private Apps:
  marque só os checkboxes de scope que você realmente chama.
- Imponha **verificação em 2 etapas (2SV / MFA)** em cada console
  de admin SaaS, **incluindo** contas super-admin / org-owner /
  billing-owner. Amarre SSO ao seu IdP e desabilite o fallback de
  password para admins.
- Exija **service accounts dedicadas, não compartilhadas** para
  integrações SaaS sistema-a-sistema. Os nomes de service account
  devem codificar propósito (`jira-ingestion-sa`, não
  `api-user-3`). Desabilite login interativo nessas contas onde a
  plataforma permitir.
- Especificamente para Google Workspace: faça rotação de keys de
  service-account com domain-wide delegation ≤ 90 dias, prefira
  Workload Identity Federation onde for suportado, e audite as
  chamadas a `Admin SDK` em Admin Console > Reports.
- Especificamente para Atlassian (Jira/Confluence): prefira
  **OAuth 2.0 (3LO) / Atlassian Connect** com `actAsAccountId`; só
  caia em API tokens user-bound quando estiver scriptando
  automação pessoal. Faça rotação dos API tokens por-usuário
  ≤ 90 dias.
- Especificamente para NetSuite: prefira **OAuth 2.0** ou **TBA
  (Token-Based Authentication)** com um integration record
  dedicado; nunca use o fluxo de login user/password para
  integrações de sistema.
- Para BambooHR / Workday / NetSuite (classe HRIS/ERP): trate
  cada export bulk de funcionários/PII como uma **fronteira de
  DLP** — logue o request, o principal autenticado, o número de
  linhas e o destino. Alerte sobre volume incomum.

### NUNCA
- Hardcode um API token SaaS, OAuth client secret, webhook signing
  key, ou service-account JSON em source, container images,
  binários de app mobile, ou JS client-side. Os formatos de token
  do vendor que este rule file detecta (ex.: `xoxb-`, `xapp-`,
  `jira_pat_`, `pat-na`, `ya29.`, `1//`, `sk_live_`) são scaneados
  em massa por atacantes em GitHub público, npm, PyPI e Docker Hub
  em poucos minutos depois do push.
- Desabilite a verificação de assinatura de webhook "pra testar".
  Cada compromisso público de Slack / HubSpot / Zoom / Calendly /
  Teams / Lark / Notion via webhook spoofado explorou uma
  integração que foi pra prod com checks de assinatura
  desligados.
- Emita um scope OAuth **super admin** do Google Workspace
  (`https://www.googleapis.com/auth/admin`) para qualquer coisa
  que não seja uma automação IT-owned bem controlada. A maioria
  dos casos de uso precisa apenas do mais estreito
  `admin.directory.*.readonly`.
- Compartilhe um único **API token pessoal** entre serviços para
  Jira, Confluence, BambooHR, Workday, NetSuite ou Notion. Tokens
  person-bound herdam os privilégios do humano e vazam pelo
  laptop / conta SaaS daquele humano.
- Configure uma **URL de incoming webhook** de Slack / Teams /
  Lark / Google Chat que poste num canal de confiança maior que
  seus consumidores. Se um CI bot consegue postar em `#secops`, um
  compromisso de CI = phishing direto de secops. Use apps
  assinadas + permissões de posting por-canal no lugar.
- Deixe o **link sharing** no Google Drive / Notion / Confluence /
  Atlassian Cloud / SharePoint em "Anyone with the link" para
  documentos contendo dados de cliente, segredos ou roadmaps não
  públicos. Coloque a sharing policy padrão da org como
  **domain-restricted**.
- Confie no campo **`From` / `email`** de um payload de webhook
  de Calendly / HubSpot / Zoom como identidade autoritativa. A
  assinatura prova que o *vendor* mandou o payload; os campos do
  body ainda podem ser attacker-supplied (invitee spoofado, custom
  field setado pelo atacante). Procure o usuário por ID canônico
  no server-side.
- Encaminhe **refresh tokens OAuth** SaaS entre ambientes
  (dev↔staging↔prod) — cada ambiente deve ter sua própria
  connected app / OAuth client, senão credenciais de prod vivem
  no blast-radius de dev.
- Confie em código **Salesforce Apex / NetSuite SuiteScript /
  Workday Studio / Jira ScriptRunner** instalado por terceiro sem
  security review. Eles rodam com privilégios elevados e são
  vetor recorrente de incidentes de SaaS supply-chain (ex.: os
  patterns de Salesforce-via-AppExchange ATO documentados pela
  Salesforce Security 2024).

### FALSOS POSITIVOS CONHECIDOS
- **Tokens sandbox / exemplo** fornecidos pelo vendor em docs
  oficiais (ex.: Slack `xoxb-XXXXXXX-XXXXXXXX`, Stripe
  `sk_test_…`, Calendly `eyJ…example…`) — batem com os regexes
  mas têm marcadores literais `EXAMPLE` / `XXX` / `test` no
  contexto ao redor.
- `ghp_…` / `gho_…` em docs SaaS de terceiros explicando como
  plugar GitHub neles — esses são tokens de GitHub, não tokens de
  SaaS-platform, e são cobertos por `secret-detection`.
- **Email público de service-account** de um app publicado no
  Google Marketplace (`*@gserviceaccount.com`) — o email é
  público; só a JSON key é sensível.
- **OAuth client IDs** para SPAs mobile / web públicas — eles são
  desenhados para ser públicos. O **client secret** correspondente
  ainda assim tem que ser privado; sinalize só sobre o secret.

## Contexto (para humanos)

SaaS é hoje o vetor dominante de data-egress. O histórico de
incidentes 2023-2025 (Snowflake / roubo de OAuth token, Okta /
vazamento de arquivo HAR, replay de token GitHub-para-Slack,
movimento Salesforce-via-Atlassian, phish de
calendar/scheduling via links estilo Calendly) mostra três
modos de falha recorrentes:

1. **Sprawl de tokens.** Tokens person-bound e refresh tokens
   OAuth se acumulam entre vendors. Cada um é uma credencial.
   Centralize-os; expire-os em cadência.
2. **Sharing mal configurado.** Plataformas SaaS fazem default
   para conveniência ("anyone with the link"). Dados de cliente,
   pipelines de deals, docs de M&A e diagramas internos de IAM
   vazam por esses defaults com mais frequência do que por bugs
   de código.
3. **Blindspots de admin-action.** Exports bulk, concessões
   massivas de permissão, rotações de API-key e picos de
   SCIM user-write são diagnósticos de account-takeover ou abuso
   insider — mas só se você estiver olhando.

Os rule files por-plataforma deste skill dão a um revisor de IA:

- **Formatos de token** — patterns regex para detectar segredos
  SaaS hardcoded no momento do PR.
- **Misconfigurações** — settings concretos para assertar (ou
  recusar) ao gerar código de integração SaaS.
- **Red flags de admin** — formas de log query que um SIEM /
  SOAR / detection rule já deveria estar procurando.

Os rule files são deliberadamente específicos para cada vendor
para que agentes de IA não gerem lógica de detecção SaaS
"genérica" que perde ataques reais. Também são pequenos o
bastante para que a distribuição compilada `SECURITY-SKILLS.md`
possa carregá-los na tier `full` sem estourar o token budget.

## Referências

- `rules/google_workspace.json` — GWS OAuth, service-account, Admin SDK
- `rules/google_chat.json` — webhooks e bot tokens do Google Chat
- `rules/atlassian.json` — Jira & Confluence Cloud, OAuth 2.0 / API tokens
- `rules/notion.json` — Tokens de integração Notion, sharing de workspace
- `rules/hubspot.json` — HubSpot Private Apps, OAuth, webhook v3 HMAC
- `rules/salesforce.json` — Connected Apps, session tokens, Apex/Flow
- `rules/bamboohr.json` — BambooHR API key, SSO, export de funcionários
- `rules/workday.json` — Workday ISU, OAuth, report-as-a-service
- `rules/odoo.json` — Odoo XML-RPC / JSON-RPC, master password
- `rules/microsoft_teams.json` — Creds de app + bot do Teams, HMAC de outgoing webhook
- `rules/slack.json` — Tokens bot/user/app/config do Slack, URLs de webhook
- `rules/larksuite.json` — Tokens de tenant access do Lark/Feishu, webhook
- `rules/zoom.json` — Zoom JWT (legacy), Server-to-Server OAuth, webhook
- `rules/calendly.json` — Calendly PAT, OAuth, assinatura de webhook V2
- `rules/netsuite.json` — NetSuite TBA, OAuth 2.0, red flags de SuiteScript
- CWE-798, CWE-284, CWE-1392
- OWASP API Security Top 10 (2023) — API2 (auth), API8 (security misconfig)
