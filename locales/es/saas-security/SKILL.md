---
id: saas-security
language: es
source_revision: "f231fd47"
version: "1.0.0"
title: "Seguridad de aplicaciones SaaS"
description: "Detectar tokens, misconfiguraciones y red flags de admin en las plataformas SaaS principales (GWS, Atlassian, Notion, HubSpot, Salesforce, BambooHR, Workday, Odoo, plataformas de chat, Zoom, Calendly, NetSuite)"
category: prevention
severity: critical
applies_to:
  - "al cablear una API key o token OAuth de SaaS en código"
  - "al revisar un connector / webhook / bridge SCIM de SaaS"
  - "al hacer triage de actividad sospechosa de admin de SaaS"
  - "al diseñar infraestructura que proxea tráfico SaaS"
  - "al responder una pregunta de seguridad relacionada con SaaS"
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

# Seguridad de aplicaciones SaaS

## Reglas (para agentes de IA)

### SIEMPRE
- Guardar API tokens de SaaS, OAuth secrets, webhook signing keys y
  archivos JSON de service-account en un **secrets manager** (Vault,
  AWS Secrets Manager, GCP Secret Manager, Doppler, 1Password Connect)
  — nunca inline, nunca `os.Setenv`-desde-source, nunca en variables
  de repo de CI (sólo `secrets.*`).
- Para integraciones SaaS **basadas en OAuth** (Google Workspace,
  Microsoft 365, Slack, Atlassian Cloud, HubSpot, Zoom, Notion, Lark,
  Calendly, NetSuite OAuth 2.0, Salesforce Connected Apps): persistir
  `refresh_token` cifrado-en-reposo, refrescar access tokens antes de
  que expiren, y guardar el client secret en una ruta solo-server
  (nunca en bundles de JS/mobile).
- Para **webhooks HMAC** (Slack `X-Slack-Signature`, Calendly V2
  `Calendly-Webhook-Signature`, HubSpot v3 `X-HubSpot-Signature-v3`,
  plataformas estilo Stripe, Zoom verification token, Teams outgoing
  webhook HMAC, Lark `X-Lark-Signature`, Notion verification token):
  validar la firma y la ventana de timestamp (default 5 min) en cada
  request entrante **antes** de parsear el body o confiar en
  cualquier campo.
- Pinear las base URLs de SaaS APIs a los hostnames de producción
  del vendor (`api.atlassian.com`, `api.hubapi.com`,
  `api.calendly.com`, `*.zoom.us`, `slack.com/api`,
  `graph.microsoft.com`, `api.bamboohr.com`, `wd*.myworkday.com`,
  `*.salesforce.com`/`*.force.com`, `api.notion.com`,
  `open.larksuite.com`/`open.feishu.cn`, `*.netsuite.com`). Rechazar
  respuestas de hostnames inesperados — esto atrapa intentos de
  DNS-takeover y proxy de account-takeover.
- Tratar endpoints **SCIM** y **directory-sync** como
  security-sensitive: requerir mutual TLS o JWT bearer firmado,
  rate-limit, y loggear cada write de usuario/grupo a un sink con
  evidencia de manipulación.
- Usar **scopes de mínimo privilegio** en cada app SaaS que crees.
  Salesforce Connected Apps: evitar `full`/`refresh_token` salvo que
  sea requerido. Slack bot tokens: listar sólo los scopes que llamás.
  Google Workspace OAuth: pedir
  `.../auth/admin.directory.user.readonly` en lugar de
  `admin.directory.user` si no escribís. HubSpot Private Apps:
  tildar sólo los scope checkboxes que efectivamente usás.
- Imponer **verificación en 2 pasos (2SV / MFA)** en cada consola
  de admin SaaS, **incluyendo** cuentas super-admin / org-owner /
  billing-owner. Atar SSO a tu IdP y deshabilitar el fallback de
  password para admins.
- Requerir **service accounts dedicadas, no compartidas** para
  integraciones SaaS sistema-a-sistema. Los nombres de service
  account deben codificar propósito (`jira-ingestion-sa`, no
  `api-user-3`). Deshabilitar el login interactivo en esas cuentas
  donde la plataforma lo permita.
- Específicamente para Google Workspace: rotar service-account keys
  con domain-wide delegation ≤ 90 días, preferir Workload Identity
  Federation donde esté soportado, y auditar las llamadas a
  `Admin SDK` en Admin Console > Reports.
- Específicamente para Atlassian (Jira/Confluence): preferir
  **OAuth 2.0 (3LO) / Atlassian Connect** con `actAsAccountId`; sólo
  caer a API tokens user-bound cuando hagas scripting de
  automatización personal. Rotar los API tokens por-usuario
  ≤ 90 días.
- Específicamente para NetSuite: preferir **OAuth 2.0** o **TBA
  (Token-Based Authentication)** con un integration record
  dedicado; nunca usar el flujo de login user/password para
  integraciones sistema.
- Para BambooHR / Workday / NetSuite (clase HRIS/ERP): tratar
  cada export bulk de empleados/PII como un **boundary de DLP** —
  loggear el request, el principal autenticado, el row count y el
  destino. Alertar sobre volumen inusual.

### NUNCA
- Hard-codear un API token de SaaS, OAuth client secret, webhook
  signing key, o service-account JSON en source, container images,
  binarios de mobile app, o JS client-side. Los formatos de token
  del vendor que este rule file detecta (por ej. `xoxb-`, `xapp-`,
  `jira_pat_`, `pat-na`, `ya29.`, `1//`, `sk_live_`) son
  masivamente scaneados por atacantes en GitHub público, npm, PyPI
  y Docker Hub a minutos de cada push.
- Deshabilitar la verificación de firma de webhook "para testing".
  Cada compromise público de Slack / HubSpot / Zoom / Calendly /
  Teams / Lark / Notion vía webhook spoofeado explotó una
  integración que llegó a prod con los checks de firma apagados.
- Emitir un scope OAuth **super admin** de Google Workspace
  (`https://www.googleapis.com/auth/admin`) a cualquier cosa que
  no sea una automatización IT-owned bien controlada. La mayoría
  de los casos de uso necesitan sólo el más angosto
  `admin.directory.*.readonly`.
- Compartir un único **personal API token** entre servicios para
  Jira, Confluence, BambooHR, Workday, NetSuite o Notion. Los
  tokens person-bound heredan los privilegios del humano y
  filtran por la laptop / cuenta SaaS de ese humano.
- Configurar una **URL de incoming webhook** de Slack / Teams /
  Lark / Google Chat que postee en un canal de confianza más alta
  que sus consumers. Si un CI bot puede postear en `#secops`, un
  compromise de CI = phishing directo a secops. Usar apps firmadas
  + permisos de posteo por-canal en su lugar.
- Dejar el **link sharing** de Google Drive / Notion / Confluence /
  Atlassian Cloud / SharePoint en "Anyone with the link" para
  documentos que contengan datos de cliente, secretos, o roadmaps
  no públicos. Que la sharing policy por default de la org sea
  **restricted-al-dominio**.
- Confiar en el campo **`From` / `email`** de un payload de
  webhook de Calendly / HubSpot / Zoom como identidad autoritativa.
  La firma prueba que el *vendor* mandó el payload; los campos del
  body siguen pudiendo ser attacker-supplied (invitee spoofeado,
  custom field puesto por el atacante). Buscar al usuario por ID
  canónico server-side.
- Forwardear **refresh tokens de OAuth** de SaaS entre entornos
  (dev↔staging↔prod) — cada entorno debe tener su propia
  connected app / OAuth client, sino las credenciales de prod
  viven dentro del blast-radius de dev.
- Confiar en código **Salesforce Apex / NetSuite SuiteScript /
  Workday Studio / Jira ScriptRunner** instalado por un tercero sin
  una security review. Estos corren con privilegios elevados y son
  vector recurrente de incidentes de SaaS supply-chain (por ej.,
  los patterns de Salesforce-via-AppExchange ATO documentados por
  Salesforce Security 2024).

### FALSOS POSITIVOS CONOCIDOS
- **Tokens de sandbox / ejemplo** provistos por el vendor en docs
  oficiales (por ej. Slack `xoxb-XXXXXXX-XXXXXXXX`, Stripe
  `sk_test_…`, Calendly `eyJ…example…`) — matchean los regexes
  pero contienen marcadores literales `EXAMPLE` / `XXX` / `test`
  en el contexto circundante.
- `ghp_…` / `gho_…` en docs SaaS de terceros explicando cómo
  cablear GitHub en ellos — esos son tokens de GitHub, no tokens
  de SaaS-platform, y están cubiertos por `secret-detection`.
- **Email público de service-account** de una app publicada de
  Google Marketplace (`*@gserviceaccount.com`) — el email es
  público; sólo la JSON key es sensible.
- **OAuth client IDs** para SPAs mobile / web públicas — están
  diseñados para ser públicos. El **client secret** correspondiente
  igual debe ser privado; alertar sólo sobre el secret.

## Contexto (para humanos)

SaaS es hoy el vector dominante de data-egress. El historial de
incidentes 2023-2025 (Snowflake / robo de OAuth tokens, Okta /
filtración de HAR file, replay de token de GitHub-a-Slack,
movimiento Salesforce-vía-Atlassian, phish de calendar/scheduling
vía links estilo Calendly) muestra tres modos de fallo
recurrentes:

1. **Token sprawl.** Los tokens person-bound y los refresh tokens
   de OAuth se acumulan a través de vendors. Cada uno es una
   credential. Centralizarlos; expirarlos por cadencia.
2. **Sharing misconfigurado.** Las plataformas SaaS hacen default
   a la conveniencia ("anyone with the link"). Los datos de
   clientes, pipelines de deals, docs de M&A y diagramas de IAM
   internos se filtran por esos defaults más seguido que por bugs
   de código.
3. **Blindspots de admin-action.** Los exports bulk, las
   concesiones masivas de permisos, las rotaciones de API-key y
   los spikes de SCIM user-write son diagnósticos de
   account-takeover o abuso interno — pero sólo si los estás
   observando.

Los rule files por-plataforma de este skill le dan a un revisor de
IA:

- **Formatos de token** — patrones regex para detectar secretos
  SaaS hard-codeados a tiempo de PR.
- **Misconfiguraciones** — settings concretos para asertar (o
  rechazar) al generar código de integración SaaS.
- **Red flags de admin** — formas de log query que un SIEM / SOAR /
  rule de detección ya debería estar mirando.

Los rule files son deliberadamente específicos a cada vendor para
que los agentes de IA no generen lógica de detección SaaS
"genérica" que se pierda ataques reales. También son lo
suficientemente chicos como para que la distribución compilada
`SECURITY-SKILLS.md` pueda llevarlos en la tier `full` sin
explotar el token budget.

## Referencias

- `rules/google_workspace.json` — GWS OAuth, service-account, Admin SDK
- `rules/google_chat.json` — Google Chat webhooks y bot tokens
- `rules/atlassian.json` — Jira & Confluence Cloud, OAuth 2.0 / API tokens
- `rules/notion.json` — Tokens de integración Notion, sharing de workspace
- `rules/hubspot.json` — HubSpot Private Apps, OAuth, webhook v3 HMAC
- `rules/salesforce.json` — Connected Apps, session tokens, Apex/Flow
- `rules/bamboohr.json` — BambooHR API key, SSO, export de empleados
- `rules/workday.json` — Workday ISU, OAuth, report-as-a-service
- `rules/odoo.json` — Odoo XML-RPC / JSON-RPC, master password
- `rules/microsoft_teams.json` — Creds de app + bot de Teams, HMAC de outgoing webhook
- `rules/slack.json` — Tokens bot/user/app/config de Slack, URLs de webhook
- `rules/larksuite.json` — Tokens de tenant access de Lark/Feishu, webhook
- `rules/zoom.json` — Zoom JWT (legacy), Server-to-Server OAuth, webhook
- `rules/calendly.json` — Calendly PAT, OAuth, firma de webhook V2
- `rules/netsuite.json` — NetSuite TBA, OAuth 2.0, red flags de SuiteScript
- CWE-798, CWE-284, CWE-1392
- OWASP API Security Top 10 (2023) — API2 (auth), API8 (security misconfig)
