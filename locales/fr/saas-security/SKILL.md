---
id: saas-security
language: fr
source_revision: "f231fd47"
version: "1.0.0"
title: "Sécurité des applications SaaS"
description: "Détecter tokens, misconfigurations et red flags d'admin des principales plateformes SaaS (GWS, Atlassian, Notion, HubSpot, Salesforce, BambooHR, Workday, Odoo, plateformes de chat, Zoom, Calendly, NetSuite)"
category: prevention
severity: critical
applies_to:
  - "lors du câblage d'une API key ou d'un token OAuth SaaS dans du code"
  - "lors de la review d'un connecteur / webhook / bridge SCIM SaaS"
  - "lors du triage d'activité admin SaaS suspecte"
  - "lors de l'écriture d'infra qui proxy le trafic SaaS"
  - "lors de la réponse à une question de sécurité liée au SaaS"
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

# Sécurité des applications SaaS

## Règles (pour les agents IA)

### TOUJOURS
- Stocker les API tokens SaaS, OAuth secrets, webhook signing keys et
  fichiers JSON de service-account dans un **secrets manager** (Vault,
  AWS Secrets Manager, GCP Secret Manager, Doppler, 1Password
  Connect) — jamais inline, jamais `os.Setenv`-depuis-source, jamais
  dans des variables de repo CI (seulement `secrets.*`).
- Pour les intégrations SaaS **basées OAuth** (Google Workspace,
  Microsoft 365, Slack, Atlassian Cloud, HubSpot, Zoom, Notion, Lark,
  Calendly, NetSuite OAuth 2.0, Salesforce Connected Apps) :
  persister `refresh_token` chiffré-au-repos, refresh les access
  tokens avant expiration, et stocker le client secret dans un chemin
  server-only (jamais dans les bundles JS/mobile).
- Pour les **webhooks HMAC** (Slack `X-Slack-Signature`, Calendly V2
  `Calendly-Webhook-Signature`, HubSpot v3 `X-HubSpot-Signature-v3`,
  plateformes style Stripe, Zoom verification token, Teams outgoing
  webhook HMAC, Lark `X-Lark-Signature`, Notion verification token) :
  valider la signature et la fenêtre timestamp (défaut 5 min) sur
  chaque request entrante **avant** de parser le body ou de faire
  confiance à un champ.
- Pinner les base URLs des APIs SaaS sur les hostnames de production
  du vendor (`api.atlassian.com`, `api.hubapi.com`,
  `api.calendly.com`, `*.zoom.us`, `slack.com/api`,
  `graph.microsoft.com`, `api.bamboohr.com`, `wd*.myworkday.com`,
  `*.salesforce.com`/`*.force.com`, `api.notion.com`,
  `open.larksuite.com`/`open.feishu.cn`, `*.netsuite.com`). Rejeter
  les réponses des hostnames inattendus — ça attrape les tentatives
  de DNS-takeover et de proxy d'account-takeover.
- Traiter les endpoints **SCIM** et **directory-sync** comme
  security-sensitive : exiger mutual TLS ou JWT bearer signé,
  rate-limit, et logguer chaque write user/group dans un sink
  tamper-evident.
- Utiliser des **scopes de moindre privilège** sur chaque app SaaS
  que vous créez. Salesforce Connected Apps : éviter
  `full`/`refresh_token` sauf si requis. Slack bot tokens : ne
  lister que les scopes que vous appelez. Google Workspace OAuth :
  demander `.../auth/admin.directory.user.readonly` au lieu de
  `admin.directory.user` si vous n'écrivez pas. HubSpot Private
  Apps : ne cocher que les checkboxes de scope que vous appelez
  réellement.
- Appliquer la **vérification en 2 étapes (2SV / MFA)** sur chaque
  console admin SaaS, **y compris** les comptes super-admin /
  org-owner / billing-owner. Lier SSO à votre IdP et désactiver le
  fallback password pour les admins.
- Exiger des **service accounts dédiés, non partagés** pour les
  intégrations SaaS système-à-système. Les noms de service account
  doivent encoder le but (`jira-ingestion-sa`, pas `api-user-3`).
  Désactiver le login interactif sur ces comptes là où la plateforme
  le permet.
- Spécifiquement pour Google Workspace : rotater les clés
  service-account de domain-wide delegation ≤ 90 jours, préférer
  Workload Identity Federation là où c'est supporté, et auditer les
  appels `Admin SDK` dans Admin Console > Reports.
- Spécifiquement pour Atlassian (Jira/Confluence) : préférer
  **OAuth 2.0 (3LO) / Atlassian Connect** avec `actAsAccountId` ; ne
  retomber sur les API tokens user-bound que pour scripter de
  l'automatisation personnelle. Rotater les API tokens par-user
  ≤ 90 jours.
- Spécifiquement pour NetSuite : préférer **OAuth 2.0** ou **TBA
  (Token-Based Authentication)** avec un integration record dédié ;
  ne jamais utiliser le flux user/password login pour des
  intégrations système.
- Pour BambooHR / Workday / NetSuite (classe HRIS/ERP) : traiter
  chaque export bulk d'employés/PII comme une **frontière DLP** —
  logguer la requête, le principal authentifié, le nombre de lignes
  et la destination. Alerter sur un volume inhabituel.

### JAMAIS
- Hardcoder un API token SaaS, OAuth client secret, webhook signing
  key, ou service-account JSON dans la source, les images de
  container, les binaires d'app mobile, ou le JS client-side. Les
  formats de token vendor que ce fichier de règles détecte (ex.
  `xoxb-`, `xapp-`, `jira_pat_`, `pat-na`, `ya29.`, `1//`,
  `sk_live_`) sont scannés en masse par les attaquants sur GitHub
  public, npm, PyPI, et Docker Hub dans les minutes qui suivent un
  push.
- Désactiver la vérification de signature webhook "pour les tests".
  Chaque compromise public de Slack / HubSpot / Zoom / Calendly /
  Teams / Lark / Notion via webhook spoofé exploitait une
  intégration arrivée en prod avec les checks de signature désactivés.
- Émettre un scope OAuth **super admin** de Google Workspace
  (`https://www.googleapis.com/auth/admin`) à autre chose qu'une
  automation IT-owned étroitement contrôlée. La plupart des
  use-cases n'ont besoin que du plus étroit
  `admin.directory.*.readonly`.
- Partager un même **API token personnel** entre services pour Jira,
  Confluence, BambooHR, Workday, NetSuite, ou Notion. Les tokens
  person-bound héritent des privilèges de l'humain et fuitent par le
  laptop / compte SaaS de cet humain.
- Configurer une **URL d'incoming webhook** Slack / Teams / Lark /
  Google Chat qui poste dans un channel de confiance plus haute que
  ses consommateurs. Si un bot CI peut poster dans `#secops`, un
  compromise CI = phishing direct de secops. Utiliser des apps
  signées + des permissions de posting par-channel à la place.
- Laisser le **link sharing** sur Google Drive / Notion / Confluence
  / Atlassian Cloud / SharePoint à "Anyone with the link" pour des
  documents contenant des données client, des secrets, ou des
  roadmaps non publiques. Mettre la sharing policy de l'org par
  défaut sur **restreint-au-domaine**.
- Faire confiance au champ **`From` / `email`** d'un payload de
  webhook Calendly / HubSpot / Zoom comme identité faisant autorité.
  La signature prouve que le *vendor* a envoyé le payload ; les
  champs du body peuvent toujours être attacker-supplied (invitee
  spoofé, custom field mis par l'attaquant). Chercher l'utilisateur
  par ID canonique côté serveur.
- Faire transiter les **refresh tokens OAuth** SaaS entre
  environnements (dev↔staging↔prod) — chaque environnement doit
  avoir sa propre connected app / son propre OAuth client, sinon
  les credentials prod vivent dans le blast-radius de dev.
- Faire confiance à du code **Salesforce Apex / NetSuite SuiteScript
  / Workday Studio / Jira ScriptRunner** installé par un tiers sans
  security review. Ça tourne avec des privilèges élevés et c'est un
  vecteur récurrent d'incidents de supply-chain SaaS (ex. les
  patterns Salesforce-via-AppExchange ATO documentés par Salesforce
  Security 2024).

### FAUX POSITIFS CONNUS
- Les **tokens sandbox / example** fournis par le vendor dans les
  docs officielles (ex. Slack `xoxb-XXXXXXX-XXXXXXXX`, Stripe
  `sk_test_…`, Calendly `eyJ…example…`) — matchent les regex mais
  contiennent des marqueurs littéraux `EXAMPLE` / `XXX` / `test`
  dans le contexte alentour.
- `ghp_…` / `gho_…` dans des docs SaaS tierces expliquant comment
  brancher GitHub dedans — ce sont des tokens GitHub, pas des
  tokens de SaaS-platform, et c'est couvert par `secret-detection`.
- L'**email public de service-account** d'une app Google
  Marketplace publiée (`*@gserviceaccount.com`) — l'email est
  public ; seule la JSON key est sensible.
- Les **OAuth client IDs** pour les SPAs mobile / web publiques —
  ils sont conçus pour être publics. Le **client secret**
  correspondant doit quand même être privé ; ne signaler que sur le
  secret.

## Contexte (pour les humains)

SaaS est maintenant le vecteur dominant de data-egress.
L'historique d'incidents 2023-2025 (Snowflake / vol de tokens
OAuth, Okta / fuite de fichier HAR, replay de token GitHub-à-Slack,
mouvement Salesforce-via-Atlassian, phish calendar/scheduling via
des links style Calendly) montre trois modes d'échec récurrents :

1. **Sprawl de tokens.** Les tokens person-bound et les refresh
   tokens OAuth s'accumulent à travers les vendors. Chacun est une
   credential. Les centraliser ; les faire expirer en cadence.
2. **Sharing mal configuré.** Les plateformes SaaS défaultent à la
   commodité ("anyone with the link"). Les données client, les
   pipelines de deals, les docs M&A, et les schémas IAM internes
   fuitent par ces défauts plus souvent que par des bugs de code.
3. **Angles morts admin.** Les exports bulk, les concessions
   massives de permissions, les rotations d'API-key et les pics de
   SCIM user-write sont diagnostiques d'account-takeover ou d'abus
   insider — mais seulement si vous regardez.

Les fichiers de règles par-plateforme de ce skill donnent à un
reviewer IA :

- **Formats de token** — patterns regex pour détecter des secrets
  SaaS hardcodés au moment du PR.
- **Misconfigurations** — settings concrets à asserter (ou refuser)
  lors de la génération de code d'intégration SaaS.
- **Red flags admin** — formes de log query qu'un SIEM / SOAR /
  detection rule devrait déjà chercher.

Les fichiers de règles sont délibérément spécifiques à chaque
vendor pour que les agents IA ne génèrent pas de logique de
détection SaaS "générique" qui rate les vraies attaques. Ils sont
aussi assez petits pour que la distribution compilée
`SECURITY-SKILLS.md` puisse les emporter dans la tier `full` sans
faire péter le token budget.

## Références

- `rules/google_workspace.json` — GWS OAuth, service-account, Admin SDK
- `rules/google_chat.json` — webhooks et bot tokens Google Chat
- `rules/atlassian.json` — Jira & Confluence Cloud, OAuth 2.0 / API tokens
- `rules/notion.json` — Tokens d'intégration Notion, sharing de workspace
- `rules/hubspot.json` — HubSpot Private Apps, OAuth, webhook v3 HMAC
- `rules/salesforce.json` — Connected Apps, session tokens, Apex/Flow
- `rules/bamboohr.json` — BambooHR API key, SSO, export d'employés
- `rules/workday.json` — Workday ISU, OAuth, report-as-a-service
- `rules/odoo.json` — Odoo XML-RPC / JSON-RPC, master password
- `rules/microsoft_teams.json` — Creds d'app + bot Teams, HMAC d'outgoing webhook
- `rules/slack.json` — Tokens bot/user/app/config Slack, URLs de webhook
- `rules/larksuite.json` — Tokens de tenant access Lark/Feishu, webhook
- `rules/zoom.json` — Zoom JWT (legacy), Server-to-Server OAuth, webhook
- `rules/calendly.json` — Calendly PAT, OAuth, signature de webhook V2
- `rules/netsuite.json` — NetSuite TBA, OAuth 2.0, red flags SuiteScript
- CWE-798, CWE-284, CWE-1392
- OWASP API Security Top 10 (2023) — API2 (auth), API8 (security misconfig)
