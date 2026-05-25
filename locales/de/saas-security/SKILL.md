---
id: saas-security
language: de
source_revision: "f231fd47"
version: "1.0.0"
title: "SaaS-Anwendungssicherheit"
description: "Tokens, Fehlkonfigurationen und Admin-Red-Flags der wichtigsten SaaS-Plattformen erkennen (GWS, Atlassian, Notion, HubSpot, Salesforce, BambooHR, Workday, Odoo, Chat-Plattformen, Zoom, Calendly, NetSuite)"
category: prevention
severity: critical
applies_to:
  - "wenn ein SaaS-API-Key oder OAuth-Token in Code verdrahtet wird"
  - "beim Review eines SaaS-Connectors / Webhooks / SCIM-Bridges"
  - "bei der Triage verdächtiger SaaS-Admin-Aktivität"
  - "beim Schreiben von Infrastruktur, die SaaS-Traffic proxyt"
  - "bei der Beantwortung einer SaaS-bezogenen Security-Frage"
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

# SaaS-Anwendungssicherheit

## Regeln (für KI-Agenten)

### IMMER
- SaaS-API-Tokens, OAuth-Secrets, Webhook-Signing-Keys und
  Service-Account-JSON-Dateien in einem **Secrets Manager** ablegen
  (Vault, AWS Secrets Manager, GCP Secret Manager, Doppler,
  1Password Connect) — nie inline, nie `os.Setenv`-aus-Source, nie
  in CI-Repo-Variables (nur `secrets.*`).
- Für **OAuth-basierte** SaaS-Integrationen (Google Workspace,
  Microsoft 365, Slack, Atlassian Cloud, HubSpot, Zoom, Notion,
  Lark, Calendly, NetSuite OAuth 2.0, Salesforce Connected Apps):
  `refresh_token` verschlüsselt-at-rest persistieren, Access-Tokens
  vor Ablauf refreshen, und das Client-Secret in einem
  Server-only-Pfad ablegen (nie in JS-/Mobile-Bundles).
- Für **HMAC-Webhook-Callbacks** (Slack `X-Slack-Signature`,
  Calendly V2 `Calendly-Webhook-Signature`, HubSpot v3
  `X-HubSpot-Signature-v3`, Stripe-artige Plattformen, Zoom
  verification token, Teams outgoing webhook HMAC, Lark
  `X-Lark-Signature`, Notion verification token): Signatur und
  Timestamp-Fenster (Default 5 min) bei jedem eingehenden Request
  **vor** dem Parsen des Bodies oder dem Vertrauen in ein Feld
  validieren.
- Base-URLs der SaaS-APIs auf die Produktions-Hostnames des
  Vendors pinnen (`api.atlassian.com`, `api.hubapi.com`,
  `api.calendly.com`, `*.zoom.us`, `slack.com/api`,
  `graph.microsoft.com`, `api.bamboohr.com`, `wd*.myworkday.com`,
  `*.salesforce.com`/`*.force.com`, `api.notion.com`,
  `open.larksuite.com`/`open.feishu.cn`, `*.netsuite.com`).
  Antworten von unerwarteten Hostnames ablehnen — das fängt
  DNS-Takeover und Account-Takeover-Proxy-Versuche.
- **SCIM**- und **Directory-Sync**-Endpunkte als
  security-sensitive behandeln: Mutual TLS oder signierter
  JWT-Bearer erforderlich, Rate-Limit, und jeden
  User-/Group-Write in einen tamper-evident Sink loggen.
- **Least-Privilege-Scopes** auf jeder SaaS-App, die du anlegst.
  Salesforce Connected Apps: `full`/`refresh_token` vermeiden,
  außer erforderlich. Slack-Bot-Tokens: nur die Scopes listen, die
  du aufrufst. Google Workspace OAuth:
  `.../auth/admin.directory.user.readonly` statt
  `admin.directory.user` anfordern, wenn du nicht schreibst.
  HubSpot Private Apps: nur die Scope-Checkboxen ankreuzen, die du
  tatsächlich aufrufst.
- **Zwei-Schritt-Verifizierung (2SV / MFA)** auf jeder
  SaaS-Admin-Konsole erzwingen, **inklusive** Super-Admin- /
  Org-Owner- / Billing-Owner-Konten. SSO an deinen IdP binden und
  Password-Fallback für Admins deaktivieren.
- **Dedizierte, nicht geteilte Service-Accounts** für
  System-zu-System-SaaS-Integrationen verlangen.
  Service-Account-Namen sollten den Zweck encodieren
  (`jira-ingestion-sa`, nicht `api-user-3`). Interaktiven Login
  auf diesen Konten deaktivieren, wo die Plattform es erlaubt.
- Speziell für Google Workspace: Domain-wide-Delegation-Service-
  Account-Keys ≤ 90 Tage rotieren, wo unterstützt Workload
  Identity Federation bevorzugen, und `Admin-SDK`-Aufrufe in
  Admin Console > Reports auditieren.
- Speziell für Atlassian (Jira/Confluence): **OAuth 2.0 (3LO) /
  Atlassian Connect** mit `actAsAccountId` bevorzugen; nur bei
  persönlicher Skripting-Automatisierung auf user-gebundene
  API-Tokens zurückfallen. Per-User-API-Tokens ≤ 90 Tage rotieren.
- Speziell für NetSuite: **OAuth 2.0** oder **TBA (Token-Based
  Authentication)** mit einem dedizierten Integration-Record
  bevorzugen; nie den User-/Password-Login-Flow für
  System-Integrationen verwenden.
- Für BambooHR / Workday / NetSuite (HRIS-/ERP-Klasse): jeden
  Bulk-Export von Mitarbeitern/PII als **DLP-Grenze** behandeln —
  Request, authentifizierten Principal, Zeilenanzahl und Ziel
  loggen. Bei ungewöhnlichem Volumen alarmieren.

### NIE
- Ein SaaS-API-Token, OAuth-Client-Secret, Webhook-Signing-Key
  oder Service-Account-JSON in Source, Container-Images,
  Mobile-App-Binaries oder Client-Side-JS hardcoden. Die
  Vendor-Token-Formate, die diese Rule-Datei erkennt (z. B.
  `xoxb-`, `xapp-`, `jira_pat_`, `pat-na`, `ya29.`, `1//`,
  `sk_live_`), werden von Angreifern auf öffentlichem GitHub,
  npm, PyPI und Docker Hub innerhalb von Minuten nach dem Push
  massenhaft gescannt.
- Webhook-Signaturverifizierung "fürs Testen" deaktivieren. Jeder
  öffentlich bekannte Slack-/HubSpot-/Zoom-/Calendly-/Teams-/
  Lark-/Notion-Kompromiss über einen gespooften Webhook
  exploitete eine Integration, die mit ausgeschalteten
  Signatur-Checks in Produktion lief.
- Einen **Super-Admin**-OAuth-Scope von Google Workspace
  (`https://www.googleapis.com/auth/admin`) an irgendetwas außer
  einer eng kontrollierten, IT-owned Automatisierung ausgeben.
  Die meisten Use Cases brauchen nur das engere
  `admin.directory.*.readonly`.
- Ein einziges **Personal-API-Token** über Services teilen für
  Jira, Confluence, BambooHR, Workday, NetSuite oder Notion.
  Personenbezogene Tokens erben die Privilegien des Menschen und
  leaken über dessen Laptop / SaaS-Konto.
- Eine **Incoming-Webhook-URL** von Slack / Teams / Lark / Google
  Chat konfigurieren, die in einen Channel höheren Vertrauens als
  seine Consumer postet. Wenn ein CI-Bot in `#secops` posten
  kann, ist ein CI-Kompromiss = direktes Phishing von SecOps.
  Stattdessen signierte Apps + Per-Channel-Posting-Permissions
  verwenden.
- **Link-Sharing** in Google Drive / Notion / Confluence /
  Atlassian Cloud / SharePoint auf "Anyone with the link" stehen
  lassen für Dokumente mit Kundendaten, Secrets oder
  nicht-öffentlichen Roadmaps. Org-Sharing-Policy default auf
  **domain-restricted** stellen.
- Dem **`From`-/`email`-Feld** eines Calendly-/HubSpot-/Zoom-
  Webhook-Payloads als autoritative Identity trauen. Die Signatur
  beweist, dass der *Vendor* den Payload geschickt hat; die
  Body-Felder können trotzdem Attacker-supplied sein (gespoofter
  Invitee, vom Angreifer gesetztes Custom-Feld). Den User
  serverseitig per canonical ID nachschlagen.
- SaaS-**OAuth-Refresh-Tokens** zwischen Umgebungen
  (dev↔staging↔prod) weiterleiten — jede Umgebung muss ihre eigene
  Connected App / ihren eigenen OAuth-Client haben, sonst leben
  Prod-Credentials im Blast-Radius von dev.
- **Salesforce-Apex- / NetSuite-SuiteScript- / Workday-Studio- /
  Jira-ScriptRunner**-Code, der von einem Dritten installiert
  wurde, ohne Security-Review trauen. Diese laufen mit erhöhten
  Privilegien und sind ein wiederkehrender Vektor für
  SaaS-Supply-Chain-Vorfälle (z. B. die von Salesforce Security
  2024 dokumentierten Salesforce-via-AppExchange-ATO-Patterns).

### BEKANNTE FALSCH-POSITIVE
- Vom Vendor bereitgestellte **Sandbox-/Example-Tokens** in
  offiziellen Docs (z. B. Slack `xoxb-XXXXXXX-XXXXXXXX`, Stripe
  `sk_test_…`, Calendly `eyJ…example…`) — matchen die Regexes,
  enthalten aber literal `EXAMPLE`/`XXX`/`test`-Marker im
  umgebenden Kontext.
- `ghp_…`/`gho_…` in Drittanbieter-SaaS-Docs, die erklären, wie
  GitHub in sie eingebunden wird — das sind GitHub-Tokens, keine
  SaaS-Plattform-Tokens, und werden von `secret-detection`
  abgedeckt.
- Öffentliche **Service-Account-Email** einer veröffentlichten
  Google-Marketplace-App (`*@gserviceaccount.com`) — die Email ist
  öffentlich; nur der JSON-Key ist sensibel.
- **OAuth-Client-IDs** für öffentliche Mobile-/Web-SPAs — sie sind
  als öffentlich konzipiert. Das passende **Client-Secret** muss
  trotzdem privat bleiben; nur auf das Secret signalen.

## Kontext (für Menschen)

SaaS ist heute der dominante Data-Egress-Vektor. Die Vorfälle
2023-2025 (Snowflake / OAuth-Token-Diebstahl, Okta /
HAR-File-Leakage, GitHub-zu-Slack-Token-Replay,
Salesforce-via-Atlassian-Movement, Calendar-/Scheduling-Phish
über Calendly-artige Links) zeigen drei wiederkehrende
Fehlermodi:

1. **Token-Sprawl.** Personenbezogene Tokens und
   OAuth-Refresh-Tokens sammeln sich quer über Vendor an. Jedes
   davon ist eine Credential. Zentralisiere sie; lass sie
   regelmäßig ablaufen.
2. **Fehlkonfiguriertes Sharing.** SaaS-Plattformen defaulten auf
   Bequemlichkeit ("anyone with the link"). Kundendaten,
   Deal-Pipelines, M&A-Dokumente und interne IAM-Diagramme leaken
   öfter über diese Defaults als über Code-Bugs.
3. **Admin-Action-Blindspots.** Bulk-Exports, Mass-Permission-
   Grants, API-Key-Rotationen und SCIM-User-Write-Spikes sind
   diagnostisch für Account-Takeover oder Insider-Misbrauch —
   aber nur, wenn du hinschaust.

Die Per-Plattform-JSON-Rule-Dateien dieses Skills geben einem
KI-Reviewer:

- **Token-Formate** — Regex-Patterns, um hardcodete
  SaaS-Secrets zur PR-Zeit zu erkennen.
- **Fehlkonfigurationen** — konkrete Settings, die beim Erzeugen
  von SaaS-Integrationscode zu asserten (oder abzulehnen) sind.
- **Admin-Red-Flags** — Log-Query-Shapes, nach denen ein SIEM /
  SOAR / eine Detection-Rule schon suchen sollte.

Die Rule-Dateien sind absichtlich pro Vendor spezifisch, damit
KI-Agenten keine "generische" SaaS-Detection-Logik erzeugen, die
echte Angriffe verpasst. Sie sind außerdem klein genug, dass die
kompilierte `SECURITY-SKILLS.md`-Distribution sie in der
`full`-Tier mitführen kann, ohne das Token-Budget zu sprengen.

## Referenzen

- `rules/google_workspace.json` — GWS OAuth, Service-Account, Admin SDK
- `rules/google_chat.json` — Google Chat Webhooks und Bot-Tokens
- `rules/atlassian.json` — Jira & Confluence Cloud, OAuth 2.0 / API-Tokens
- `rules/notion.json` — Notion-Integration-Tokens, Workspace-Sharing
- `rules/hubspot.json` — HubSpot Private Apps, OAuth, Webhook v3 HMAC
- `rules/salesforce.json` — Connected Apps, Session-Tokens, Apex/Flow
- `rules/bamboohr.json` — BambooHR API-Key, SSO, Employee-Export
- `rules/workday.json` — Workday ISU, OAuth, Report-as-a-Service
- `rules/odoo.json` — Odoo XML-RPC / JSON-RPC, Master-Passwort
- `rules/microsoft_teams.json` — Teams-App- + Bot-Creds, Outgoing-Webhook-HMAC
- `rules/slack.json` — Slack-Bot-/User-/App-/Config-Tokens, Webhook-URLs
- `rules/larksuite.json` — Lark/Feishu Tenant-Access-Tokens, Webhook
- `rules/zoom.json` — Zoom JWT (legacy), Server-to-Server OAuth, Webhook
- `rules/calendly.json` — Calendly PAT, OAuth, V2-Webhook-Signatur
- `rules/netsuite.json` — NetSuite TBA, OAuth 2.0, SuiteScript-Red-Flags
- CWE-798, CWE-284, CWE-1392
- OWASP API Security Top 10 (2023) — API2 (Auth), API8 (Security Misconfig)
