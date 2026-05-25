---
id: cors-security
language: de
source_revision: "afe376a8"
version: "1.0.0"
title: "CORS-Sicherheit"
description: "Strikte CORS-Konfiguration: kein Wildcard mit Credentials, allowlist-basierte Origins, sinnvoller Preflight-Cache, minimale exponierte Header"
category: prevention
severity: high
applies_to:
  - "beim Erzeugen von CORS-Middleware oder Framework-Config"
  - "beim Verdrahten von CORS-Headern in API Gateway / CloudFront / Nginx"
  - "beim Reviewen eines cross-origin Browser-Endpoints"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1000
  full: 2000
rules_path: "rules/"
related_skills: ["frontend-security", "api-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP HTML5 Security Cheat Sheet — CORS"
  - "CWE-942 — Permissive Cross-domain Policy with Untrusted Domains"
  - "Fetch Living Standard (CORS)"
---

# CORS-Sicherheit

## Regeln (für KI-Agenten)

### IMMER
- Eine **Allowlist** von Origins verwenden, kein `*`. Den eingehenden
  `Origin`-Header nur reflektieren, wenn er einer bekannten Konfig-
  Entry oder einem vorkompilierten Regex operator-kontrollierter
  Hostnames entspricht.
- Wenn Antworten Credentials enthalten (Cookies, `Authorization`),
  `Access-Control-Allow-Credentials: true` setzen **und** sicherstellen,
  dass `Access-Control-Allow-Origin` ein einzelner spezifischer Origin-
  String ist — nie `*`.
- `Vary: Origin` an Antworten anhängen, deren Body vom Request-`Origin`
  abhängt, damit Caches nicht die Antwort eines Origin an einen anderen
  ausliefern.
- Preflight `Access-Control-Allow-Methods` auf die tatsächlich
  akzeptierten Methoden einschränken; `Access-Control-Allow-Headers` auf
  die tatsächlich konsumierten Header.
- `Access-Control-Max-Age` auf einen sinnvollen Wert setzen (in
  Production ≤ 86400), um Preflight-Latenz zu amortisieren, ohne eine
  schlechte Allowlist festzuzurren.
- Die Allowlist im Code (oder in einer eingecheckten Config-Datei)
  pflegen, nicht aus einer Datenbank ableiten — damit Angreifer nicht
  durch das Einfügen einer Zeile ihren Origin hinzufügen können.

### NIE
- `Access-Control-Allow-Origin: *` zusammen mit
  `Access-Control-Allow-Credentials: true` setzen. Die Fetch-Spec
  verbietet das aus gutem Grund — Browser werden die Antwort ablehnen,
  aber das größere Problem ist, dass ein vorgelagerter Proxy / Cache
  sie bereits geleakt haben kann.
- Den `Origin`-Header ohne Allowlist-Check reflektieren
  (`Access-Control-Allow-Origin: <Origin>` für jeden eingehenden Origin).
  Das ist dasselbe wie `*` für Credentials, nur mit schlechterem
  Cache-Verhalten.
- `null` als Origin zulassen. `null` schickt Chrome aus sandboxed
  iframes, `data:`-URIs und `file://` — keines davon sollte
  credentialed Zugriff auf deine API haben.
- Beliebige Subdomains via Regex wie `.*\.example\.com$` zulassen, ohne
  Subdomain-Takeover zu berücksichtigen. Spezifische Subdomains pinnen;
  `*.example.com` als bewusste, an Subdomain-Ownership-Kontrollen
  gekoppelte Entscheidung behandeln.
- Interne Header via `Access-Control-Expose-Headers` exponieren. Auf
  das Minimum begrenzen, das das Frontend wirklich braucht.
- CORS als Autorisierung verwenden. CORS ist eine *Browser*-Policy;
  sie stoppt nicht Server-zu-Server, curl oder Non-Browser-Clients.
  Authentifiziere den Request ordentlich.

### BEKANNTE FALSCH-POSITIVE
- Echt öffentliche, unauthentifizierte APIs (z. B. Open Data,
  Marketing-CDN-Endpoints) können legitim
  `Access-Control-Allow-Origin: *` *ohne* Credentials verwenden.
- Interne Admin-Tools, die auf ein privates Netz beschränkt sind, können
  einen einzelnen festen Origin verwenden; das Wildcard-Problem trifft
  nicht zu, weil es keine cross-origin Caller gibt.
- Eine Handvoll Integrationen (Stripe.js, Plaid, Auth0) erwartet
  spezifische CORS-Header — den CORS-Abschnitt des jeweiligen Providers
  lesen, bevor die Baseline gelockert wird.

## Kontext (für Menschen)

CORS wird breit missverstanden als Security-Control. Ist es nicht — es
ist eine *Lockerung* der Same-Origin-Policy. Der Security-Control ist
Authentifizierung. CORS-Misskonfigurationen sind wichtig, weil sie in
Kombination mit Cookies oder `Authorization`-Headern unvertrauten
Origins die Fähigkeit geben, credentialed cross-origin Requests zu
machen und die Antwort zu lesen.

Dieser Skill ist by design kurz — die Matrix schlechter Kombinationen
ist endlich, und die Regeln sind stumpf.

## Referenzen

- `rules/cors_safe_config.json`
- [OWASP CORS Origin Header Scrutiny](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny).
- [CWE-942](https://cwe.mitre.org/data/definitions/942.html).
- [Fetch — CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol).
