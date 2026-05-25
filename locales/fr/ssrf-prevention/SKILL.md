---
id: ssrf-prevention
language: fr
source_revision: "4c215e6f"
version: "1.0.0"
title: "Prévention SSRF"
description: "Défense contre Server-Side Request Forgery : blocage du metadata cloud, filtrage d'IPs internes, défense contre DNS rebinding, URL fetching basé sur allowlist"
category: prevention
severity: critical
applies_to:
  - "lors de la génération de code qui fetch une URL fournie par le client"
  - "lors du câblage de webhooks, image proxies, PDF renderers, oEmbed fetchers"
  - "lors de l'exécution dans tout environnement cloud avec un service instance metadata"
  - "lors de la revue d'un wrapper d'URL parsing ou d'HTTP client"
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

# Prévention SSRF

## Règles (pour les agents IA)

### TOUJOURS
- Valider **chaque** URL fetchée pour un client via une
  **allowlist** d'hôtes attendus. L'allowlist est la seule défense
  durable — les block-lists sont contournables via des tricks
  d'encoding, l'IPv6 dual-stack, et le DNS rebinding.
- Résoudre le hostname **une fois**, valider l'IP résolue contre
  ta block-list de plages privées / réservées / link-local, puis
  se connecter à cette IP pinée en utilisant SNI. Sinon un
  attaquant peut faire un race de DNS rebind entre validation et
  connect (`time-of-check / time-of-use`).
- Bloquer à la couche réseau **et** à la couche applicative.
  Couper l'egress vers `169.254.169.254`, `[fd00:ec2::254]`,
  `metadata.google.internal` et `100.100.100.200` depuis tout
  service qui n'a pas légitimement besoin du metadata service.
- Imposer **IMDSv2** sur AWS EC2 (session-token, hop-limit=1).
  IMDSv1 — le pattern que le breach Capital One 2019 a exploité —
  doit être désactivé au niveau de l'instance.
- Désactiver les redirects HTTP par défaut sur les fetchers
  server-side (ou n'en suivre qu'un nombre petit et borné, en
  re-validant la nouvelle URL contre l'allowlist à chaque hop).
  Le bypass SSRF le plus commun est `https://allowed.example.com`
  retournant un 302 vers `http://169.254.169.254/...`.
- Utiliser un HTTP client séparé et restreint pour les URLs
  *contrôlées par l'utilisateur* vs les URLs *internes*. Utiliser
  le mauvais client doit fail closed (par ex. via une distinction
  de type en Go / Rust / TypeScript).
- Parser les URLs avec un seul parser bien connu (`net/url.Parse`
  en Go, `urllib.parse` en Python, `new URL()` en JavaScript). Les
  parsers différentiels entre par ex. WHATWG et RFC-3986 sont une
  classe documentée de bypass SSRF.

### JAMAIS
- Faire confiance à un hostname / IP fourni par l'utilisateur.
  Toujours re-résoudre dans ton resolver de confiance et
  re-vérifier l'adresse résolue.
- Se connecter à une URL sur la base de son hostname quand le
  protocole permet les redirects — `gopher://`, `dict://`,
  `file://`, `jar://`, `netdoc://`, `ldap://` sont tous des
  amplificateurs SSRF communs. Restreindre à `http://` et
  `https://` (et `ftp://` seulement si réellement nécessaire).
- Faire confiance à `0.0.0.0`, `127.0.0.1`, `[::]`, `[::1]`,
  `localhost`, ou `*.localhost.test` — tous atteignent l'instance
  locale. La liste doit aussi inclure link-local
  `169.254.0.0/16`, IPv6 IPv4-mapped `::ffff:127.0.0.1`, et IPv6
  ULA `fc00::/7`.
- Utiliser le string d'URL de l'utilisateur dans une ligne de log
  ou un response d'erreur — ça peut être l'oracle de réflexion
  SSRF qui transforme un SSRF aveugle en SSRF d'exfiltration de
  data.
- Faire tourner un sidecar / proxy de blocage de metadata comme
  **seule** défense — un attaquant qui trouve un pseudo-URL
  Unix-domain-socket ou un hostname mal configuré peut router
  autour du proxy. L'allowlist au niveau application reste
  requise.
- Autoriser IDN / Punycode dans les URLs utilisateur sans
  normalisation — les attaques homographes IDN contournent les
  checks naïfs de string-allowlist (`gооgle.com` avec o
  cyrillique ≠ `google.com`).

### FAUX POSITIFS CONNUS
- Les intégrations server-to-server où les deux côtés sont
  contrôlés par l'opérateur et l'URL est hardcoded dans la config
  (pas fournie par l'utilisateur) — l'allowlist ici est la config
  statique elle-même.
- Les calls service-to-service local au cluster Kubernetes — ils
  ne passent pas par de l'input utilisateur, mais attention à
  toute network policy cross-namespace.
- Les webhooks sortants **vers** le client (par ex. webhooks
  Slack, Discord, Microsoft Teams). Valider que le host de l'URL
  est dans l'allowlist documentée de l'intégration, pas
  arbitraire.

## Contexte (pour les humains)

SSRF est désormais le vecteur d'accès initial de facto pour les
breaches cloud. La chaîne est : une URL fournie par l'utilisateur
→ le server la fetch → le server a des credentials implicites
(IAM cloud metadata, APIs internes d'admin, endpoints RPC) →
l'attaquant vole les credentials. Le breach Capital One 2019
(80M enregistrements clients) était un cas d'école de SSRF +
exfiltration IMDSv1. Les fixes sont simples et bien documentés ;
les patterns réapparaissent parce que le fetching d'URL est un
petit coin de la plupart des codebases.

Ce skill insiste sur les classes DNS-rebinding et redirect-bypass
parce que c'est là que les validators d'URL générés par IA
échouent le plus souvent — le blocage évident de
169.254.169.254 est facile à ajouter, mais le pattern
allow-only-after-resolve-and-pin demande plus de réflexion.

## Références

- `rules/ssrf_sinks.json`
- `rules/cloud_metadata_endpoints.json`
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
- [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
- [Capital One 2019 breach DOJ filing](https://www.justice.gov/usao-wdwa/press-release/file/1188626/download).
- [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html).
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf).
