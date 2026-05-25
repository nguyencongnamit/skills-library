---
id: cors-security
language: fr
source_revision: "afe376a8"
version: "1.0.0"
title: "Sécurité CORS"
description: "Configuration CORS stricte : pas de wildcard avec credentials, origines en allowlist, cache de preflight raisonnable, en-têtes exposés minimaux"
category: prevention
severity: high
applies_to:
  - "lors de la génération du middleware CORS ou de la config du framework"
  - "lors du câblage des en-têtes CORS d'API Gateway / CloudFront / Nginx"
  - "lors de la revue d'un endpoint cross-origin exposé au navigateur"
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

# Sécurité CORS

## Règles (pour les agents IA)

### TOUJOURS
- Utiliser une **allowlist** d'origines, pas `*`. Refléter l'en-tête
  `Origin` entrant uniquement quand il correspond à une entrée connue
  de la configuration (ou à une regex précompilée de noms d'hôtes
  contrôlés par l'opérateur).
- Si les réponses incluent des credentials (cookies, `Authorization`),
  positionner `Access-Control-Allow-Credentials: true` **et** garantir
  que `Access-Control-Allow-Origin` est une seule chaîne d'origine
  spécifique — jamais `*`.
- Inclure `Vary: Origin` sur les réponses dont le corps dépend de
  l'`Origin` de la requête, pour que les caches ne servent pas la
  réponse d'une origine à une autre.
- Restreindre `Access-Control-Allow-Methods` du preflight aux méthodes
  effectivement acceptées par l'endpoint ; restreindre
  `Access-Control-Allow-Headers` aux en-têtes effectivement consommés.
- Positionner `Access-Control-Max-Age` à une valeur raisonnable
  (≤ 86400 en production) pour amortir la latence du preflight sans
  figer une mauvaise allowlist.
- Maintenir l'allowlist dans le code (ou dans un fichier de config
  versionné), pas dérivée d'une base de données — pour que les
  attaquants ne puissent pas ajouter leur origine en insérant une
  ligne.

### JAMAIS
- Positionner `Access-Control-Allow-Origin: *` avec
  `Access-Control-Allow-Credentials: true`. La spec Fetch l'interdit
  pour une raison — les navigateurs refuseront la réponse, mais le plus
  gros problème est qu'un proxy / cache en amont peut déjà l'avoir
  fuitée.
- Refléter l'en-tête `Origin` sans vérification par allowlist
  (`Access-Control-Allow-Origin: <Origin>` pour toute origine
  entrante). C'est la même chose que `*` pour les credentials avec un
  comportement de cache pire.
- Autoriser `null` comme Origin. `null` est ce que Chrome envoie depuis
  des iframes sandboxed, des URIs `data:` et `file://` — aucun ne
  devrait avoir d'accès credentialed à votre API.
- Autoriser des sous-domaines arbitraires avec une regex comme
  `.*\.example\.com$` sans tenir compte du subdomain takeover. Épingler
  des sous-domaines spécifiques ; traiter `*.example.com` comme une
  décision délibérée couplée à des contrôles de propriété des
  sous-domaines.
- Exposer des en-têtes internes via `Access-Control-Expose-Headers`.
  Limiter au minimum dont le frontend a réellement besoin.
- Utiliser CORS comme autorisation. CORS est une politique de
  *navigateur* ; ça n'arrête pas server-to-server, curl ou les clients
  non-navigateurs. Authentifie la requête correctement.

### FAUX POSITIFS CONNUS
- Les APIs vraiment publiques et non authentifiées (open data,
  endpoints CDN marketing) peuvent légitimement utiliser
  `Access-Control-Allow-Origin: *` *sans* credentials.
- Les outils d'admin internes restreints à un réseau privé peuvent
  utiliser une seule origine fixe ; la préoccupation du wildcard ne
  s'applique pas car il n'y a pas d'appelants cross-origin.
- Quelques intégrations (Stripe.js, Plaid, Auth0) attendent des
  en-têtes CORS spécifiques — lire la section CORS de chaque
  fournisseur avant d'assouplir la base.

## Contexte (pour les humains)

CORS est largement compris à tort comme un contrôle de sécurité. Ce
n'en est pas un — c'est un *assouplissement* de la same-origin policy.
Le contrôle de sécurité c'est l'authentification. La mauvaise
configuration CORS importe parce que, combinée avec des cookies ou des
en-têtes `Authorization`, elle donne aux origines non fiables la
capacité de faire des requêtes cross-origin credentialed et de lire la
réponse.

Cette skill est courte by design — la matrice des mauvaises
combinaisons est finie et les règles sont tranchantes.

## Références

- `rules/cors_safe_config.json`
- [OWASP CORS Origin Header Scrutiny](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny).
- [CWE-942](https://cwe.mitre.org/data/definitions/942.html).
- [Fetch — CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol).
