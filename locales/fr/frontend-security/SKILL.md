---
id: frontend-security
language: fr
source_revision: "afe376a8"
version: "1.0.0"
title: "Sécurité du frontend"
description: "Durcissement côté navigateur : XSS, CSP, CORS, SRI, DOM clobbering, sandboxing d'iframe, Trusted Types"
category: prevention
severity: high
applies_to:
  - "lors de la génération de templates HTML / JSX / Vue / Svelte"
  - "lors du câblage des headers de réponse dans une web app"
  - "lors de l'ajout de balises de script tiers ou de ressources CDN"
languages: ["html", "javascript", "typescript", "tsx", "jsx", "vue", "svelte"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2800
rules_path: "rules/"
related_skills: ["cors-security", "auth-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP XSS Prevention Cheat Sheet"
  - "OWASP Content Security Policy Cheat Sheet"
  - "CWE-79: Improper Neutralization of Input During Web Page Generation"
  - "MDN Trusted Types"
---

# Sécurité du frontend

## Règles (pour les agents IA)

### TOUJOURS
- Traiter toutes les données utilisateur / URL / storage comme non
  fiables. Rendre via l'échappement du framework (`{}` en
  JSX/Vue/Svelte, `{{ }}` en templating). Pour du HTML brut,
  utiliser un sanitizer audité (DOMPurify) avec une allowlist
  stricte.
- Envoyer un header `Content-Security-Policy` strict. Baseline
  minimale en production : `default-src 'self'; script-src 'self'
  'nonce-<random>'; object-src 'none'; base-uri 'self';
  frame-ancestors 'none'; form-action 'self';
  upgrade-insecure-requests`. Utiliser des nonces ou des hashes —
  jamais `'unsafe-inline'` pour `script-src`.
- Définir `Strict-Transport-Security: max-age=63072000;
  includeSubDomains; preload`,
  `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer-when-downgrade` ou plus strict, et
  `Permissions-Policy` pour désactiver les features non utilisées.
- Ajouter `integrity="sha384-..." crossorigin="anonymous"` à chaque
  `<script>` et `<link rel="stylesheet">` chargé depuis un CDN.
- Ajouter `sandbox="allow-scripts allow-same-origin"` (uniquement
  les attributs nécessaires) à chaque `<iframe>`. Par défaut, pas
  de flags allow.
- Utiliser des cookies avec `Secure; HttpOnly; SameSite=Lax` (ou
  `Strict` pour les flux sensibles). Préfixe `__Host-` quand il n'y
  a pas de partage entre sous-domaines.
- Activer Trusted Types là où le navigateur le permet
  (`Content-Security-Policy: require-trusted-types-for 'script'`)
  pour que les assignations aux sinks DOM (`innerHTML`,
  `setAttribute('src', ...)` pour les scripts) passent forcément par
  une policy typée.

### JAMAIS
- Utiliser `dangerouslySetInnerHTML`, `v-html`, `{@html ...}`,
  `innerHTML =` ou `document.write` avec une entrée non fiable.
- Utiliser `eval`, `new Function`, `setTimeout(string)`,
  `setInterval(string)` ou `Function('return x')`.
- Injecter une entrée utilisateur dans `href`, `src`, `formaction`,
  `action` ou tout attribut porteur d'URL sans valider le schéma
  (bloquer `javascript:`, `data:`, `vbscript:`).
- Utiliser `target="_blank"` sans `rel="noopener noreferrer"` —
  fuite de `window.opener`.
- Faire confiance à des nœuds DOM par leur id seul. DOM clobbering :
  un `<input name="config">` contrôlé par l'attaquant masque
  `window.config`.
- Utiliser `postMessage` sans vérifier `event.origin` contre une
  allowlist.
- Stocker des JWT, des refresh tokens ou des PII dans `localStorage`
  / `sessionStorage` — n'importe quel XSS les exfiltre. Préférer des
  cookies HttpOnly.
- Lire ou écrire `document.cookie` depuis JavaScript pour les
  cookies d'auth — ils devraient de toute façon être HttpOnly.

### FAUX POSITIFS CONNUS
- Les outils d'admin internes qui rendent délibérément du Markdown
  / du texte riche issu d'auteurs de confiance peuvent utiliser
  `dangerouslySetInnerHTML` après un passage de sanitizer ;
  documenter l'appel au sanitizer inline.
- Les extensions de navigateur ont parfois besoin de
  `'unsafe-eval'` dans le CSP de l'extension ; le CSP de la web app
  exposée à l'utilisateur doit l'interdire malgré tout.
- Les connexions WebSocket vers des endpoints non-same-origin sont
  acceptables quand le serveur effectue une validation d'origin.

## Contexte (pour les humains)

L'OWASP XSS Prevention Cheat Sheet reste la référence faisant
autorité pour les règles d'échappement ; CSP est la couche de
défense en profondeur qui transforme un échappement manqué en
rapport loggé plutôt qu'en session volée. Trusted Types est le
pattern plus récent, appliqué par le navigateur, qui déplace la
question "est-ce passé par un sanitizer ?" de l'audit à l'exécution
vers le système de types.

Les frontends générés par IA tendent à atteindre `innerHTML` et
`dangerouslySetInnerHTML` parce que c'est plus court ; ce skill est
le contrepoids.

## Références

- `rules/csp_defaults.json`
- `rules/xss_sinks.json`
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html).
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Cross-site scripting.
- [Trusted Types (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API).
