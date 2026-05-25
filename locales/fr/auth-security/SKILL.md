---
id: auth-security
language: fr
source_revision: "afe376a8"
version: "1.0.0"
title: "Sécurité d'authentification et d'autorisation"
description: "JWT, OAuth 2.0 / OIDC, gestion de session, CSRF, hachage de mots de passe et imposition de MFA"
category: prevention
severity: critical
applies_to:
  - "lors de la génération de flux login / signup / reset de mot de passe"
  - "lors de la génération d'émission ou de vérification de JWT"
  - "lors de la génération de code client ou serveur OAuth 2.0 / OIDC"
  - "lors du câblage de cookies de session, jetons CSRF, MFA"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1300
  full: 2700
rules_path: "rules/"
related_skills: ["api-security", "crypto-misuse", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "OWASP Authentication Cheat Sheet"
  - "OWASP Session Management Cheat Sheet"
  - "RFC 6749 — OAuth 2.0"
  - "RFC 7519 — JSON Web Token"
  - "RFC 9700 — OAuth 2.0 Security BCP"
  - "NIST SP 800-63B (Authenticator Assurance)"
---

# Sécurité d'authentification et d'autorisation

## Règles (pour les agents IA)

### TOUJOURS
- Pour la vérification de JWT, épingler l'algorithme attendu (`RS256`,
  `EdDSA` ou `ES256`) et vérifier `iss`, `aud`, `exp`, `nbf` et `iat`.
  Rejeter `alg=none` et tout algorithme inattendu.
- Pour les clients publics OAuth 2.0 (SPA / mobile / CLI), utiliser le
  **flux authorization code avec PKCE** (S256). Jamais l'implicit flow.
  Jamais le resource owner password credentials grant.
- Cookies de session : `Secure; HttpOnly; SameSite=Lax` (ou `Strict` pour
  les flux sensibles). Utiliser le préfixe `__Host-` quand il n'y a pas de
  partage de sous-domaine.
- Renouveler l'identifiant de session au login et lors d'un changement de
  privilège. Lier la session à l'user agent uniquement comme signal faible
  — jamais comme seule vérification.
- Hacher les mots de passe avec argon2id (m=64 MiB, t=3, p=1) et un sel
  aléatoire par utilisateur. Bcrypt cost ≥ 12 ou scrypt N≥2^17 sont des
  alternatives acceptables pour des systèmes legacy. PBKDF2-SHA256 requiert
  ≥ 600 000 itérations (minimum OWASP 2023).
- Imposer une longueur de mot de passe ≥ 12 caractères sans règles de
  composition ; autoriser Unicode ; vérifier les mots de passe candidats
  contre une liste de mots de passe compromis (HIBP / API k-anonymity de
  pwned-passwords).
- Implémenter le verrouillage de compte *ou* le rate limiting pour les
  tentatives de mot de passe (NIST SP 800-63B §5.2.2 : au plus 100 échecs
  sur 30 jours).
- Implémenter la protection CSRF pour les requêtes modificatrices d'état
  joignables depuis une session de navigateur : synchronizer token,
  double-submit cookie, ou `SameSite=Strict` pour les endpoints à haut
  risque.
- Exiger MFA / step-up pour les opérations administratives, les changements
  de mot de passe, les changements de dispositif MFA, les changements de
  facturation.
- Pour OIDC, valider le `nonce` que vous avez envoyé contre le `nonce` du
  ID token ; valider `at_hash` / `c_hash` quand présents.

### JAMAIS
- Utiliser `Math.random()` (ou tout RNG non-CSPRNG) pour générer des IDs
  de session, des jetons de reset, des codes de récupération MFA ou des
  clés d'API.
- Accepter JWT `alg=none` ; ou accepter HS256 depuis un client quand
  l'émetteur signe avec RS256 (attaque classique de confusion d'algorithme).
- Comparer mots de passe ou hash de jetons avec `==` / `strcmp` ; utiliser
  un comparateur à temps constant.
- Stocker les mots de passe de manière réversible (chiffrés au lieu de
  hachés). Le stockage doit être à sens unique.
- Divulguer lequel de l'identifiant ou du mot de passe était incorrect.
  Renvoyer un message générique "invalid credentials".
- Mettre des access tokens, refresh tokens ou IDs de session dans des
  query strings d'URL — ils fuient dans les logs, en-têtes Referer et
  historique du navigateur.
- Utiliser `localStorage` / `sessionStorage` pour conserver des refresh
  tokens de longue durée. Utiliser des cookies HttpOnly.
- Faire confiance aux rôles / claims fournis par le client au niveau de
  l'API — redéduire le sujet authentifié et consulter l'autorisation côté
  serveur à chaque requête.
- Émettre des access tokens de longue durée (>1 heure) ; s'appuyer sur des
  refresh tokens avec rotation.
- Utiliser l'implicit flow ou le password grant.

### FAUX POSITIFS CONNUS
- Les jetons service-à-service avec des TTLs longs sont parfois acceptables
  lorsqu'ils sont stockés dans un secret manager et liés à une identité de
  workload spécifique.
- L'auth "magic link" en développement local sans hachage de mot de passe
  pour des utilisateurs de dev éphémères est OK si elle est gardée derrière
  un flag d'env et désactivée en prod.
- Les jetons en query d'URL sont tolérables à *un* endroit — le retour
  d'authorization code OAuth — parce que la valeur est à courte durée et
  à usage unique.

## Contexte (pour les humains)

Les défaillances d'authentification apparaissent constamment dans OWASP
Top 10 (A07:2021 — Identification and Authentication Failures). Les modes
courants sont : stockage faible de mot de passe, jetons prévisibles, MFA
manquante, mauvaise configuration JWT et fixation de session. RFC 9700
(OAuth 2.0 Security BCP) et NIST SP 800-63B sont les références
autoritatives pour la recette.

Les assistants IA ont tendance à livrer de l'auth "ça marche en dev" :
JWT HS256 avec secrets en dur, `bcrypt.hash` avec cost 10 par défaut, pas
de PKCE, jetons dans localStorage. Cette skill attrape chacun de ces cas.

## Références

- `rules/jwt_safe_config.json`
- `rules/oauth_flows.json`
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
- [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700).
