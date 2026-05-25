---
id: protocol-security
language: fr
source_revision: "afe376a8"
version: "1.0.0"
title: "Sécurité des protocoles"
description: "TLS 1.2+, mTLS, validation de certificat, HSTS, credentials de canal gRPC, checks d'Origin WebSocket"
category: hardening
severity: critical
applies_to:
  - "lors de la génération de clients et serveurs HTTP / gRPC / WebSocket / SMTP / base de données"
  - "lors de la génération de configuration TLS dans le code ou la config plateforme"
  - "lors de la génération d'auth service-à-service"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2400
rules_path: "rules/"
related_skills: ["crypto-misuse", "frontend-security", "api-security"]
last_updated: "2026-05-13"
sources:
  - "NIST SP 800-52 Rev. 2 (TLS Guidelines)"
  - "RFC 8446 — TLS 1.3"
  - "RFC 6797 — HSTS"
  - "OWASP Transport Layer Security Cheat Sheet"
  - "CWE-295, CWE-326, CWE-319, CWE-757"
---

# Sécurité des protocoles

## Règles (pour les agents IA)

### TOUJOURS
- Par défaut **TLS 1.3** pour les nouveaux clients et serveurs ;
  n'autoriser TLS 1.2 que pour l'interop avec des pairs legacy.
  Désactiver TLS 1.0/1.1, SSLv2/v3.
- Valider le certificat serveur : chaîne vers une CA de confiance,
  nom correspondant au hostname attendu (ou SAN), non expiré, non
  révoqué (OCSP stapling activé).
- Activer HSTS sur les réponses HTTP pour tout ce qui est servi en
  HTTPS : `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.
  Inscrire le host à la HSTS preload list une fois stable.
- Utiliser **mutual TLS** (mTLS) pour le trafic service-à-service à
  l'intérieur d'un trust domain (mesh : Istio / Linkerd ; standalone
  : SPIFFE / SPIRE pour l'identité).
- Pour les clients/serveurs gRPC, utiliser `grpc.secure_channel` /
  `grpc.SslCredentials` / `credentials.NewTLS` — jamais
  `insecure_channel` en production.
- Pour les serveurs WebSocket, valider le header `Origin` contre une
  allowlist et authentifier le handshake (cookies + token CSRF, ou
  un bearer en query-string utilisé une fois à l'upgrade et
  re-validé).
- Pour les tokens service-à-service, préférer des **SPIFFE IDs**
  (`spiffe://trust-domain/...`) avec des certs de workload courts,
  plutôt que des API keys long terme.
- Pinner le certificat (pinning de public key) pour les clients
  mobile / desktop à fort risque qui rappellent le backend de
  l'opérateur.

### JAMAIS
- Désactiver la vérification du certificat (`InsecureSkipVerify: true`,
  `verify=False`, `rejectUnauthorized: false`,
  `CURLOPT_SSL_VERIFYPEER=0`). Le seul usage acceptable est dans un
  test unitaire qui s'exécute contre un cert localhost éphémère.
- Implémenter un `X509TrustManager` / `HostnameVerifier` /
  `URLSessionDelegate` / `ServerCertificateValidationCallback`
  custom qui retourne « trusted » sans condition.
- Mélanger des ressources HTTP et HTTPS sur la même page (mixed
  content) — les navigateurs modernes bloqueront les sous-ressources,
  mais les APIs restent vulnérables au downgrade MITM.
- Envoyer des tokens / mots de passe sur HTTP en clair — même sur
  localhost en dev, à moins que l'environnement de dev soit
  documenté comme non pertinent pour la sécurité.
- Utiliser `grpc.insecure_channel(...)` en code de production.
- Faire confiance au header `Host` / `X-Forwarded-Host` /
  `Forwarded` sans allowlist ; les URLs absolues construites à
  partir de `Host` permettent du host-header injection et du
  password-reset poisoning.
- Faire suivre aveuglément les headers `Authorization` / `Cookie`
  entrants au travers des origins dans votre service mesh — re-
  dériver l'identité depuis mTLS ou un service token.
- Activer la TLS renegotiation sur les clients que vous contrôlez ;
  pinner sur `tls.NoRenegotiation` quand disponible.

### FAUX POSITIFS CONNUS
- Les serveurs dev en localhost-uniquement avec des certs
  self-signed et une documentation explicite sont OK ; les tests CI
  contre des certs éphémères signés par CA sont OK.
- Un petit nombre d'intégrations legacy enterprise requièrent TLS
  1.2 avec un cipher spécifique ; documenter l'exception et isoler
  l'intégration derrière un proxy.
- Les endpoints publics en lecture seule (ex., pages de statut)
  peuvent légitimement être servis en HTTP pour la cacheabilité,
  bien que HTTPS reste préféré.

## Contexte (pour les humains)

NIST SP 800-52 Rev. 2 est la référence TLS faisant autorité au sein
du gouvernement US ; RFC 8446 c'est TLS 1.3 lui-même. Le mode
d'échec récurrent en code review est **`InsecureSkipVerify`** (ou
ses équivalents dans chaque langage) — en général introduit « pour
faire passer les tests » et jamais retiré.

Ce skill s'accorde naturellement avec `crypto-misuse` (choix
d'algorithme) et `auth-security` (émission de tokens).

## Références

- `rules/tls_defaults.json`
- `rules/cert_validation_sinks.json`
- [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final).
- [RFC 8446 — TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446).
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html).
- [CWE-295](https://cwe.mitre.org/data/definitions/295.html) — Improper Certificate Validation.
