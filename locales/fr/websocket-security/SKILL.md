---
id: websocket-security
language: fr
source_revision: "4c215e6f"
version: "1.0.0"
title: "Sécurité WebSocket"
description: "Endpoints WebSocket sécurisés : validation d'Origin, auth au handshake, limites de taille/débit de message, wss-only, backoff de reconnexion"
category: prevention
severity: high
applies_to:
  - "lors de la génération d'un server WebSocket / Socket.IO / SignalR"
  - "lors du câblage de messagerie temps réel, presence, ou édition collaborative"
  - "lors de la revue de l'exposition des endpoints /ws ou wss://"
languages: ["javascript", "typescript", "python", "go", "java", "csharp", "ruby", "elixir"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "cors-security", "auth-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP WebSocket Security Cheat Sheet"
  - "RFC 6455 — The WebSocket Protocol"
  - "CWE-1385: Missing Origin Validation in WebSockets"
  - "CWE-770: Allocation of Resources Without Limits or Throttling"
---

# Sécurité WebSocket

## Règles (pour les agents IA)

### TOUJOURS
- Valider le **header `Origin`** sur le handshake d'upgrade
  WebSocket contre une allowlist. CORS ne s'applique **pas** aux
  WebSockets — le browser upgrade joyeusement cross-origin et
  laisse JavaScript sur `attacker.com` ouvrir
  `wss://api.example.com/ws` avec les cookies de l'utilisateur
  (Cross-Site WebSocket Hijacking).
- Exiger l'authentification **sur le handshake** lui-même, pas en
  premier message après le connect. Soit :
  1. Auth basée cookie sur l'upgrade HTTP (et CSRF-protégée en
     vérifiant Origin), ou
  2. Un token signé à durée courte (5–10 min) dans le header de
     subprotocol `Sec-WebSocket-Protocol`, ou
  3. Un token signé en query parameter.
  Ne jamais faire confiance à un message `subscribe` / `auth`
  après l'upgrade — à ce stade la connexion est déjà ouverte avec
  le contexte de cookie authentifié.
- Utiliser **`wss://`** uniquement en production. `ws://` en clair
  sur l'internet ouvert expose les session tokens, le contenu des
  messages et les primitives CSRF à n'importe quel observateur
  on-path.
- Imposer une **taille max de message** côté server (typique :
  32 KiB pour du chat, 256 KiB pour de l'édition collaborative,
  bien plus seulement quand le cas d'usage l'exige et que la
  barre d'auth est haute). Sans limite, un seul socket ouvert
  peut OOM le server.
- Imposer un **rate limit de messages** par connexion (ex. 60
  messages/minute) et un **rate limit de connexion** par IP source
  / par utilisateur authentifié. L'abus en temps réel (spam de
  chat, flood de ping de presence) est une source fréquente de
  DoS.
- Implémenter des **heartbeats ping / pong** (toutes les 20–30 s)
  et fermer la connexion sur pong manqué. Sinon les sockets TCP
  half-open s'accumulent derrière les load balancers.
- Côté client, utiliser un **exponential backoff borné** pour la
  reconnexion (ex. base 1 s, facteur 2, max 60 s, jitter ±20%).
  Une boucle de reconnexion naïve `setTimeout(connect, 0)` fait
  fondre le server pendant les outages.
- Traiter chaque message WebSocket comme une request séparée pour
  les fins de **validation d'input** et d'**autorisation**. Les
  permissions de l'utilisateur peuvent changer après l'ouverture
  du socket (logout, changement de role, lock du compte) —
  re-vérifier à chaque action privilégiée.

### JAMAIS
- Sauter la validation d'Origin parce que « c'est un WebSocket,
  CORS ne s'applique pas ». C'est précisément pour ça qu'il faut
  la faire à la main. L'attaque documentée est Cross-Site
  WebSocket Hijacking, démontrée publiquement en 2013 et toujours
  commune dans les reports bug-bounty 2024.
- Utiliser un session cookie comme token WebSocket longue durée.
  Si la connexion WS est censée survivre à plusieurs tabs /
  pages, émettre un JWT court rafraîchissable dans le subprotocol ;
  ne pas compter sur le fait que le cookie va rester pour toujours.
- Permettre des `subprotocols` arbitraires du client d'influencer
  le routing côté server sans allowlist. La négociation de
  subprotocol est contrôlée par l'attaquant.
- Faire tourner les handlers WebSocket dans le même processus /
  thread pool que les handlers de request HTTP sans sizing limits
  — un WebSocket style slow-loris peut affamer tout le travail
  HTTP.
- Exposer la topologie interne du cluster dans les messages
  WebSocket (ex. `{"server_id": "pod-prod-42"}`). Les IDs
  internes sont du matériel de reconnaissance sur un canal
  temps-réel bavard.

### FAUX POSITIFS CONNUS
- Les endpoints publics de chat / presence intentionnellement
  ouverts à n'importe quel origin doivent quand même imposer des
  rate limits par connexion et un cap par IP source ; ils peuvent
  légitimement permettre `Origin: null` pour les clients desktop /
  mobile.
- Les clients natifs mobile / desktop n'envoient pas de header
  `Origin`. Décider d'avance si on les autorise (et appliquer un
  mode d'auth différent comme device-cert + bearer token) ou si
  on les rejette d'emblée.
- Les WebSockets service-to-service (ex. Kafka WebSocket bridge,
  Apache Pulsar) à l'intérieur d'un VPC privé peuvent légitimement
  utiliser `ws://` avec mTLS géré à la couche réseau.

## Contexte (pour les humains)

Les WebSockets sont le cousin longue-durée d'HTTP. La plupart des
contrôles qu'HTTP a gratuits (CORS, CSP, auth par request) ne
s'appliquent pas out-of-the-box, et les frameworks qui enrobent
les WebSockets derrière une API de plus haut niveau (Socket.IO,
SignalR, Phoenix Channels) cachent le mécanisme d'upgrade
suffisamment pour que les devs oublient de le durcir.

Les deux classes d'incident récurrentes sont :
1. **Cross-Site WebSocket Hijacking** — check d'Origin manquant +
   auth par cookie → attacker.com ouvre un WS avec les cookies de
   l'utilisateur et lit son stream.
2. **Épuisement de ressources** — pas de limite de taille / débit
   / connexion + un protocole bavard → DoS trivial.

Les deux sont des fixes simples, mais les deux sont faciles à
oublier en générant un quick feature de chat / collab. Ce skill
miroite le cheat sheet OWASP plus les must-have opérationnels
(heartbeats, backoff).

## Références

- `rules/websocket_hardening.json`
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Cheat_Sheet.html).
- [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html).
- [Cross-Site WebSocket Hijacking explainer](https://christian-schneider.net/CrossSiteWebSocketHijacking.html).
- [RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455).
