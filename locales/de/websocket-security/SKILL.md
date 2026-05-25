---
id: websocket-security
language: de
source_revision: "4c215e6f"
version: "1.0.0"
title: "WebSocket-Security"
description: "Sichere WebSocket-Endpoints: Origin-Validierung, Auth beim Handshake, Message-Größen-/Rate-Limits, wss-only, Reconnect-Backoff"
category: prevention
severity: high
applies_to:
  - "beim Generieren eines WebSocket- / Socket.IO- / SignalR-Servers"
  - "beim Verdrahten von Real-time-Messaging, Presence oder kollaborativem Editing"
  - "beim Review der Exposition von /ws- oder wss://-Endpoints"
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

# WebSocket-Security

## Regeln (für KI-Agenten)

### IMMER
- Den **`Origin`-Header** beim WebSocket-Upgrade-Handshake gegen
  eine Allowlist validieren. CORS gilt **nicht** für WebSockets —
  der Browser upgraded fröhlich cross-origin und lässt JavaScript
  auf `attacker.com` `wss://api.example.com/ws` mit den Cookies
  des Nutzers öffnen (Cross-Site WebSocket Hijacking).
- Authentifizierung **am Handshake selbst** verlangen, nicht als
  erste Message nach dem Connect. Entweder:
  1. Cookie-basierte Auth beim HTTP-Upgrade (und CSRF-Schutz via
     Origin-Verifikation), oder
  2. Ein kurzlebiges signiertes Token (5–10 min Lifetime) im
     `Sec-WebSocket-Protocol`-Subprotocol-Header, oder
  3. Ein signiertes Query-Parameter-Token.
  Niemals einer `subscribe`- / `auth`-Message nach dem Upgrade
  vertrauen — zu dem Zeitpunkt ist die Verbindung schon mit dem
  authentifizierten Cookie-Kontext offen.
- In Produktion ausschließlich **`wss://`** verwenden. Klartext-
  `ws://` über das offene Internet exponiert Session-Tokens,
  Message-Inhalte und CSRF-Primitive an jeden On-Path-Beobachter.
- **Maximale Message-Größe** am Server erzwingen (typisch: 32 KiB
  für Chat, 256 KiB für kollaboratives Editing, höher nur wenn der
  Use Case es verlangt und die Auth-Hürde hoch ist). Ohne Limit
  kann ein einziger offener Socket den Server OOM-killen.
- Ein **Message-Rate-Limit** pro Connection (z. B. 60 Messages/
  Minute) und ein **Connection-Rate-Limit** pro Source-IP / pro
  authentifiziertem Nutzer erzwingen. Real-Time-Missbrauch
  (Chat-Spam, Presence-Ping-Flood) ist eine häufige DoS-Quelle.
- **Ping- / Pong-Heartbeats** implementieren (alle 20–30 s) und
  die Verbindung bei verpasstem Pong schließen. Sonst sammeln sich
  Half-open-TCP-Sockets hinter Load Balancern an.
- Auf Client-Seite **bounded exponential Backoff** für
  Reconnection (z. B. Base 1 s, Faktor 2, Max 60 s, Jitter ±20%).
  Eine naive `setTimeout(connect, 0)`-Reconnect-Loop schmilzt den
  Server während Outages.
- Jede WebSocket-Message als separaten Request für Zwecke der
  **Input-Validation** und **Authorisierung** behandeln. Die
  Permissions des Nutzers können sich nach dem Öffnen des Socket
  ändern (Logout, Rollenwechsel, Account-Lock) — bei jeder
  privilegierten Aktion neu prüfen.

### NIE
- Origin-Validierung überspringen, weil „es ist ein WebSocket, CORS
  gilt nicht". Genau deshalb muss man sie selbst machen. Der
  dokumentierte Angriff ist Cross-Site WebSocket Hijacking, 2013
  öffentlich demonstriert und 2024 immer noch häufig in
  Bug-Bounty-Reports.
- Ein Session-Cookie als langlebiges WebSocket-Token verwenden.
  Soll die WS-Verbindung mehrere Tabs / Seiten überleben, ein
  refreshbares kurzlebiges JWT im Subprotocol ausstellen; nicht
  darauf verlassen, dass das Cookie ewig hängen bleibt.
- Beliebige `subprotocols` vom Client serverseitiges Routing
  beeinflussen lassen ohne Allowlist. Subprotocol-Verhandlung ist
  vom Angreifer kontrolliert.
- WebSocket-Handler im selben Prozess / Thread-Pool wie HTTP-
  Request-Handler ohne Sizing-Limits laufen lassen — ein
  Slow-Loris-Style-WebSocket kann die gesamte HTTP-Arbeit
  aushungern.
- Interne Cluster-Topologie in WebSocket-Messages exponieren
  (z. B. `{"server_id": "pod-prod-42"}`). Interne IDs sind
  Aufklärungsmaterial auf einem geschwätzigen Real-Time-Channel.

### BEKANNTE FALSCH-POSITIVE
- Öffentliche Chat- / Presence-Endpoints, die absichtlich für
  jeden Origin offen sind, müssen trotzdem Per-Connection-Rate-
  Limits und einen Per-Source-IP-Cap erzwingen; sie dürfen
  legitim `Origin: null` für Desktop- / Mobile-Clients erlauben.
- Mobile- / Desktop-Native-Clients senden keinen `Origin`-Header.
  Im Voraus entscheiden, ob sie erlaubt sind (und einen anderen
  Auth-Modus wie Device-Cert + Bearer-Token anwenden) oder direkt
  abgelehnt werden.
- Service-zu-Service-WebSockets (z. B. Kafka-WebSocket-Bridge,
  Apache Pulsar) innerhalb einer privaten VPC dürfen legitim
  `ws://` mit mTLS auf Netzwerk-Layer benutzen.

## Kontext (für Menschen)

WebSockets sind der langlebige Cousin von HTTP. Die meisten
Controls, die HTTP gratis bekommt (CORS, CSP, Per-Request-Auth),
gelten nicht out-of-the-box, und Frameworks, die WebSockets hinter
einer Higher-Level-API verpacken (Socket.IO, SignalR, Phoenix
Channels), verstecken den Upgrade-Mechanismus genug, dass
Entwickler vergessen, ihn zu härten.

Die zwei wiederkehrenden Incident-Klassen sind:
1. **Cross-Site WebSocket Hijacking** — fehlender Origin-Check +
   Cookie-Auth → attacker.com öffnet einen WS mit den Cookies des
   Nutzers und liest dessen Stream.
2. **Resource-Exhaustion** — kein Size-/Rate-/Connection-Limit +
   ein geschwätziges Protokoll → trivialer DoS.

Beides sind simple Fixes, aber beides ist leicht zu vergessen,
wenn man schnell ein Chat- / Collab-Feature generiert. Dieser
Skill spiegelt das OWASP-Cheat-Sheet plus die operativen
Must-haves (Heartbeats, Backoff).

## Referenzen

- `rules/websocket_hardening.json`
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Cheat_Sheet.html).
- [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html).
- [Cross-Site WebSocket Hijacking explainer](https://christian-schneider.net/CrossSiteWebSocketHijacking.html).
- [RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455).
