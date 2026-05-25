---
id: websocket-security
language: es
source_revision: "4c215e6f"
version: "1.0.0"
title: "Seguridad de WebSocket"
description: "Endpoints WebSocket seguros: validación de Origin, auth en el handshake, límites de tamaño/tasa de mensajes, wss-only, backoff de reconexión"
category: prevention
severity: high
applies_to:
  - "al generar un server WebSocket / Socket.IO / SignalR"
  - "al cablear mensajería en tiempo real, presence, o edición colaborativa"
  - "al revisar exposición de endpoints /ws o wss://"
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

# Seguridad de WebSocket

## Reglas (para agentes de IA)

### SIEMPRE
- Validar el **header `Origin`** del handshake de upgrade del
  WebSocket contra una allowlist. CORS **no** aplica a WebSockets — el
  browser felizmente upgradea cross-origin y deja que JavaScript en
  `attacker.com` abra `wss://api.example.com/ws` con las cookies del
  usuario (Cross-Site WebSocket Hijacking).
- Requerir autenticación **en el handshake** mismo, no como primer
  mensaje después del connect. Una de:
  1. Auth basada en cookie en el HTTP upgrade (y protegida contra
     CSRF verificando Origin), o
  2. Un token firmado de vida corta (5–10 min) en el header de
     subprotocol `Sec-WebSocket-Protocol`, o
  3. Un token firmado en query parameter.
  Nunca confiar en un mensaje `subscribe` / `auth` después del
  upgrade — para ese punto la conexión ya se abrió con el contexto
  de cookie autenticada.
- Usar **`wss://`** solamente en producción. `ws://` plano sobre la
  internet pública expone session tokens, contenido de mensajes y
  primitivas de CSRF a cualquier observador en el path.
- Enforzar **tamaño máximo de mensaje** en el server (típico: 32 KiB
  para chat, 256 KiB para edición colaborativa, más alto solo si el
  caso de uso lo demanda y la barra de auth es alta). Sin un límite,
  un solo socket abierto puede hacer OOM al server.
- Enforzar un **límite de tasa de mensajes** por conexión (ej. 60
  mensajes/minuto) y un **límite de tasa de conexión** por IP de
  origen / por usuario autenticado. Abuso en tiempo real (spam de
  chat, flood de pings de presence) es una fuente frecuente de DoS.
- Implementar **heartbeats ping / pong** (cada 20–30 s) y cerrar la
  conexión en pong perdido. Si no, sockets TCP half-open se acumulan
  detrás de los load balancers.
- Del lado del cliente, usar **exponential backoff acotado** para
  reconexión (ej. base 1 s, factor 2, max 60 s, jitter ±20%). Un
  loop naive `setTimeout(connect, 0)` derrite al server durante
  outages.
- Tratar cada mensaje WebSocket como un request separado para los
  fines de **validación de input** y **autorización**. Los permisos
  del usuario pueden cambiar después de que el socket está abierto
  (logout, cambio de rol, lock de cuenta) — re-chequear en cada
  acción privilegiada.

### NUNCA
- Saltarse la validación de Origin porque "es un WebSocket, CORS no
  aplica". Justamente por eso hay que hacerlo a mano. El ataque
  documentado es Cross-Site WebSocket Hijacking, demostrado
  públicamente en 2013 y todavía común en reportes de bug-bounty
  en 2024.
- Usar una session cookie como token WebSocket de larga vida. Si se
  espera que la conexión WS sobreviva múltiples tabs / páginas,
  emitir un JWT corto y refrescable en el subprotocol; no confiar
  en que la cookie va a quedarse para siempre.
- Permitir `subprotocols` arbitrarios del cliente que influyan en
  el routing del server sin una allowlist. La negociación de
  subprotocol está controlada por el atacante.
- Correr handlers de WebSocket en el mismo proceso / pool de threads
  que los handlers de request HTTP sin sizing limits — un WebSocket
  estilo slow-loris puede matar de hambre todo el trabajo HTTP.
- Exponer topología interna del cluster en mensajes WebSocket (ej.
  `{"server_id": "pod-prod-42"}`). Los IDs internos son material de
  reconocimiento en un canal en tiempo real verboso.

### FALSOS POSITIVOS CONOCIDOS
- Endpoints públicos de chat / presence que están intencionalmente
  abiertos a cualquier origin todavía deben enforzar rate limits por
  conexión y un cap por IP de origen; pueden legítimamente permitir
  `Origin: null` para clientes desktop / mobile.
- Clientes nativos mobile / desktop no mandan header `Origin`.
  Decidir de antemano si permitirlos (y aplicar un modo de auth
  distinto, como device-cert + bearer token) o rechazarlos sin más.
- WebSockets service-to-service (ej. Kafka WebSocket bridge,
  Apache Pulsar) dentro de una VPC privada pueden legítimamente
  usar `ws://` con mTLS manejado en la capa de red.

## Contexto (para humanos)

Los WebSockets son el primo de vida larga de HTTP. La mayoría de los
controles que HTTP recibe gratis (CORS, CSP, auth por request) no
aplican out-of-the-box, y los frameworks que envuelven WebSockets
detrás de una API de más alto nivel (Socket.IO, SignalR, Phoenix
Channels) esconden el mecanismo de upgrade lo suficiente como para
que los devs se olviden de endurecerlo.

Las dos clases recurrentes de incidente son:
1. **Cross-Site WebSocket Hijacking** — Origin check faltante + auth
   por cookie → attacker.com abre un WS con las cookies del usuario
   y lee su stream.
2. **Agotamiento de recursos** — sin límite de tamaño / tasa /
   conexión + un protocolo verboso → DoS trivial.

Ambos son fixes simples, pero ambos son fáciles de olvidar al
generar un feature rápido de chat / colab. Este skill espeja el
cheat sheet de OWASP más los must-haves operacionales (heartbeats,
backoff).

## Referencias

- `rules/websocket_hardening.json`
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Cheat_Sheet.html).
- [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html).
- [Cross-Site WebSocket Hijacking explainer](https://christian-schneider.net/CrossSiteWebSocketHijacking.html).
- [RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455).
