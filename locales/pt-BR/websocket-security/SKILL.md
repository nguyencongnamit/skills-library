---
id: websocket-security
language: pt-BR
source_revision: "4c215e6f"
version: "1.0.0"
title: "Segurança de WebSocket"
description: "Endpoints WebSocket seguros: validação de Origin, auth no handshake, limites de tamanho/taxa de mensagens, wss-only, backoff de reconexão"
category: prevention
severity: high
applies_to:
  - "ao gerar um server WebSocket / Socket.IO / SignalR"
  - "ao ligar mensageria em tempo real, presence, ou edição colaborativa"
  - "ao revisar exposição de endpoints /ws ou wss://"
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

# Segurança de WebSocket

## Regras (para agentes de IA)

### SEMPRE
- Valide o **header `Origin`** no handshake de upgrade do
  WebSocket contra uma allowlist. CORS **não** se aplica a
  WebSockets — o browser felizmente upgrada cross-origin e deixa
  JavaScript em `attacker.com` abrir
  `wss://api.example.com/ws` com as cookies do usuário
  (Cross-Site WebSocket Hijacking).
- Exija autenticação **no handshake** em si, não como primeira
  mensagem depois do connect. Uma de:
  1. Auth baseada em cookie no upgrade HTTP (e protegida contra
     CSRF verificando Origin), ou
  2. Um token assinado de vida curta (5–10 min) no header de
     subprotocol `Sec-WebSocket-Protocol`, ou
  3. Um token assinado em query parameter.
  Nunca confie numa mensagem `subscribe` / `auth` depois do
  upgrade — nesse ponto a conexão já foi aberta com o contexto
  de cookie autenticado.
- Use **`wss://`** somente em produção. `ws://` em texto claro
  sobre a internet aberta expõe session tokens, conteúdo de
  mensagem e primitivas de CSRF para qualquer observador
  on-path.
- Force **tamanho máximo de mensagem** no server (típico:
  32 KiB para chat, 256 KiB para edição colaborativa, mais alto
  só quando o caso de uso exige e a barra de auth é alta). Sem
  um limite, um único socket aberto pode OOM o server.
- Force um **rate limit de mensagens** por conexão (ex.: 60
  mensagens/minuto) e um **rate limit de conexão** por IP de
  origem / por usuário autenticado. Abuso em tempo real (spam de
  chat, flood de ping de presence) é fonte frequente de DoS.
- Implemente **heartbeats ping / pong** (a cada 20–30 s) e feche
  a conexão num pong perdido. Senão, sockets TCP half-open se
  acumulam atrás dos load balancers.
- No client, use **backoff exponencial limitado** para
  reconexão (ex.: base 1 s, fator 2, max 60 s, jitter ±20%). Um
  loop ingênuo `setTimeout(connect, 0)` derrete o server
  durante outages.
- Trate cada mensagem WebSocket como uma request separada para
  fins de **validação de input** e **autorização**. As
  permissões do usuário podem mudar depois do socket ser aberto
  (logout, troca de role, lock de conta) — re-cheque em cada
  ação privilegiada.

### NUNCA
- Pule a validação de Origin porque "é WebSocket, CORS não se
  aplica". Justamente por isso você tem que fazer manual. O
  ataque documentado é Cross-Site WebSocket Hijacking,
  demonstrado publicamente em 2013 e ainda comum em report de
  bug-bounty em 2024.
- Use um session cookie como token WebSocket de longa duração.
  Se a conexão WS é pra sobreviver a múltiplas tabs / páginas,
  emita um JWT curto, refreshable, no subprotocol; não conte que
  a cookie vai ficar grudada pra sempre.
- Deixe `subprotocols` arbitrários do client influenciarem o
  routing server-side sem allowlist. A negociação de
  subprotocol é controlada pelo atacante.
- Rode handlers WebSocket no mesmo processo / pool de threads
  dos handlers de request HTTP sem sizing limits — um WebSocket
  estilo slow-loris pode matar de fome todo o trabalho HTTP.
- Exponha topologia interna do cluster em mensagens WebSocket
  (ex.: `{"server_id": "pod-prod-42"}`). IDs internos são
  material de reconhecimento num canal em tempo real tagarela.

### FALSOS POSITIVOS CONHECIDOS
- Endpoints públicos de chat / presence que são intencionalmente
  abertos a qualquer origin ainda precisam forçar rate limits
  por conexão e um cap por IP de origem; podem legitimamente
  permitir `Origin: null` para clients desktop / mobile.
- Clients nativos mobile / desktop não mandam header `Origin`.
  Decida com antecedência se permite (e aplique um modo de auth
  diferente, tipo device-cert + bearer token) ou rejeita logo.
- WebSockets service-to-service (ex.: Kafka WebSocket bridge,
  Apache Pulsar) dentro de uma VPC privada podem legitimamente
  usar `ws://` com mTLS sendo tratado na camada de rede.

## Contexto (para humanos)

WebSockets são o primo de longa duração do HTTP. A maior parte
dos controles que o HTTP ganha de graça (CORS, CSP, auth por
request) não se aplicam out-of-the-box, e frameworks que
embrulham WebSockets atrás de uma API de mais alto nível
(Socket.IO, SignalR, Phoenix Channels) escondem o mecanismo de
upgrade o suficiente para os devs esquecerem de endurecer.

As duas classes recorrentes de incidente são:
1. **Cross-Site WebSocket Hijacking** — check de Origin
   faltando + auth via cookie → attacker.com abre um WS com as
   cookies do usuário e lê o stream dele.
2. **Exaustão de recursos** — sem limite de tamanho / taxa /
   conexão + protocolo tagarela → DoS trivial.

Os dois são fixes simples, mas os dois são fáceis de esquecer
ao gerar uma feature rápida de chat / colab. Esse skill espelha
o cheat sheet do OWASP mais os must-have operacionais
(heartbeats, backoff).

## Referências

- `rules/websocket_hardening.json`
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Cheat_Sheet.html).
- [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html).
- [Cross-Site WebSocket Hijacking explainer](https://christian-schneider.net/CrossSiteWebSocketHijacking.html).
- [RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455).
