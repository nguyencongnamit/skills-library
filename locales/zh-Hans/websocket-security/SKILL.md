---
id: websocket-security
language: zh-Hans
source_revision: "4c215e6f"
version: "1.0.0"
title: "WebSocket 安全"
description: "WebSocket endpoint 加固:Origin 校验、握手时认证、消息大小 / 速率限制、wss-only、重连退避"
category: prevention
severity: high
applies_to:
  - "生成 WebSocket / Socket.IO / SignalR 服务器时"
  - "接入实时消息、presence 或协作编辑时"
  - "review /ws 或 wss:// endpoint 暴露面时"
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

# WebSocket 安全

## 规则(面向 AI 代理)

### 必须
- 在 WebSocket upgrade 握手时拿 allowlist 校验 **`Origin` header**。
  CORS **不** 适用于 WebSocket —— 浏览器会很欢乐地跨源 upgrade,
  让 `attacker.com` 上的 JavaScript 拿用户的 cookie 去开
  `wss://api.example.com/ws`(Cross-Site WebSocket Hijacking)。
- 把认证做在 **握手本身** 上,而不是 connect 之后的第一条消息。
  三选一:
  1. HTTP upgrade 上的 cookie 认证(并通过校验 Origin 来防
     CSRF),或
  2. 在 `Sec-WebSocket-Protocol` subprotocol header 里放一个短
     时效(5–10 分钟)的签名 token,或
  3. 一个签名过的 query parameter token。
  绝不要信任 upgrade 之后才来的 `subscribe` / `auth` 消息 ——
  那时连接已经带着已认证 cookie 上下文开起来了。
- 生产环境只用 **`wss://`**。公网上的明文 `ws://` 会把 session
  token、消息内容和 CSRF 原语暴露给任何在路径上的观测者。
- 服务端强制 **消息最大大小**(典型值:聊天 32 KiB,协作编辑
  256 KiB,只有用例确实需要、且认证门槛足够高时才更大)。没有
  限制的话,一个开着的 socket 就能让服务端 OOM。
- 每条连接强制 **消息速率上限**(例如 60 条/分钟),按源 IP /
  按已认证用户强制 **连接速率上限**。实时滥用(聊天 spam、
  presence ping flood)是常见的 DoS 来源。
- 实现 **ping / pong 心跳**(每 20–30 秒),pong 丢失就关连接。
  否则 half-open TCP socket 会在负载均衡器后面堆积。
- 客户端用 **有界指数退避** 重连(例如 base 1s、factor 2、
  max 60s、jitter ±20%)。朴素的 `setTimeout(connect, 0)` 重
  连循环在故障期间会把服务端熔掉。
- 把每条 WebSocket 消息当作单独 request 来做 **输入校验** 和
  **授权**。socket 开起来之后,用户权限可能变(登出、改 role、
  账号被锁),每个特权动作上都要重新核对。

### 禁止
- 不要因为"这是 WebSocket,CORS 不适用"就跳过 Origin 校验。
  恰恰因为如此你才要自己做。这种攻击有名字,叫 Cross-Site
  WebSocket Hijacking,2013 年就公开演示过,到 2024 年的赏金
  报告里还在反复出现。
- 不要把 session cookie 当作长期的 WebSocket token。如果 WS
  连接需要跨多个 tab / 页面存活,在 subprotocol 里下发一个可
  刷新的短时效 JWT;不要依赖 cookie 永远在。
- 不要让 client 任意 `subprotocols` 在没有 allowlist 的情况下
  影响服务端 routing。subprotocol 协商是攻击者可控的。
- 不要把 WebSocket handler 跟 HTTP request handler 放在同一个
  进程 / 线程池里、又不做 sizing 限制 —— slow-loris 风格的
  WebSocket 能把整个 HTTP 工作饿死。
- 不要在 WebSocket 消息里暴露集群内部拓扑(例如
  `{"server_id": "pod-prod-42"}`)。在一个话痨的实时通道上,
  内部 ID 就是侦察素材。

### 已知误报
- 故意对任意 origin 开放的公开聊天 / presence endpoint 仍然必
  须强制单连接速率限制和按源 IP cap;它们可以合理地允许
  桌面 / 移动端的 `Origin: null`。
- 移动 / 桌面原生客户端不发 `Origin` header。要事先决定是允许
  它们(并改用 device-cert + bearer token 这种不同的认证方式),
  还是直接拒绝。
- 私有 VPC 内的服务到服务 WebSocket(例如 Kafka WebSocket
  bridge、Apache Pulsar)可以合理使用 `ws://`,由网络层处理
  mTLS。

## 背景(面向人类)

WebSocket 是 HTTP 的长寿命表亲。HTTP 自带的大多数控制
(CORS、CSP、按 request 认证)在 WebSocket 上并不会开箱即用,
而那些把 WebSocket 包在更高层 API 后面的框架(Socket.IO、
SignalR、Phoenix Channels)又把 upgrade 机制藏得太深,以至于
开发者会忘了去加固它。

两类反复出现的事故是:
1. **Cross-Site WebSocket Hijacking** —— 没做 Origin 校验 +
   cookie 认证 → attacker.com 拿着用户的 cookie 开一个 WS,
   把用户的流读走。
2. **资源耗尽** —— 没有大小 / 速率 / 连接限制 + 一个话痨协议
   → 轻易 DoS。

两类修复都很简单,但两类在临时写一个聊天 / 协作 feature 时
都很容易忘。本 skill 镜像 OWASP cheat sheet,外加运维必需项
(心跳、退避)。

## 参考

- `rules/websocket_hardening.json`
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Cheat_Sheet.html).
- [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html).
- [Cross-Site WebSocket Hijacking explainer](https://christian-schneider.net/CrossSiteWebSocketHijacking.html).
- [RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455).
