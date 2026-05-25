---
id: cors-security
language: zh-Hans
source_revision: "afe376a8"
version: "1.0.0"
title: "CORS 安全"
description: "严格 CORS 配置:带凭据时不允许通配符,来源走 allowlist,合理的 preflight 缓存,最小化的暴露 header"
category: prevention
severity: high
applies_to:
  - "在生成 CORS 中间件或框架配置时"
  - "在连接 API Gateway / CloudFront / Nginx 的 CORS header 时"
  - "在评审面向浏览器的跨源端点时"
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

# CORS 安全

## 规则（面向 AI 代理）

### 必须
- 来源使用 **allowlist**,不要用 `*`。仅当传入的 `Origin` 与配置中已知
  条目(或运营方控制的主机名预编译正则)匹配时,才回显该 header。
- 当响应包含凭据(cookie、`Authorization`)时,既要设置
  `Access-Control-Allow-Credentials: true`,**又**要保证
  `Access-Control-Allow-Origin` 是单一明确的来源字符串 —— 决不能是 `*`。
- 当响应正文依赖请求的 `Origin` 时,在响应中包含 `Vary: Origin`,以免
  缓存把一个来源的响应发给另一个来源。
- 把 preflight 的 `Access-Control-Allow-Methods` 限制为该端点实际接受的
  方法;把 `Access-Control-Allow-Headers` 限制为实际消费的 header。
- 把 `Access-Control-Max-Age` 设为合理值(生产环境 ≤ 86400),既能摊
  平 preflight 的延迟,又不至于把错的 allowlist 长期固化。
- 在代码(或版本化的配置文件)中维护 allowlist,而不是从数据库派生 ——
  这样攻击者就不能通过插入一行数据加入自己的来源。

### 禁止
- 不要把 `Access-Control-Allow-Origin: *` 与
  `Access-Control-Allow-Credentials: true` 同时设置。Fetch 规范明令禁止
  —— 浏览器会拒绝响应,但更大的问题是上游 proxy / 缓存可能已经把它
  泄露了。
- 不要在没有 allowlist 校验的情况下回显 `Origin` header(对任何传入
  来源都返回 `Access-Control-Allow-Origin: <Origin>`)。对凭据而言,这
  与 `*` 等价,而且缓存行为更糟。
- 不要把 `null` 当作合法 Origin。Chrome 在 sandboxed iframe、`data:`
  URI 和 `file://` 下会发送 `null` —— 这些都不应当带凭据访问你的 API。
- 不要用 `.*\.example\.com$` 之类的正则放行任意子域,而不考虑子域劫持。
  把具体子域显式 pin 下来;把 `*.example.com` 视作与子域所有权控制绑
  在一起的有意决定。
- 不要通过 `Access-Control-Expose-Headers` 暴露内部 header。仅暴露前端
  真正需要的最小集合。
- 不要把 CORS 当作授权机制。CORS 是*浏览器*策略;它无法挡住
  server-to-server、curl 或非浏览器客户端。请做正经的请求认证。

### 已知误报
- 真正公开、无需鉴权的 API(如开放数据、营销 CDN 端点)合法地可以在
  *没有*凭据的情况下使用 `Access-Control-Allow-Origin: *`。
- 仅限私有网络访问的内部管理工具可以使用单一固定 Origin;通配符的担忧
  在这里不适用,因为不存在跨源调用方。
- 少数集成 (Stripe.js、Plaid、Auth0) 期望特定的 CORS header —— 在放宽
  基线之前阅读各家供应商的 CORS 章节。

## 背景(面向人类)

CORS 常被误解为安全控制。它不是 —— 它是 same-origin policy 的
*放宽*。真正的安全控制是认证。CORS 配置错误之所以重要,是因为它在与
cookie 或 `Authorization` header 结合时,会让不可信来源具备发起带凭据
跨源请求并读取响应的能力。

本 skill 故意写得很短 —— 错误组合的矩阵是有限的,规则也很直接。

## 参考

- `rules/cors_safe_config.json`
- [OWASP CORS Origin Header Scrutiny](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny).
- [CWE-942](https://cwe.mitre.org/data/definitions/942.html).
- [Fetch — CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol).
