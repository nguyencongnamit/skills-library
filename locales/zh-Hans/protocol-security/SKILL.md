---
id: protocol-security
language: zh-Hans
source_revision: "afe376a8"
version: "1.0.0"
title: "协议安全"
description: "TLS 1.2+、mTLS、证书校验、HSTS、gRPC 通道凭据、WebSocket Origin 校验"
category: hardening
severity: critical
applies_to:
  - "在生成 HTTP / gRPC / WebSocket / SMTP / 数据库的客户端与服务端时"
  - "在代码或平台 config 中生成 TLS 配置时"
  - "在生成服务对服务的鉴权时"
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

# 协议安全

## 规则(面向 AI 代理)

### 必须
- 新客户端和服务端默认使用 **TLS 1.3**;仅在为兼容遗留对端时才允
  许 TLS 1.2。禁用 TLS 1.0/1.1、SSLv2/v3。
- 校验服务端证书:能链到一个可信 CA、名字匹配预期 hostname(或
  SAN)、未过期、未吊销(启用 OCSP stapling)。
- 在所有用 HTTPS 提供的 HTTP 响应里启用 HSTS:
  `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`。
  稳定后把这个 host 加进 HSTS preload list。
- 在同一个 trust domain 内的服务对服务流量使用 **mutual TLS**
  (mTLS)(网格:Istio / Linkerd;独立部署:SPIFFE / SPIRE
  做身份)。
- gRPC 客户端/服务端要用 `grpc.secure_channel` /
  `grpc.SslCredentials` / `credentials.NewTLS` —— 生产中绝不用
  `insecure_channel`。
- WebSocket 服务端要按 allowlist 校验 `Origin` header,并对握手
  做鉴权(cookie + CSRF token,或在 upgrade 时使用一次性且会重新
  校验的 query-string bearer)。
- 服务对服务的 token,优先使用 **SPIFFE ID**
  (`spiffe://trust-domain/...`)和短期 workload 证书,胜过长期
  API key。
- 对高风险的移动 / 桌面客户端回调到运营方自己的后端时,要对证书
  做 pin(public key pinning)。

### 禁止
- 不要关闭证书校验(`InsecureSkipVerify: true`、`verify=False`、
  `rejectUnauthorized: false`、`CURLOPT_SSL_VERIFYPEER=0`)。唯一
  可接受的场景是 unit test 跑在 localhost 临时 cert 上。
- 不要写一个无条件返回 trusted 的自定义 `X509TrustManager` /
  `HostnameVerifier` / `URLSessionDelegate` /
  `ServerCertificateValidationCallback`。
- 不要在同一个页面上混用 HTTP 和 HTTPS 资源(mixed content)——
  现代浏览器会拦截子资源,但 API 依旧可能被 MITM downgrade。
- 不要把 token / 密码走明文 HTTP —— 哪怕是 dev 的 localhost,除
  非该 dev 环境被明确文档化为与安全无关。
- 生产代码里不要用 `grpc.insecure_channel(...)`。
- 没有 allowlist 就不要信任 `Host` / `X-Forwarded-Host` /
  `Forwarded` header;用 `Host` 拼出的绝对 URL 会带来 host-header
  injection 和 password-reset poisoning。
- 不要在你的 service mesh 里跨 origin 盲目转发进入的
  `Authorization` / `Cookie` header —— 要从 mTLS 或 service token
  重新派生身份。
- 不要在你掌控的客户端上启用 TLS renegotiation;可用时 pin 到
  `tls.NoRenegotiation`。

### 已知误报
- 仅在 localhost 运行、用自签名 cert 且有明确文档说明的 dev 服务
  端是 OK 的;CI 测试跑在 CA 临时签发 cert 上也是 OK 的。
- 一小撮遗留的企业级集成需要 TLS 1.2 + 特定 cipher;把这种例外文
  档化,并把这个集成放到一个 proxy 后面隔离开来。
- 公开的只读 endpoint(例如 status page)出于可缓存性可以合理地走
  HTTP,但 HTTPS 仍然更可取。

## 背景(面向人类)

NIST SP 800-52 Rev. 2 是美国政府权威的 TLS 参考;RFC 8446 就是
TLS 1.3 本身。code review 中反复出现的失败模式是
**`InsecureSkipVerify`**(及其在各语言里的等价物)—— 通常是"为
了让测试跑过"加进去的,然后从来没改回去。

这个 skill 与 `crypto-misuse`(算法选择)和 `auth-security`
(token 发放)自然配对。

## 参考

- `rules/tls_defaults.json`
- `rules/cert_validation_sinks.json`
- [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final).
- [RFC 8446 — TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446).
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html).
- [CWE-295](https://cwe.mitre.org/data/definitions/295.html) — Improper Certificate Validation.
