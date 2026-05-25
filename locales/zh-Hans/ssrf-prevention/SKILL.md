---
id: ssrf-prevention
language: zh-Hans
source_revision: "4c215e6f"
version: "1.0.0"
title: "SSRF 防御"
description: "防御 Server-Side Request Forgery:云 metadata 拦截、内网 IP 过滤、DNS rebinding 防护、基于 allowlist 的 URL 拉取"
category: prevention
severity: critical
applies_to:
  - "生成会去拉取客户端提供 URL 的代码时"
  - "接入 webhook、图像代理、PDF renderer、oEmbed fetcher 时"
  - "运行在任何带 instance metadata service 的云环境中时"
  - "review URL 解析或 HTTP client 封装时"
languages: ["*"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "cors-security", "infrastructure-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP SSRF Prevention Cheat Sheet"
  - "CWE-918: Server-Side Request Forgery"
  - "Capital One 2019 breach post-mortem (IMDSv1 SSRF)"
  - "AWS IMDSv2 documentation"
  - "PortSwigger Web Security Academy — SSRF labs"
---

# SSRF 防御

## 规则(面向 AI 代理)

### 必须
- 替客户端发出的 **每一个** URL 都必须经过预期主机的 **allowlist**
  校验。allowlist 是唯一稳健的防御 —— blocklist 会被编码 trick、
  IPv6 双栈和 DNS rebinding 绕过。
- hostname 只解析 **一次**,把解析出的 IP 跟你列出的私网 / 保留 /
  link-local 段 blocklist 比对,然后用 SNI 连接到那个钉死的 IP。
  否则攻击者可以在校验和 connect 之间做 DNS rebind race
  (`time-of-check / time-of-use`)。
- **既** 在网络层 **也** 在应用层拦。从任何不合法需要 metadata
  service 的服务里,丢弃到 `169.254.169.254`、`[fd00:ec2::254]`、
  `metadata.google.internal` 和 `100.100.100.200` 的 egress。
- AWS EC2 上强制 **IMDSv2**(session-token,hop-limit=1)。IMDSv1
  —— 2019 年 Capital One 入侵利用的就是这个 pattern —— 必须在实例
  级别禁用。
- 服务端 fetcher 默认关闭 HTTP redirect(或者只允许跟随一个小的
  有界次数,每一跳都把新 URL 重新拿 allowlist 校验)。最常见的
  SSRF 绕过就是 `https://allowed.example.com` 返回一个 302 指到
  `http://169.254.169.254/...`。
- 对 *用户控制* URL 与 *内部* URL 分别使用两个独立、受限的 HTTP
  client。用错 client 时必须 fail closed(例如在 Go / Rust /
  TypeScript 里通过类型系统区分)。
- 用单一、有名的 parser 解析 URL(Go 的 `net/url.Parse`、Python 的
  `urllib.parse`、JavaScript 的 `new URL()`)。WHATWG 和 RFC-3986
  之类的差分 parser 是一类有据可查的 SSRF 绕过路径。

### 禁止
- 不要信任用户传入的 hostname / IP。始终在你信任的 resolver 里重新
  解析,并重新校验解析后的地址。
- 当协议允许 redirect 时,不要凭 hostname 就直接连过去 ——
  `gopher://`、`dict://`、`file://`、`jar://`、`netdoc://`、
  `ldap://` 全都是常见的 SSRF 放大器。限制只允许 `http://` 和
  `https://`(`ftp://` 只在真的需要时)。
- 不要信任 `0.0.0.0`、`127.0.0.1`、`[::]`、`[::1]`、`localhost`、
  `*.localhost.test` —— 它们都能到本机实例。这个名单还必须包括
  link-local `169.254.0.0/16`、IPv4 映射的 IPv6
  `::ffff:127.0.0.1`,以及 IPv6 ULA `fc00::/7`。
- 不要在日志行或错误响应里使用用户那段 URL 字符串 —— 它可能正是
  把盲 SSRF 变成数据外泄 SSRF 的反射 oracle。
- 不要把屏蔽 metadata 的 sidecar / proxy 当作 **唯一** 的防御 ——
  找到 Unix-domain-socket 伪 URL 或配置错误 hostname 的攻击者
  可以绕过 proxy。应用层 allowlist 仍然不可或缺。
- 不要在不做规范化的情况下允许用户 URL 里出现 IDN / Punycode ——
  IDN 同形字攻击会绕过朴素的字符串 allowlist 检查(西里尔字母 o 的
  `gооgle.com` ≠ `google.com`)。

### 已知误报
- 双方都由运维控制、URL 在配置里硬编码(并非用户提供)的
  server-to-server 集成 —— 这里的 allowlist 就是静态配置本身。
- Kubernetes 集群内的 service-to-service 调用 —— 它们不经过用户
  输入,但要留意任何跨 namespace 的 network policy。
- 出站到客户端的 webhook(例如 Slack、Discord、Microsoft Teams
  webhook)。校验 URL host 是否在该集成的文档化 allowlist 里,而
  不是任意 host。

## 背景(面向人类)

SSRF 现在已经是云端入侵事实上的入口向量。链路是:用户提供一个
URL → server 去拉 → server 自带凭据(云 metadata IAM、内部
admin API、RPC endpoint) → 攻击者偷走凭据。2019 年 Capital One
入侵(8000 万客户记录)就是 SSRF + IMDSv1 外泄的教科书案例。
修复方法简单、文档化也齐全;之所以模式还在反复出现,是因为 URL
拉取在大多数代码库里只是一个小角落。

本 skill 强调 DNS-rebinding 和 redirect-bypass 这两类,是因为
AI 生成的 URL 校验在这两类上最常翻车 —— 把
169.254.169.254 显式拉黑很容易,但 "解析后再钉死再连"
(allow-only-after-resolve-and-pin)这个 pattern 需要更多思考。

## 参考

- `rules/ssrf_sinks.json`
- `rules/cloud_metadata_endpoints.json`
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
- [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
- [Capital One 2019 breach DOJ filing](https://www.justice.gov/usao-wdwa/press-release/file/1188626/download).
- [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html).
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf).
