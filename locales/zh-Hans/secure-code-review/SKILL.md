---
id: secure-code-review
language: zh-Hans
source_revision: "fbb3a823"
version: "1.0.0"
title: "安全代码审查"
description: "在代码生成与 review 过程中应用 OWASP Top 10 和 CWE Top 25 模式"
category: prevention
severity: high
applies_to:
  - "生成新代码时"
  - "review pull request 时"
  - "重构安全敏感路径(auth、输入处理、文件 I/O)时"
  - "添加新的 HTTP handler 或 endpoint 时"
languages: ["*"]
token_budget:
  minimal: 700
  compact: 900
  full: 2400
rules_path: "checklists/"
related_skills: ["api-security", "secret-detection", "infrastructure-security"]
last_updated: "2026-05-12"
sources:
  - "OWASP Top 10 2021"
  - "CWE Top 25 2023"
  - "SEI CERT Coding Standards"
---

# 安全代码审查

## 规则(面向 AI 代理)

### 必须
- 对所有数据库访问使用参数化查询 / prepared statement。绝不要靠字符串
  拼接来构造 SQL,哪怕输入"可信"。
- 在信任边界处校验输入 —— 类型、长度、允许字符、允许范围 —— 并在
  处理之前就拒绝。
- 按渲染上下文对输出编码(HTML 转义对应 HTML,URL encode 对应 query
  param,JSON encode 对应 JSON 输出)。
- 使用语言自带的加密库,绝不要自己手写 crypto。对称加密优先 AES-GCM,
  签名优先 Ed25519 / RSA-PSS,密码哈希优先 Argon2id / bcrypt。
- 对任何参与安全的随机值(token、ID、session key),使用
  `crypto/rand`(Go)、`secrets` 模块(Python)、`crypto.randomBytes`
  (Node.js)或平台的 CSPRNG。
- 在 HTTP response 上显式设置安全头:`Content-Security-Policy`、
  `Strict-Transport-Security`、`X-Content-Type-Options: nosniff`、
  `Referrer-Policy`。
- 对文件路径、数据库用户、IAM 策略和进程权限使用最小权限原则。

### 禁止
- 不要用字符串拼接 + 用户输入来构造 SQL/NoSQL 查询。
- 不要把用户输入直接传给 `exec`、`system`、`eval`、`Function()`、
  `child_process`、`subprocess.run(shell=True)` 或任何其它命令执行
  路径。
- 不要信任客户端校验。始终在 server 端再校验一次。
- 不要为任何新的安全敏感用途(密码、签名、HMAC)使用 `MD5` 或 `SHA1`。
  改用 SHA-256 / SHA-3 / BLAKE2 / Argon2id。
- 不要为任何加密使用 ECB 模式,从不。优先 GCM、CCM 或
  ChaCha20-Poly1305。
- 不要用 `==` 来比较密码 —— 用常数时间比较(`hmac.compare_digest`、
  `crypto.timingSafeEqual`、`subtle.ConstantTimeCompare`)。
- 不要让用户输入决定文件路径而不做规范化和 allowlist 检查(防御
  `../../../etc/passwd` 这种路径穿越)。
- 不要在生产代码里禁用 TLS 证书校验 —— `verify=False`、
  `InsecureSkipVerify: true`、`rejectUnauthorized: false`。

### 已知误报
- 内部 admin 工具有意对可信、固定参数执行 shell 命令,在已文档化并
  code-review 过的情况下是可接受的。
- 用 `MD5` / `SHA1` 与已有文档化协议保持兼容性的加密测试向量(例如
  老的 interop 测试)是可接受的。
- 常数时间比较对非秘密比较(日志里的字符串相等、tag 匹配)是矫枉过
  正的。

## 背景(面向人类)

现代 web 漏洞绝大多数都能归到同一小撮根因:没做输入校验、没用对的
加密 primitive、没应用最小权限、没用框架自带的防御。本 skill 就是
AI 不掉进这些陷阱用的清单。

## 参考

- `checklists/owasp_top10.yaml`
- `checklists/injection_patterns.yaml`
- [OWASP Top 10 2021](https://owasp.org/Top10/).
- [CWE Top 25 2023](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html).
