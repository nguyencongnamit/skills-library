---
id: auth-security
language: zh-Hans
source_revision: "afe376a8"
version: "1.0.0"
title: "身份认证与授权安全"
description: "JWT、OAuth 2.0 / OIDC、会话管理、CSRF、密码哈希以及 MFA 强制"
category: prevention
severity: critical
applies_to:
  - "在生成登录 / 注册 / 密码重置流程时"
  - "在生成 JWT 签发或验证时"
  - "在生成 OAuth 2.0 / OIDC 客户端或服务端代码时"
  - "在连接会话 cookie、CSRF 令牌、MFA 时"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1300
  full: 2700
rules_path: "rules/"
related_skills: ["api-security", "crypto-misuse", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "OWASP Authentication Cheat Sheet"
  - "OWASP Session Management Cheat Sheet"
  - "RFC 6749 — OAuth 2.0"
  - "RFC 7519 — JSON Web Token"
  - "RFC 9700 — OAuth 2.0 Security BCP"
  - "NIST SP 800-63B (Authenticator Assurance)"
---

# 身份认证与授权安全

## 规则（面向 AI 代理）

### 必须
- 进行 JWT 验证时,固定预期算法 (`RS256`、`EdDSA` 或 `ES256`),
  并校验 `iss`、`aud`、`exp`、`nbf` 与 `iat`。拒绝 `alg=none` 以及任何
  预期之外的算法。
- 对 OAuth 2.0 公共客户端 (SPA / 移动 / CLI),使用**带 PKCE 的授权码流程**
  (S256)。绝不使用 implicit flow。绝不使用 resource owner password
  credentials grant。
- 会话 cookie:`Secure; HttpOnly; SameSite=Lax`(对敏感流程使用 `Strict`)。
  在没有跨子域共享时使用 `__Host-` 前缀。
- 在登录与权限变更时轮换会话标识符。把会话与 user agent 绑定时,
  只能作为弱信号——绝不作为唯一校验。
- 用 argon2id (m=64 MiB, t=3, p=1) 配合每用户随机盐对密码做哈希。
  Bcrypt cost ≥ 12 或 scrypt N≥2^17 是 legacy 系统可接受的备选。
  PBKDF2-SHA256 至少需要 600,000 次迭代(OWASP 2023 最低要求)。
- 密码长度 ≥ 12 字符,且不施加字符组成规则;允许 Unicode;把候选密码
  与已泄露密码列表 (HIBP / pwned-passwords k-匿名 API) 比对。
- 为密码尝试实现账户锁定*或*限流(NIST SP 800-63B §5.2.2:30 天内最多
  100 次失败)。
- 对所有可从浏览器会话访问、会改变状态的请求实现 CSRF 保护:
  synchronizer token、double-submit cookie,或对高风险端点使用
  `SameSite=Strict`。
- 对管理操作、密码变更、MFA 设备变更、计费变更要求 MFA / step-up。
- 对 OIDC,把发送时的 `nonce` 与 ID token 中的 `nonce` 做校验;
  当存在时校验 `at_hash` / `c_hash`。

### 禁止
- 使用 `Math.random()`(或任何非 CSPRNG)生成会话 ID、重置令牌、
  MFA 恢复码或 API 密钥。
- 接受 `alg=none` 的 JWT;或在签发方用 RS256 签名时接受客户端给的 HS256
  (经典的算法混淆攻击)。
- 用 `==` / `strcmp` 比较密码或令牌哈希;请使用常数时间比较函数。
- 以可逆方式存储密码(加密而不是哈希)。存储必须是单向的。
- 泄露到底是用户名错还是密码错。返回通用的 "invalid credentials"
  信息。
- 把访问令牌、刷新令牌或会话 ID 放进 URL query string ——它们会泄漏到日志、
  Referer 头和浏览器历史里。
- 用 `localStorage` / `sessionStorage` 持有长期刷新令牌。请使用 HttpOnly
  cookie。
- 在 API 层信任客户端提供的角色 / claim ——每次请求都要重新得出已认证主体
  并在服务端查询授权。
- 签发长期(>1 小时)访问令牌;请使用带轮换的刷新令牌。
- 使用 implicit flow 或 password grant。

### 已知误报
- 在密钥管理器中存储、且绑定到具体 workload 身份的服务到服务令牌,
  有时使用较长 TTL 是可接受的。
- 本地开发用、不做密码哈希的 "magic link" 临时用户认证可以接受,
  前提是它被一个环境标志门控,并在生产关闭。
- URL query 里出现令牌仅在*一个*位置可容忍——OAuth 授权码回调——
  因为值是一次性、短期有效的。

## 背景(面向人类)

身份认证缺陷长期出现在 OWASP Top 10 (A07:2021 — Identification and
Authentication Failures) 中。常见模式包括:弱密码存储、可预测的令牌、
缺失 MFA、JWT 配置错误以及会话固定。RFC 9700 (OAuth 2.0 Security BCP)
与 NIST SP 800-63B 是该领域的权威配方。

AI 助手往往交付"在 dev 能跑"的认证:写死密钥的 HS256 JWT、用默认 cost 10
的 `bcrypt.hash`、没有 PKCE、把令牌放进 localStorage。本 skill 就是为了
逐项把这些拦住。

## 参考

- `rules/jwt_safe_config.json`
- `rules/oauth_flows.json`
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
- [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700).
