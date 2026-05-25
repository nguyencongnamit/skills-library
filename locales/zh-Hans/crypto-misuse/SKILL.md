---
id: crypto-misuse
language: zh-Hans
source_revision: "afe376a8"
version: "1.0.0"
title: "密码学误用"
description: "拦截弱算法、可预测 RNG、密钥过短、slow-hash 误用以及非常量时间的比较"
category: prevention
severity: critical
applies_to:
  - "在生成做哈希 / 加密 / 签名的代码时"
  - "在生成比较 secret / MAC / token 的代码时"
  - "在配置 TLS 设置、密钥长度或 RNG 时"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2500
rules_path: "rules/"
related_skills: ["secret-detection", "auth-security", "protocol-security"]
last_updated: "2026-05-13"
sources:
  - "NIST SP 800-131A Rev. 2"
  - "NIST SP 800-57 Part 1 Rev. 5"
  - "OWASP Cryptographic Storage Cheat Sheet"
  - "CWE-327, CWE-338, CWE-916, CWE-208"
---

# 密码学误用

## 规则（面向 AI 代理）

### 必须
- 使用语言/平台自带的密码学库。Python：`cryptography`、`secrets`。
  JavaScript：Web Crypto、`crypto.webcrypto`、Node 的 `crypto`。
  Go：`crypto/*`、`golang.org/x/crypto`。Java：JCE / Bouncy Castle。
  .NET：`System.Security.Cryptography`。
- 使用密码学安全的 RNG：Python `secrets.token_bytes` /
  `secrets.token_urlsafe`,JS `crypto.getRandomValues` /
  `crypto.randomBytes`,Go `crypto/rand.Read`,Java `SecureRandom`。
- 用慢 KDF 哈希密码,目标是生产硬件上 ~100 ms:**argon2id**
  (首选,RFC 9106 参数:m=64 MiB、t=3、p=1)、**scrypt**
  (N=2^17、r=8、p=1)、或 **bcrypt**(cost ≥ 12)。
  始终配合每用户随机 salt。
- 用 AEAD(带认证加密)加密:AES-256-GCM、ChaCha20-Poly1305、或
  AES-256-GCM-SIV。每次加密生成新的随机 nonce。
- 使用 TLS 1.2+(强烈推荐 TLS 1.3)。禁用 TLS 1.0/1.1、SSLv3、
  RC4、3DES 和导出强度密码。
- 用常量时间助手比较 MAC / 签名 / token:`hmac.compare_digest`、
  `crypto.subtle.timingSafeEqual`、`subtle.ConstantTimeCompare`、
  `MessageDigest.isEqual`、`CryptographicOperations.FixedTimeEquals`。
- 非对称密钥:RSA ≥ 3072 位,ECDSA P-256 或 P-384,Ed25519,X25519。

### 禁止
- 在签名、证书、密码存储或消息认证中使用 MD5 或 SHA-1。(明确记录了
  用途之后,在与安全无关的偶发场景中(如 ETag、文件去重)仍可使用。)
- 在新代码中使用 DES、3DES、RC4 或 Blowfish。
- 使用 ECB 模式。在没有对密文做 HMAC 的情况下使用 CBC。在 CTR/GCM
  下复用同一 nonce。
- 用未加 salt 的哈希存密码。把 `sha256(password)` 用于密码存储 ——
  它是快速哈希,暴力破解很容易。
- 在 C / Go 中用 `Math.random()`、Python `random`、`rand()` 生成
  token、ID、nonce 或密码。它们都是可预测的。
- 把 IV/nonce、salt 或 key 硬编码。同一密钥下绝不复用 GCM/Poly1305
  的 nonce。
- 用 `==`、`===`、`strcmp`、`bytes.Equal` 比较 secret —— 它们存在
  时序泄露。
- 自造密码学(自定义 XOR、自定义 HMAC、自定义 Diffie–Hellman、
  自定义签名方案)。请使用经过审计的原语。

### 已知误报
- 在与安全无关的上下文中使用 MD5 / SHA-1:HTTP ETag 计算、内容去重、
  对非敏感数据的缓存键、fixture 指纹。把这些用法标注为
  `// non-security use: ...`。
- 测试向量和 KAT (Known Answer Test) 故意硬编码 IV、key 和明文 ——
  它们属于 `tests/`,不属于生产。
- 老协议互操作:某些行业 / 政府协议仍要求特定的老式密码学算法。
  记录例外,并用 feature flag 隔离。

## 背景(面向人类)

NIST SP 800-131A Rev. 2 是美国政府权威的算法弃用路线图;OWASP 的
密码学存储 cheat sheet 是"应该这样做"的实用伴侣。常见的失败模式:
密码使用快速哈希 (CWE-916)、token 使用可预测 RNG (CWE-338)、
错误的密码学算法选择 (CWE-327)、对 secret 的非常量时间比较
(CWE-208)。

AI 助手往往会复现 2014 年前后 Stack Overflow 上常见的加密示例,这
意味着大量的 `sha256(password)` 和带手工 padding 的 `AES-CBC`。本
skill 是对此的反制。

## 参考

- `rules/algorithm_blocklist.json`
- `rules/key_size_minimums.json`
- [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final).
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).
- [CWE-327](https://cwe.mitre.org/data/definitions/327.html) — 已被攻破或风险高的密码学。
- [CWE-916](https://cwe.mitre.org/data/definitions/916.html) — 密码哈希计算成本不足。
