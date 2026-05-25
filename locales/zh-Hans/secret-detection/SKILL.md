---
id: secret-detection
language: zh-Hans
source_revision: "9808b0fa"
version: "1.4.0"
title: "秘密检测"
description: "在代码里检测并阻止硬编码的 secret、API key、token 和凭据"
category: prevention
severity: critical
applies_to:
  - "每次 commit 之前"
  - "review 处理凭据的代码时"
  - "编写配置文件时"
  - "创建 .env 或配置模板时"
languages: ["*"]
token_budget:
  minimal: 800
  compact: 1300
  full: 2000
rules_path: "rules/"
tests_path: "tests/"
related_skills: ["dependency-audit", "supply-chain-security"]
last_updated: "2026-05-14"
sources:
  - "OWASP Secrets Management Cheat Sheet"
  - "CWE-798: Use of Hard-coded Credentials"
  - "CWE-259: Use of Hard-coded Password"
  - "NIST SP 800-57 Part 1 Rev. 5: Key Management"
---

# 秘密检测

## 规则(面向 AI 代理)

### 必须
- 检查所有靠近以下关键词、且长度超过 20 字符的 string literal:
  `api_key`、`secret`、`token`、`password`、`credential`、`auth`、
  `bearer`、`private_key`、`access_key`、`client_secret`、
  `refresh_token`。
- 对匹配已知 secret pattern 的任何字符串发警告。内置 pattern set
  覆盖:AWS(`AKIA...`)、GitHub 经典(`ghp_`、`gho_`)以及
  **细粒度**(`github_pat_`)PAT、OpenAI(`sk-`)、**Anthropic
  (`sk-ant-api03-`)**、Slack(`xox[baprs]-`)、Stripe
  (`sk_live_`)、Google(`AIza...`)、**Azure AD client secret**、
  **Databricks(`dapi`)**、**Datadog 32-hex 配合 hotword**、
  **Twilio(`SK`)**、**SendGrid(`SG.`)**、**npm(`npm_`)**、
  **PyPI 上传(`pypi-AgEI`)**、**Heroku UUID 配合 hotword**、
  **DigitalOcean(`dop_v1_`)**、**HashiCorp Vault(`hvs.`)**、
  **Supabase(`sbp_`)**、**Linear(`lin_api_`)**、JWT,以及
  PEM 私钥。
- 确认 `.gitignore` 包含:`*.pem`、`*.key`、`.env`、`.env.*`、
  `*credentials*`、`*secret*`、`id_rsa*`、`*.ppk`。
- 对任何带 secret 的凭据、连接字符串或 API endpoint,优先使用环境
  变量(`os.environ`、`process.env`、`os.Getenv`)而不是硬编码值。
- 当凭据需要跨机器或服务共享时,建议使用 secrets manager
  (1Password、AWS Secrets Manager、HashiCorp Vault、Doppler)。

### 禁止
- 不要 commit 匹配以下 pattern 的文件:`*.pem`、`*.key`、`*.p12`、
  `*.pfx`、`.env`、`.env.local`、`*credentials*`、`id_rsa`、
  `id_dsa`、`id_ecdsa`、`id_ed25519`。
- 不要在源码里硬编码 API key、token、密码或连接字符串。
- 不要在测试 fixture 里放真 secret —— 用有文档的占位符,例如
  `AKIAIOSFODNN7EXAMPLE`、
  `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` 或
  `xoxb-EXAMPLE-EXAMPLE`。
- 不要打印或记录 secret 值,即使在 debug 模式也不行。
- 不要把 secret 回显到 CI log 的终端里(在 GitHub Actions 里用
  `::add-mask::` 遮蔽)。
- 不要把签名密钥嵌进容器镜像里,哪怕是 base image。

### 已知误报
- AWS 文档示例:`AKIAIOSFODNN7EXAMPLE` 以及对应的 secret access
  key `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`。
- 包含以下字样的字符串:"example"、"test"、"placeholder"、
  "dummy"、"sample"、"changeme"、"your-key-here"、"REPLACE_ME"、
  "TODO"、"FIXME"、"XXX"。
- CSS/SCSS 里的 hash literal(例如 `#ff0000`、`#deadbeef`)。
- 测试里用 base64 编码的非敏感内容(编码过的 lorem ipsum、图像
  fixture)。
- changelog 和 release notes 里的 git commit SHA。
- OAuth RFC 文档示例里的 JWT token(注释中出现的 `eyJ...` 字
  符串)。

## 背景(面向人类)

硬编码 secret 至今仍是最常见的入侵原因之一。GitHub 每年的
"State of the Octoverse" 报告里,secret 泄露持续位列前三大被披露
漏洞类别,而单次 secret 泄露的平均成本(补救 + 轮换 + 影响)还没
算上客户数据,就已经按每事件几万美元来衡量。

AI 编码助手会加剧这个风险,因为阻力最小的路径就是 inline 一个能
跑的凭据并"以后再修"。本 skill 是它的对冲:训练 AI 拒绝这条阻力
最小的路径。

`rules/dlp_patterns.json` 里的检测策略对应那条分层 pipeline,现
在带 **26 个不同的 pattern**,覆盖开发平台(GitHub 细粒度 PAT、
Anthropic、OpenAI、Supabase、Linear)、云(AWS、Azure AD、GCP、
DigitalOcean、Heroku)、数据平台(Databricks、Datadog、HashiCorp
Vault)和通讯(Twilio、SendGrid、Slack)。每个 pattern 都带有严
重程度、hotword、hotword 邻近窗口,以及一个 entropy 下限来提升
精度。
在 [secure-edge ARCHITECTURE.md](https://github.com/kennguy3n/secure-edge/blob/main/ARCHITECTURE.md)
里有记录 —— Aho-Corasick 前缀扫描、对候选做 regex 验证、hotword
邻近、entropy 阈值,以及排除规则 —— 全部为静态分析场景做了适配。

## 参考

- `rules/dlp_patterns.json` —— 机器可读的 pattern,带 Aho-Corasick
  前缀、hotword、entropy 阈值。
- `rules/dlp_exclusions.json` —— 社区维护的误报抑制规则。
- `tests/corpus.json` —— 用于验证的测试 fixture。
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html) —— 使用硬编码凭据。
- [CWE-259](https://cwe.mitre.org/data/definitions/259.html) —— 使用硬编码密码。
