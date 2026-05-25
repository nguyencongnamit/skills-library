---
id: logging-security
language: zh-Hans
source_revision: "afe376a8"
version: "1.0.0"
title: "日志安全"
description: "防止 secret / PII 出现在日志中、防御 log-injection 攻击、避免缺失 audit trail 与过弱的留存策略"
category: prevention
severity: high
applies_to:
  - "在生成 logger 调用或结构化日志 schema 时"
  - "在配置 log shipper、sink、留存与访问控制时"
  - "在审查 audit logging 需求时"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2400
rules_path: "rules/"
related_skills: ["secret-detection", "error-handling-security", "compliance-awareness"]
last_updated: "2026-05-13"
sources:
  - "OWASP Logging Cheat Sheet"
  - "CWE-532 — Insertion of Sensitive Information into Log File"
  - "CWE-117 — Improper Output Neutralization for Logs"
  - "NIST SP 800-92 (Guide to Computer Security Log Management)"
---

# 日志安全

## 规则（面向 AI 代理）

### 必须
- 用**结构化格式**(JSON 或 logfmt)记录日志,字段名要稳定。需要包
  含 `timestamp`、`service`、`version`、`level`、`trace_id`、
  `span_id`、`user_id`(已认证时)、`request_id`、`event`。
- 在日志到达 sink 之前,要让每条日志先经过一个**脱敏器**:密码、
  token、API key、cookie、含有 `?token=` 的完整 URL,以及常见 PII
  模式(类 SSN、类信用卡号,邮箱可选)。
- 对任何受用户控制的字符串,在打日志前先清理换行 / 控制字符
  (CWE-117):替换掉 `\n`、`\r`、`\t`,让攻击者无法注入伪造的日志
  行。
- 把安全相关的事件作为**不可变的审计记录**记录下来:登录成功 /
  失败、MFA 挑战、改密码、改角色、授予 / 撤销访问、数据导出、管
  理员操作。审计记录有更长的留存和更严格的访问控制。
- 按数据类别(而不是全局)设置留存:debug 短、审计长、超过用户同
  意期限的 PII 不要留。
- 把日志发到集中式、append-only 的存储(Cloud Logging、
  CloudWatch、Elastic、Loki),读权限限定在 engineering / SecOps。
- 对某个服务"日志缺失"(静默失败)和日志量异常(10× 飙升或 10×
  下降)告警。

### 禁止
- 不要在 INFO 级别记录完整的 request / response body。Body 里经
  常含有密码、token、PII 和上传的文件。
- 不要记录 `Authorization` header、`Cookie` / `Set-Cookie`
  header、query-string 中的 token,以及任何名为 `password`、
  `secret`、`token`、`key`、`private`、`credential` 的字段 ——
  哪怕事先用 `***` 这样"打码"也不行。
- 不要把已绑定参数值的完整 SQL 语句记下来;改为记录"模板 + 参数
  *名* + 该值的 hash 标识符"。
- 不要让无特权用户能读到含其他用户数据的原始日志。
- 在生产服务中,不要用裸的 `print()` / `console.log` /
  `fmt.Println`;用统一配置的 logger,让脱敏和结构都一致生效。
- 不要为了"减噪声"而关掉认证失败的日志 —— 暴力破解检测依赖那些
  记录。
- 在生产环境中,不要只往本地磁盘的单个文件写日志;一旦 pod /
  container / VM 死掉,那些日志就没了。

### 已知误报
- health-check 或负载均衡器探活日志,可以在负载均衡器层合理地降
  采样 / 抑制,以节省日志量。
- 一个长得像 token 的 `request_id` 值不是 token —— 按模式匹配的
  脱敏器可能过度脱敏;把已知安全的前缀(例如你的 `req_` 关联 ID)
  加进白名单。
- 没有 auth header 的匿名公开 API 访问日志,本身不算隐私问题;但
  客户端 IP 在 GDPR 下仍可能是 PII。

## 背景(面向人类)

日志是 secret 最常以明文出现的地方 —— 请求 dump、异常堆栈、
debug 输出、第三方 SDK 的遥测。OWASP Logging Cheat Sheet 涵盖了
运营层面的规则;NIST SP 800-92 覆盖留存 / 集中化 / audit trail 这
一面。Audit trail 的要求出现在 SOC 2 CC7.2、PCI-DSS 10、HIPAA
§164.312(b) 与 ISO 27001 A.12.4 之下。

这个 skill 是 `secret-detection`(扫描源代码)和
`error-handling-security`(清洗对外响应)的搭档。日志夹在两者之
间,两边的内容都会渗到这里。

## 参考

- `rules/redaction_patterns.json`
- `rules/audit_event_schema.json`
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
- [CWE-532](https://cwe.mitre.org/data/definitions/532.html).
- [CWE-117](https://cwe.mitre.org/data/definitions/117.html).
- [NIST SP 800-92](https://csrc.nist.gov/publications/detail/sp/800-92/final).
