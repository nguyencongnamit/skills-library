---
id: error-handling-security
language: zh-Hans
source_revision: "afe376a8"
version: "1.0.0"
title: "错误处理安全"
description: "客户端响应中不出现 stack trace / SQL / 路径 / 框架版本;对外返回通用错误,日志中保留结构化错误"
category: prevention
severity: medium
applies_to:
  - "在生成 HTTP / GraphQL / RPC 错误处理器时"
  - "在生成 exception / panic / rescue 块时"
  - "在配置框架默认错误页时"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 900
  full: 1900
rules_path: "rules/"
related_skills: ["api-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP Error Handling Cheat Sheet"
  - "CWE-209 — Generation of Error Message Containing Sensitive Information"
  - "CWE-754 — Improper Check for Unusual or Exceptional Conditions"
---

# 错误处理安全

## 规则（面向 AI 代理）

### 必须
- 在边界(HTTP 处理器、RPC 方法、消息消费者)处捕获异常。在服务端用
  完整上下文记录;对外返回脱敏后的错误。
- 对外错误响应包含:稳定的错误码、简短的人类可读消息、相关性 / 请
  求 ID。绝不包含:stack trace、SQL 片段、文件路径、内部主机名、框
  架版本横幅。
- 在恰当的级别记录错误:`ERROR` / `WARN` 用于可执行的失败;`INFO`
  用于预期的业务结果;`DEBUG` 用于诊断细节(且仅在显式启用时)。
- 在整个 API 表面返回统一的错误响应 —— 同样的形状、同样的码集 ——
  这样攻击者无法从错误差异推断行为(例如登录:"用户名错"与"密码
  错"用相同的消息和相同的时序)。
- 在生产环境禁用框架默认错误页(`app.debug = False` /
  `Rails.env.production?` / `Environment=Production` / `DEBUG=False`)。
  用一个只返回相关性 ID 的 5xx 页面替代。
- 使用集中化的错误渲染 helper,让脱敏规则只在一处存在,不重复。

### 禁止
- 不要在生产环境向客户端渲染 `traceback.format_exc()`、
  `e.toString()`、`printStackTrace()`、`panic` 或框架的 debug 页。
- 不要在错误消息里回显 SQL 查询 / 参数 —— `IntegrityError:
  duplicate key value violates unique constraint "users_email_key"`
  会把表名和列名告诉攻击者。
- 不要泄露记录存在性信息:`User not found` 与 `Invalid password`
  会让攻击者枚举账户。对两者使用同一条消息。
- 不要泄露文件系统路径(`/var/www/app/src/handlers.py`)或版本横幅
  (`X-Powered-By: Express/4.17.1`)。
- 不要把 `try / except: pass` 当作错误处理;异常要么是预期的(记录
  +继续),要么不是(让它向上传播)。
- 不要用 4xx 错误响应去校验输入的形状 —— 机器人会迭代参数,根据响
  应 body 来学习 schema。对格式不正的输入返回统一的 400 加相关性
  ID。
- 不要把完整错误细节(包括 PII)发到第三方错误追踪服务而不经过
  scrubber。要遮蔽 `password`、`Authorization`、`Cookie`、
  `Set-Cookie`、`token`、`secret` 以及常见的 PII 模式。

### 已知误报
- `localhost` / `*.local` 上面向开发者的错误页是可以的。
- 少量 API 端点(debug、admin、内部 RPC)可以合法地返回更多细节;它
  们必须要求已认证、已授权的调用者,且永远不可从互联网到达。
- 健康检查和 CI smoke test 在从集群内部调用时,故意暴露细节。

## 背景(面向人类)

CWE-209 文字短但影响大:攻击者就是用它从"这个服务存在"过渡到"这
个服务跑着 Spring 5.2,基于 Tomcat 9,有一张叫 `users` 的 PostgreSQL
表和一列叫 `email_normalized`"。错误消息里每多一条细节,下一步攻
击的成本就低一分。

本 skill 是有意做窄的,与 `logging-security`(同一操作的 *日志* 侧)
和 `api-security`(响应形状)配套。

## 参考

- `rules/error_response_template.json`
- `rules/redaction_patterns.json`
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html).
- [CWE-209](https://cwe.mitre.org/data/definitions/209.html).
