---
id: api-security
language: zh-Hans
source_revision: "fbb3a823"
version: "1.0.0"
title: "API 安全"
description: "将 OWASP API Top 10 模式应用于身份认证、授权与输入校验"
category: prevention
severity: high
applies_to:
  - "在生成 HTTP 处理器时"
  - "在生成 GraphQL resolver 时"
  - "在生成 gRPC 服务方法时"
  - "在评审 API 端点变更时"
languages: ["*"]
token_budget:
  minimal: 500
  compact: 750
  full: 2300
rules_path: "checklists/"
related_skills: ["secure-code-review", "secret-detection"]
last_updated: "2026-05-12"
sources:
  - "OWASP API Security Top 10 2023"
  - "OWASP Authentication Cheat Sheet"
  - "OAuth 2.0 Security Best Current Practice (RFC 9700)"
---

# API 安全

## 规则（面向 AI 代理）

### 必须
- 在每个非公开端点上强制身份认证。默认即认证;真正公开的路由需要显式标注。
- 在对象级别强制授权——确认已认证主体确实有权访问所请求的资源 ID,
  而不仅仅是"已登录"(这能挫败 OWASP API1 BOLA / IDOR 这一类问题)。
- 用显式 schema (JSON Schema、Pydantic、Zod、validator/v10 的 struct tag) 校验所有
  请求输入。尽早拒绝;绝不把不可信输入往下游传递。
- 在路由级别为身份认证端点、密码重置以及任何耗费资源的操作设置限流。
- 使用短期有效的访问令牌(≤ 1 小时)配合刷新令牌,不要使用长期 bearer 令牌。
- 对外返回通用错误信息(`invalid credentials`),把细节记录到内部日志——避免泄露
  到底是用户名错还是密码错。
- 对包含个人信息或敏感数据的响应,加上 `Cache-Control: no-store`。

### 禁止
- 在跨租户可访问的资源 URL 中使用顺序递增的整数 ID。请使用 UUID 或不可猜测的
  不透明 ID。
- 在未验证签名和有效期的情况下信任 `Authorization` 头。
- 接受算法为 `none` 的 JWT。在验证时固定预期算法。
- 把请求体直接整体赋值给 ORM 模型 (`User(**request.json)`) ——当模型存在用户
  不应控制的管理员字段时,这会导致权限提升。
- 在浏览器使用的修改状态的端点上关闭 CSRF 保护。
- 在生产环境向客户端返回堆栈跟踪或框架错误页面。
- 用 `HTTP GET` 执行任何修改状态的操作—— GET 必须是安全且幂等的。

### 已知误报
- 面向匿名流量的公开营销站点端点合法地不需要身份认证,
  也不需要负载均衡器之外的限流。
- 对于真正公开、不属于任何租户的资源(例如博客 post 的 slug、公开产品目录),
  路径里出现顺序 ID 是可以接受的。
- 健康检查端点 (`/healthz`、`/ready`) 故意绕过身份认证。

## 背景(面向人类)

OWASP API Top 10 与 Web Top 10 的主要区别在于:API 的默认配置更弱——经常跳过
CSRF,直接暴露对象 ID,并且倾向于信任开发者提供的客户端状态。本 skill 把最常见、
影响最大的错误归纳出来。

## 参考

- `checklists/auth_patterns.yaml`
- `checklists/input_validation.yaml`
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-introduction/).
- [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700).
