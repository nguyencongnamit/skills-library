---
id: graphql-security
language: zh-Hans
source_revision: "4c215e6f"
version: "1.0.0"
title: "GraphQL 安全"
description: "防御 GraphQL API:深度/复杂度限制、生产环境的 introspection、批处理/别名滥用、字段级授权、persisted queries"
category: prevention
severity: high
applies_to:
  - "在生成 GraphQL schema、resolver 或服务端配置时"
  - "在为 GraphQL 端点接入认证/授权时"
  - "在添加面向公网的 GraphQL API 网关时"
  - "在审查 /graphql 端点暴露时"
languages: ["javascript", "typescript", "python", "go", "java", "kotlin", "csharp", "ruby"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "auth-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP GraphQL Cheat Sheet"
  - "CWE-400: Uncontrolled Resource Consumption"
  - "Apollo GraphQL Production Checklist"
  - "graphql-armor (Escape technologies)"
---

# GraphQL 安全

## 规则（面向 AI 代理）

### 必须
- 在服务端强制最大**查询深度**(通常 7–10)与**查询复杂度**(代价)。
  对多对多关系做 5 层嵌套的查询可能返回数十亿节点;没有代价限制时,
  一个客户端就能压垮数据库。
- 在生产环境**关闭 introspection**。Introspection 让侦察变得轻而易
  举;合法客户端通过 codegen 或 `.graphql` 文件已经内嵌了 schema。
- 对任何高流量 / 公开 API 使用 **persisted queries**(以 allowlist
  方式锁定操作 hash)。匿名任意 GraphQL 等价于 GraphQL 版的
  `eval(req.body)`。
- 在 resolver 中应用**字段级授权**,而不仅是端点级。GraphQL 把许多
  字段聚合到一个 HTTP 响应中 —— 一个敏感字段上漏掉的 `@auth` 就会
  在整个查询里泄露数据。
- 限制每个请求的**别名**数量(通常 15)和每个 batch 中的**操作数**
  (通常 5)。Apollo / Relay 都允许批处理查询 —— 没有限制时这是个 N
  页 API 的放大原语。
- 提早拒绝**循环 fragment** 定义(大多数服务器会做,但自定义
  executor 不会)。自引用 fragment 会带来指数级的解析时代价。
- 对客户端返回通用错误(`INTERNAL_SERVER_ERROR`、`UNAUTHORIZED`),
  把堆栈跟踪 / SQL 片段只路由到服务端日志。Apollo 的默认错误会泄漏
  schema 与查询的内部细节。
- 在 GraphQL 服务器前面的 HTTP 层设置请求大小限制(通常 100 KiB)和
  请求超时(通常 10 s)。1 MiB 的 GraphQL 查询没有合法用途。

### 禁止
- 不要在生产端点开放 `/graphql` introspection。生产构建里也要禁用
  GraphQL playground(GraphiQL、Apollo Sandbox)。
- 不要因为"我们的客户端只发送格式良好的查询"就相信查询的深度 / 复杂
  度。任何攻击者都可以手工构造一个发往 `/graphql` 的请求。
- 不要允许 `@skip(if: ...)` / `@include(if: ...)` 指令来左右授权检
  查。多数 executor 中指令在授权之后运行,但自定义指令顺序已经造成
  过 authz 绕过。
- 不要在 resolver 中实现 N+1 模式(每个父记录一次 DB 查询)。改用
  DataLoader 或基于 join 的取数。N+1 既是性能问题也是 DoS 放大器。
- 不要在没有大小限制、MIME 校验和带外杀毒扫描的情况下,允许通过
  GraphQL multipart 上传文件(`apollo-upload-server`、
  `graphql-upload`)。2020 年的 CVE-2020-7754(`graphql-upload`)
  展示了一个畸形的 multipart 如何让服务器崩溃。
- 不要仅按 URL 缓存 GraphQL 响应。POST `/graphql` 始终用同一个 URL;
  缓存必须按操作 hash + 变量 + 认证 claim 作为 key,避免跨租户泄漏。
- 不要在没有 schema 校验的情况下暴露接受不可信 JSON `input:` 对象的
  mutation。GraphQL 类型在 schema 层是强制的,但 `JSON` / `Scalar`
  类型会完全绕过它们。

### 已知误报
- 在已认证 VPN 后面的内部管理 GraphQL 端点可以合法地保留
  introspection 以方便开发者。
- 静态 allowlist 的 persisted queries 让深度 / 复杂度检查在这些操作
  上变得多余 —— 对不在 allowlist 内的操作(即通过 `disabled` flag 的
  操作)仍保留这些检查。
- 公开、只读的数据 API 可以使用很高的代价限制,并在 CDN 层激进地配
  置缓存;在每个端点上文档化此权衡。

## 背景(面向人类)

GraphQL 给客户端一门查询语言。这门语言在实践中是图灵完备的 —— 深
度、别名、fragment、union 组合起来可以对 resolver 图执行近乎任意的
计算。把 `/graphql` 当成一个用简单 WAF / 限流就能搞定的单一端点是
不够的。

2022-2024 年的 GraphQL 事故时代(Hyatt、Apollo 内部的 Slack 研究、
多起通过 batching 实现的账号接管案例)都围绕缺少字段级授权或缺少代
价分析。graphql-armor(Escape)和 Apollo 自带的校验规则现在已经为大
多数问题提供了开箱即用的中间件 —— 用起来。

## 参考

- `rules/graphql_safe_config.json`
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html).
- [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
- [Apollo Production Checklist](https://www.apollographql.com/docs/apollo-server/security/production-checklist/).
- [graphql-armor](https://escape.tech/graphql-armor/).
