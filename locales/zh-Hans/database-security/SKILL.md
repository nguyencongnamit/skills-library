---
id: database-security
language: zh-Hans
source_revision: "afe376a8"
version: "1.0.0"
title: "数据库安全"
description: "防止 SQL 注入、ORM 误用、凭证泄漏;强制最小权限数据库用户和安全迁移"
category: prevention
severity: critical
applies_to:
  - "在生成 SQL 或原生查询字符串时"
  - "在生成 ORM 模型代码或查询时"
  - "在生成数据库迁移文件时"
  - "在配置连接串或连接池时"
languages: ["sql", "python", "javascript", "typescript", "go", "ruby", "java", "kotlin", "csharp"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2500
rules_path: "rules/"
related_skills: ["secret-detection", "api-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP SQL Injection Prevention Cheat Sheet"
  - "OWASP Database Security Cheat Sheet"
  - "CWE-89: Improper Neutralization of Special Elements in an SQL Command"
  - "CIS PostgreSQL / MySQL Benchmarks"
---

# 数据库安全

## 规则（面向 AI 代理）

### 必须
- 任何接触用户可控值的 SQL 都使用参数化查询 / prepared statement。把
  值作为参数传入,绝不通过字符串拼接或格式化(`%s`、`+`、template
  literal)。
- 使用 ORM 的安全查询 API。SQLAlchemy:
  `session.execute(text(":id"), {"id": user_id})`。Django:ORM 方法,
  `Model.objects.filter(...)`。Sequelize / Prisma / SQLAlchemy core:
  `.where({ ... })` 构建器。Go:
  `db.QueryContext(ctx, "select ... where id = $1", id)`。
- 校验标识符列名 / 表名 —— 它们无法参数化 —— 必须来自硬编码 allowlist,
  而不是用户输入。
- 每个应用使用专用数据库用户,只授予所需的最小权限。只读 web 应用不
  应有 `INSERT`/`UPDATE`/`DELETE`。迁移作业以另一个具备 `DDL` 权限的
  用户身份运行。
- 对多租户表启用 Row-Level Security(Postgres `CREATE POLICY` /
  Supabase RLS / Azure SQL RLS),并按会话设置租户上下文。
- 从 secret 管理器或启动时注入的环境变量获取数据库凭证 —— 绝不从签入
  仓库的 `database.yml` / `.env` 获取。按计划轮换。
- 对数据库使用 TLS(Postgres 用 `sslmode=require`,MySQL 用
  `requireSSL=true`,MSSQL 使用加密连接)。在 driver 支持的情况下 pin
  CA。
- 连接池有最大上限,要塞在数据库 `max_connections` 之内,应用层有合理
  的反压机制。

### 禁止
- 不要把用户输入拼接进 SQL:`"SELECT * FROM users WHERE name='" + name
  + "'"`。即便你自己"转义"了 —— 只有通过参数 API 绑定时,driver 才会
  正确转义。
- 不要在 ORM 的 raw 查询方法 (`.raw()`、`.objects.raw()`、
  `.query(text(...))`) 中对用户输入使用 f-string 插值。
- 不要把应用工作负载以数据库超级用户 / `root` / `postgres` / `sa` 身
  份运行。请创建服务用户。
- 不要禁用到数据库的 TLS(`sslmode=disable`、`useSSL=false`)。
- 不要在 JSON 列中存储 secret、PII 或大 blob 而不做静态加密和密钥轮
  换计划。
- 不要把破坏性迁移(DROP TABLE、DROP COLUMN、对已有数据表的 ALTER
  COLUMN 改类型)和部署内联执行,而不走 expand-contract 计划且没有验
  证过可恢复的备份。
- 不要让数据库 listener 暴露在公网而没有 allowlist;数据库应留在私有
  网络中,通过堡垒机 / VPN / private link 访问。
- 不要在 INFO 级别记录带 bind 值的完整 SQL —— bind 值几乎都属于敏感
  信息。

### 已知误报
- 运行分析师自写的临时 SQL 的报表工具合法地插入标识符;它们应当对只
  读副本运行,且使用一个权限不足以造成损害的独立用户。
- 一些 ORM(Django、SQLAlchemy 1.x)使用 `%s` 占位符作为*参数标记*,
  而不是 Python format-string 的占位符 —— 这是安全的。
- 健康检查查询 (`SELECT 1`) 故意是极简的。

## 背景(面向人类)

SQL 注入在过去十五年中始终处于 OWASP Top 10 的第一或第二位,纹丝不
动,原因是失败模式是*默认就容易出现*的:任何带字符串拼接的语言都让
你能造出查询。AI 助手会快乐地生成"开发环境能跑"的代码,把用户输入
插进 SQL —— 尤其是用于排序列、动态过滤和分页的场景。

本 skill 与 `api-security`(把守路由)和 `secret-detection`(把守
连接串)天然搭配。

## 参考

- `rules/sql_injection_sinks.json`
- `rules/orm_safe_patterns.json`
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — SQL 注入。
- [PostgreSQL Row-Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).
