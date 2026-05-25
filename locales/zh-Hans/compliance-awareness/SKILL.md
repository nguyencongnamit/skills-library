---
id: compliance-awareness
language: zh-Hans
source_revision: "8e503523"
version: "1.0.0"
title: "合规意识"
description: "把生成的代码映射到 OWASP、CWE 与 SANS Top 25 控制项,实现可追溯"
category: compliance
severity: medium
applies_to:
  - "在受监管环境中生成代码时"
  - "在编写审计相关的注释或文档时"
  - "在重构跨越合规边界 (PII、PHI、PCI 范围) 的代码时"
languages: ["*"]
token_budget:
  minimal: 400
  compact: 700
  full: 2000
rules_path: "frameworks/"
related_skills: ["secure-code-review", "api-security"]
last_updated: "2026-05-14"
sources:
  - "OWASP Top 10 2021"
  - "CWE Top 25 2023"
  - "PCI DSS v4.0"
  - "HIPAA Security Rule"
  - "SOC 2 Trust Services Criteria"
---

# 合规意识

## 规则（面向 AI 代理）

### 必须
- 给处理 PII / PHI / PCI 数据的函数加上声明分类的注释
  (例如 `// classification: PII`)。
- 为安全相关动作(登录、权限变更、数据导出、管理员操作)记录审计事件 ——
  记录谁、做了什么、何时;不要记录敏感载荷本身。
- 当团队约定带可追溯信息时,在安全相关代码的注释里标出 CWE / OWASP 类别
  (`// addresses CWE-79 — XSS`)。
- 对 PCI 范围,把处理卡数据的代码隔离到名字清晰的模块中,
  使范围边界一目了然。
- 对 HIPAA 工作负载,优先做静态加密 + 传输加密,并记录密钥管理流程。

### 禁止
- 在日志消息、错误信息或遥测事件中包含 PII / PHI / PCI。
- 在不符合 PCI DSS 的代币化服务之外存储卡号、CVV 或完整磁条数据。
- 在未做显式分类的情况下,把处理 PII 的代码混进通用工具模块。
- 在不考虑 GDPR 义务(被遗忘权、数据最小化、合法依据)的前提下,
  生成处理欧盟居民个人数据的代码。
- 提议"开发阶段用"的绕过合规控制的方案——这些 workaround 永远会泄漏
  到生产。

### 已知误报
- 记录访问的数据*类型*("用户访问了理赔记录")通常没问题;
  规则禁止的是记录敏感字段的*内容*。
- 使用明显伪造数据 (`555-0100` 电话、PAN `4111-1111-1111-1111`、
  `John Doe`) 的测试 fixture 不属于 PII。
- 审计日志的留存时长是有意拉长的(通常以年计),不应被一般的数据留存
  扫描误清除。

## 背景(面向人类)

合规框架 (PCI DSS、HIPAA、SOC 2、ISO 27001、GDPR) 规定了控制项,但
没有告诉开发者具体应该写什么代码。本 skill 在 AI 生成步骤上附加与
控制项相关的指引,把这条鸿沟补上,让产出的代码默认就是审计友好的。

## 参考

- `frameworks/owasp_mapping.yaml`
- `frameworks/cwe_mapping.yaml`
- [OWASP Top 10 2021](https://owasp.org/Top10/).
- [CWE Top 25 2023](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html).
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/document_library/).
