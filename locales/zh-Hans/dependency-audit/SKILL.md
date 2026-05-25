---
id: dependency-audit
language: zh-Hans
source_revision: "fbb3a823"
version: "1.0.0"
title: "依赖审计"
description: "审计项目依赖中的已知漏洞、恶意包和供应链风险"
category: supply-chain
severity: high
applies_to:
  - "在添加新依赖时"
  - "在升级依赖时"
  - "在审查包清单时(package.json、requirements.txt、go.mod、Cargo.toml)"
  - "在合并修改依赖文件的 PR 之前"
languages: ["*"]
token_budget:
  minimal: 400
  compact: 750
  full: 1900
rules_path: "rules/"
related_skills: ["secret-detection", "supply-chain-security"]
last_updated: "2026-05-12"
sources:
  - "OWASP Top 10 2021 — A06: Vulnerable and Outdated Components"
  - "CWE-1104: Use of Unmaintained Third Party Components"
  - "CISA Software Bill of Materials guidance"
---

# 依赖审计

## 规则（面向 AI 代理）

### 必须
- 在 lockfile 中将依赖固定到精确版本(`package-lock.json`、
  `yarn.lock`、`Pipfile.lock`、`poetry.lock`、`go.sum`、`Cargo.lock`)。
- 把每一个新依赖名与 `vulnerabilities/supply-chain/malicious-packages/`
  中内置的恶意包清单交叉比对。
- 在解决同一问题时,优先选择下载量高、维护者多、近期活跃的成熟包,
  而不是新出现的替代品。
- 运行 package manager 的 audit 命令(`npm audit`、`pip-audit`、
  `cargo audit`、`govulncheck`),在合并前审阅报告的问题。
- 验证包页面列出的仓库 URL 真实存在,且与链接的 GitHub / GitLab /
  Codeberg 项目一致。

### 禁止
- 不要在不固定版本的情况下添加依赖。
- 不要使用 `--unsafe-perm` 或等效绕过安装沙箱的 flag 来安装包。
- 不要添加名字出现在内置恶意包清单里的依赖。
- 不要在没有清晰、可记录理由的情况下添加全新的包(最近 30 天内才发
  布) —— typosquat 通常是新发布的。
- 不要在生产 lockfile 或容器镜像的 FROM 行中使用 `latest` 标签。
- 不要提交未使用的依赖 —— 它们白白扩大了攻击面。

### 已知误报
- 标为 "unknown" 的内部 monorepo 包(`@yourco/*`)—— 当 namespace 属
  于你的组织时是有效的。
- 被标为"最近发布"的稳定包的新 patch 版本(例如 `react@18.2.5` 紧
  接 `18.2.4`)—— patch 更新通常没问题。
- 与多年前的恶意条目合法重名的包,是原维护者重新注册而来。

## 背景(面向人类)

自 2019 年以来,供应链攻击的增速超过其他任何攻击类型。攻陷一个流行
包(event-stream、ua-parser-js、colors、faker、xz-utils)或发布一个
typosquat(axois vs axios、urllib3 vs urlib3)能在几小时内可靠地为攻
击者带来数千名下游受害者。

AI 编码工具尤其脆弱,因为模型无法知道一个包最近一次被攻陷是什么时
候。模型推荐的是训练期间学到的内容;如果某个维护者在训练截止之后被
攻陷,AI 会愉快地推荐带后门的版本。

本 skill 通过把动态的恶意包数据库注入 AI 的工作上下文、并要求 AI 在
添加任何依赖前查询它,来弥补这一缺陷。

## 参考

- `rules/known_malicious.json` —— 相关
  `vulnerabilities/supply-chain/malicious-packages/*.json` 文件的
  symlink 或副本。
- [OWASP Top 10 A06](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/).
- [npm Advisories](https://github.com/advisories?query=type%3Aunreviewed+ecosystem%3Anpm).
- [PyPI Advisory Database](https://github.com/pypa/advisory-database).
