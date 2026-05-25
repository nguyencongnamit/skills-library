---
id: supply-chain-security
language: zh-Hans
source_revision: "fbb3a823"
version: "1.0.0"
title: "供应链安全"
description: "防御 typosquat、依赖混淆(dependency confusion)和恶意软件包贡献"
category: supply-chain
severity: critical
applies_to:
  - "AI 被要求添加依赖时"
  - "review 修改 package manifest 的 PR 时"
  - "新建项目使用内部 namespace 时"
  - "向公开 registry 发布 package 之前"
languages: ["*"]
token_budget:
  minimal: 550
  compact: 800
  full: 2100
rules_path: "rules/"
tests_path: "tests/"
related_skills: ["dependency-audit", "secret-detection"]
last_updated: "2026-05-12"
sources:
  - "Alex Birsan, Dependency Confusion (2021)"
  - "OpenSSF Best Practices for OSS Developers"
  - "SLSA Supply-chain Levels for Software Artifacts v1.0"
---

# 供应链安全

## 规则(面向 AI 代理)

### 必须
- 每次建议添加新依赖时,都用 Levenshtein 距离跟该生态前 1000
  package 列表对比。任何与流行 package 距离 ≤ 2 的候选都要标记
  出来(`axois` vs `axios`、`urlib3` vs `urllib3`、`colours`
  vs `colors`、`python-dateutil` vs `dateutil` vs `dateutils`)。
- 校验内部 namespace 的 package(`@yourco/*`、`com.yourco.*`)
  是从内部 registry 拉的,而不是公开的。要在 `.npmrc` /
  `pip.conf` / `settings.gradle` 里明确配置内部 scope。
- 把 lockfile 里的 registry URL 钉死,防止 registry 重定向
  攻击。
- 任何新加的 package 如果是近 90 天内才发布的,要核查有没有
  经过验证的 maintainer(`npm` provenance、`sigstore` 签名、
  GPG 签名的 git tag)。
- 把 install script(`postinstall`、`preinstall`、`setup.py`
  里的任意代码、`build.rs`)当作高危面,在 PR 描述里标出来交人
  审。

### 禁止
- 不要添加名字跟内部 namespace pattern 重合的公开 package。
- 不要相信 registry 页面上 repository URL 跟它真实源仓库不一致
  的 package。
- 不要在安全关键场景(auth、crypto、HTTP、数据库 driver)推荐
  最近才发布、下载量低的 package。
- 不要关掉 package manager 的完整性校验
  (`--no-package-lock`、防御场景下的
  `--ignore-scripts = false`、生产里 `npm config set audit false`)。
- 跨 major version 的依赖升级 PR 不要在没人 review 的情况下自动
  merge。
- 不要建议从不可信源用 `curl | sh` 之类的 pattern 安装工具。

### 已知误报
- 正规组织 fork 并以 `-fork` 或 `-community` 后缀重新发布在维
  护的 package;标记之前先确认 fork 的 repo URL。
- 知名 package 的 beta / alpha release(例如 `next@canary`)
  看起来像"刚刚发布",但其实属于已知的发布节奏。
- 内部 namespace 的 package(`@yourco/internal-tools`)有意不
  上公开 registry —— 只要 `.npmrc` 配置正确,这本来就没问题。

## 背景(面向人类)

依赖混淆(dependency confusion)这一攻击类别能成立,是因为大
多数 package manager 默认在所有已配置 registry 中优先选用版本
最高的 package。攻击者只要把 `@yourco/internal-tool@99.9.9` 发
到 npmjs.com,你们团队项目里的每次 `npm install` 就都会拉攻击
者的代码,而不是合法的内部那个。

typosquat 同样具有破坏性,只不过它利用的是人的注意力,而不是
registry 的默认行为。AI 工具尤其容易踩坑,因为它们会生成看似
合理的 package 名,而不去核实哪些是真的存在。

## 参考

- `rules/typosquat_patterns.json`
- `rules/dependency_confusion.json`
- [Alex Birsan's original dependency confusion writeup](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610).
- [SLSA](https://slsa.dev/).
