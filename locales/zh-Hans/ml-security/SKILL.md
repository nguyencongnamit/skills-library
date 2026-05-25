---
id: ml-security
language: zh-Hans
source_revision: "afe376a8"
version: "1.0.0"
title: "ML / LLM 安全"
description: "prompt injection、模型 poisoning、反序列化攻击、训练数据中的 PII、notebook 中的 secret 泄漏"
category: prevention
severity: high
applies_to:
  - "在生成调用 LLM API 或构建 LLM 驱动 agent 的代码时"
  - "在生成从 disk / Hub / S3 加载 ML 模型的代码时"
  - "在生成将用户内容用于 fine-tuning 的数据 pipeline 时"
languages: ["python", "javascript", "typescript", "jupyter", "go"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2700
rules_path: "rules/"
related_skills: ["secret-detection", "supply-chain-security", "api-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP Top 10 for LLM Applications 2025"
  - "NIST AI 100-2 (Adversarial Machine Learning)"
  - "MITRE ATLAS (Adversarial Threat Landscape for AI Systems)"
  - "CWE-502, CWE-1039, CWE-1426"
---

# ML / LLM 安全

## 规则（面向 AI 代理）

### 必须
- 把模型的每一个输入 —— 包括 tool 输出、被检索后又喂回到 prompt
  的文档 —— 都视作不可信。通过被检索的网页或文档进行的间接
  prompt injection,是真实世界中最常见的 LLM 攻击。
- 在把模型输出传给下游系统(SQL builder、shell、文件写入、HTTP
  请求、代码求值器)之前,要清洗并重新编码。模型输出永远不能直接
  作为信任的主键。
- 当下一步以程序方式消费输出时,通过结构化生成(JSON Schema、
  function-call 模式、受限 decoding)强制一个**输出 schema**。校
  验失败的全部拒绝。
- 维护一个 allowlist,列出模型可以调用的 tool / 函数名;其它调用一
  律拒绝。每个 tool 的鉴权要落到 agent 的**人类用户**身上,而不只
  是模型上。
- 对 RAG:给检索到的文档打上 provenance;在 prompt 中把"指令"和
  "上下文"分隔开;不要让检索到的数据覆盖系统指令。
- 加载模型时,PyTorch 与 Hugging Face 一律用 **safetensors**;在
  PyTorch 2.4+ 上使用 `torch.load` 时加 `weights_only=True`;绝不
  从不可信来源加载任意 `.pkl` / `.pt` 文件。
- 在训练数据里清除 PII、凭据和 secret —— 在源头(数据 ingestion)、
  存储(加密 + 访问控制)、输出(响应过滤器 / 探测器)三处都要做。
- 给每个 LLM 后端的 endpoint 加 rate-limit / quota,按 tenant 跟踪
  token 花费。
- 把每一次 prompt + 模型版本 + 检索到的上下文都当作审计日志记录;
  记录前先脱敏 secret。

### 禁止
- 不要在 runtime 从不可信来源拿来制品后用 `pickle.loads` /
  `joblib.load` / `dill.loads` / `torch.load` 加载。这些反序列化器
  按设计就会执行任意代码。
- 不要把用户输入直接拼接进含有更高信任级别指令的 prompt,例如
  `f"You are a helpful agent. {user_input}"`。要用模板化的边界,加
  上明确的 system role 分离。
- 不要把 LLM 产出的字符串直接喂给 `eval`、`exec`、`os.system`、
  `subprocess(shell=True)`、`vm.runInNewContext` 或 SQL 的
  `.raw()`。
- 不要把 OpenAI / Anthropic / Cohere 的 API key 硬编码在 notebook
  或仓库文件里。要用环境变量,并配合 `secret-detection` skill。
- 不要把含 PII 的训练样本长期存储,而没有明确的同意、留存窗口和删
  除 API。
- 不要在没有服务端验证的情况下信任客户端给的模型参数(模型名、
  system prompt、tool 列表) —— 客户端会偷偷降级到更便宜 / 更弱 /
  未授权的模型。
- 不要在没有 provenance / lineage 校验的情况下使用外部 vendor
  fine-tune 出来的模型。
- 不要只用 prompt 文本作 key 来缓存 LLM 响应 —— 当 prompt 共享前缀
  时,这样会把不同用户的上下文混在一起。

### 已知误报
- 故意演练 jailbreak prompt 的研究 / red-team notebook,要放在不带
  生产凭据的隔离环境里。
- 来自可信作者的预发表学术模型常以 `.pt` checkpoint 发布;第一步
  应把它们转成 safetensors。
- 合成数据生成 pipeline 可能合法地产出会被 commit 的模型原始输
  出 —— 要确保它被打标签,并复核是否夹带了无意泄漏的 PII 或被幻觉
  出来的 secret。

## 背景(面向人类)

OWASP LLM Top 10(2025) 把最常见的攻击归为十类;**LLM01 Prompt
Injection** 和 **LLM05 Improper Output Handling** 是运营层面的首要
关注点,因为它们几乎对所有 agent 化的部署都适用。NIST AI 100-2 给
出底层 adversarial ML 类别(evasion、poisoning、extraction);MITRE
ATLAS 则提供 kill-chain 视角。

这个 skill 假设构建用 LLM 的 app 的是 Devin(或任何 AI 助手)。要
把产出的 app 当成一个安全边界 —— 哪怕"用户"是另一个 AI agent。

## 参考

- `rules/prompt_injection_patterns.json`
- `rules/unsafe_deserialization.json`
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/).
- [NIST AI 100-2](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2023.pdf).
- [MITRE ATLAS](https://atlas.mitre.org/).
- [CWE-1426](https://cwe.mitre.org/data/definitions/1426.html) — Improper Validation of Generative AI Output.
