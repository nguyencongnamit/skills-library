---
id: deserialization-security
language: zh-Hans
source_revision: "4c215e6f"
version: "1.0.0"
title: "反序列化安全"
description: "在 Java、Python、.NET、PHP、Ruby、Node.js 中阻止不安全反序列化 —— gadget 链、类型 allowlist、更安全的替代方案"
category: prevention
severity: critical
applies_to:
  - "在生成会反序列化任何不可信来源数据的代码时"
  - "在配置 cookie、会话、消息队列或 RPC payload 时"
  - "在审查 pickle / unserialize / Marshal / ObjectInputStream / BinaryFormatter 用法时"
languages: ["java", "python", "csharp", "php", "ruby", "javascript", "typescript"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "crypto-misuse", "supply-chain-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP Deserialization Cheat Sheet"
  - "CWE-502: Deserialization of Untrusted Data"
  - "CVE-2017-9805 (Struts2 XStream)"
  - "CVE-2016-4437 (Shiro RememberMe)"
  - "CVE-2019-2725 (WebLogic XMLDecoder)"
---

# 反序列化安全

## 规则（面向 AI 代理）

### 必须
- 优先选择**结构化、按 schema 校验**的格式(用 JSON Schema 校验器的
  JSON、Protobuf、FlatBuffers、带显式类型映射的 MessagePack),而不
  是多态原生序列化器。"少写 10 行映射代码"的取舍永远换不起一个 RCE
  原语。
- 当必须使用多态反序列化器时,在框架层面配置**严格的类型 allowlist**
  (Jackson 的 `PolymorphicTypeValidator`、fastjson safeMode、.NET 的
  `KnownTypeAttribute`、XStream 的 `Whitelist`)。"any class" 的默认
  值是每一个现代 Java 反序列化 CVE 的源头。
- 任何携带序列化数据的 cookie 或 token 都必须用新生成的随机密钥进行
  签名和认证(至少 HMAC-SHA-256)。在 HMAC 校验通过之前绝不反序列化。
- 让反序列化代码路径以该格式所需的最小能力运行(无文件系统、无网络、
  无子进程、无反射)—— 例如 Java 的 `ObjectInputFilter` 模式;Python
  在受限的命名空间中运行。
- 把下列函数都视为"不可信输入的反序列化原语":Java
  `ObjectInputStream.readObject`、启用 `enableDefaultTyping` 的
  Jackson、SnakeYAML `Yaml.load()`、XStream `fromXML`、Python
  `pickle.load(s)` / `cPickle` / `dill` / `joblib.load`、`yaml.load`
  (默认 Loader)、`numpy.load(allow_pickle=True)`、`torch.load`、PHP
  `unserialize`、.NET `BinaryFormatter` / `ObjectStateFormatter` /
  `NetDataContractSerializer` / `LosFormatter`、Ruby `Marshal.load` /
  `YAML.load`(Psych ≤ 3.0)。把任何一个加入请求处理代码路径都需要
  显式的安全评审。

### 禁止
- 不要把不可信字节传给上述任何原语而不加 HMAC 认证的封装。即便有封
  装,也优先选择非多态格式。
- 不要在 Java Jackson 中使用 `objectMapper.enableDefaultTyping()` 或
  `@JsonTypeInfo(use = Id.CLASS)`。`LAMINAR_INTERNAL_DEFAULT` 默认会
  造出基于 class-id 的 gadget 链(ysoserial / marshalsec)。
- 不要在 SnakeYAML 中直接使用 `new Yaml()` 而不显式指定
  `SafeConstructor`(或带 allowlist 的 `Constructor`)。默认 constructor
  是常见 Java YAML RCE CVE 的源头。
- 不要在来自网络套接字、数据库列、Redis 缓存键或任何跨信任边界的数据
  上调用 Python `pickle.loads`。无论怎么校验,pickle 都不可能变安全。
- 不要使用 Python `yaml.load(data)`(没有 `Loader=yaml.SafeLoader`)。
  PyYAML 在 6.0 把默认改成会大声失败 —— 但旧代码路径仍带着不安全的默
  认值。
- 不要在下载下来的 checkpoint 上调用 Python `torch.load(path)` 而不
  加 `weights_only=True`(PyTorch ≥ 2.6 默认为 True;更早版本会触及
  pickle 并执行任意代码)。
- 不要对 cookie / POST / GET 数据调用 PHP `unserialize()`。PHP 序列
  化格式长期以来都有基于魔术方法的 gadget 链(`__wakeup`、
  `__destruct`、`__toString`)。
- 不要对任何跨信任边界的输入使用 .NET `BinaryFormatter`、
  `NetDataContractSerializer`、`ObjectStateFormatter`、`LosFormatter`。
  微软已将 `BinaryFormatter` 标记为废弃且不安全。
- 不要信任来自当前进程之外的 Ruby `Marshal.load` 内容。对旧版本 Psych
  上的 `YAML.load` 也是同样的限制。

### 已知误报
- 双方均由运营方控制、数据端到端认证(mTLS + HMAC)、且格式选择是务实
  的内部 RPC(例如某些遗留 stack 中 Java 服务在 TLS+mTLS-only 的套接
  字上使用 ObjectInputStream 可能可以接受)。
- 对仓库内打包文件(pickle 测试 fixture 等)在构建期 / 配置期进行反序
  列化 —— 但要明确标注,且永远不要从下载结果加载。
- 像 Rails 默认的签名 cookie 会话这样的密码学认证的会话格式是 Marshal
  的预期用法,但前提是 HMAC 把反序列化挡在门外。

## 背景(面向人类)

反序列化漏洞是现代企业 stack 中最可靠的 RCE 原语。账算得简单:当序
列化器允许任意类实例化时,代码库已经导入了数千个类 —— 其中很多在
`readObject`、`__reduce__`、`__wakeup`、`Read*` 回调里有副作用。gadget
链把这些副作用串联成 RCE。

ysoserial(Java)、ysoserial.net(.NET)、marshalsec(Java)以及
Python pickle gadget 目录都是成熟工具。任何"这能被利用吗?"的问题答
案都是"能,用你的 classpath 上已经有的 gadget"。

修复方法不是过滤 —— 而是从一开始就选用不允许任意类实例化的格式。大
多数现代服务都用 mTLS 上的签名 JWT / JSON。在不得不使用多态格式的地
方,类型 allowlist + HMAC 不可妥协。

## 参考

- `rules/unsafe_deserializers.json`
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html).
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- [ysoserial](https://github.com/frohoff/ysoserial).
- [ysoserial.net](https://github.com/pwntester/ysoserial.net).
- [marshalsec](https://github.com/frohoff/marshalsec).
