---
id: deserialization-security
language: pt-BR
source_revision: "4c215e6f"
version: "1.0.0"
title: "Segurança de desserialização"
description: "Bloquear desserialização insegura em Java, Python, .NET, PHP, Ruby, Node.js — cadeias de gadgets, allowlist de tipos, alternativas mais seguras"
category: prevention
severity: critical
applies_to:
  - "ao gerar código que desserializa dados de qualquer fonte não confiável"
  - "ao configurar cookies, sessões, message queues ou payloads de RPC"
  - "ao revisar uso de pickle / unserialize / Marshal / ObjectInputStream / BinaryFormatter"
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

# Segurança de desserialização

## Regras (para agentes de IA)

### SEMPRE
- Prefira formatos **estruturais, validados por schema** (JSON com
  validador JSON Schema, Protobuf, FlatBuffers, MessagePack com mapa
  de tipos explícito) em vez de serializadores nativos polimórficos.
  O trade-off "economizar 10 linhas de código de mapping" nunca vale
  um primitivo de RCE.
- Quando um desserializador polimórfico é inevitável, configure uma
  **allowlist estrita de tipos** no nível do framework
  (`PolymorphicTypeValidator` do Jackson, fastjson safeMode,
  `KnownTypeAttribute` do .NET, `Whitelist` do XStream). O default
  "any class" é a fonte de toda CVE moderna de desserialização Java.
- Assine e autentique qualquer cookie ou token que carregue dados
  serializados com uma chave aleatória nova (HMAC-SHA-256, no
  mínimo). Nunca desserialize antes da verificação do HMAC.
- Rode os code paths de desserialização com as capacidades mínimas de
  que o formato precisa (sem filesystem, sem rede, sem subprocess,
  sem reflection) — ex.: patterns `ObjectInputFilter` em Java; Python
  em namespace restrito.
- Trate qualquer uma das funções a seguir como "primitivos de
  desserialização de input não confiável": Java
  `ObjectInputStream.readObject`, Jackson com `enableDefaultTyping`,
  SnakeYAML `Yaml.load()`, XStream `fromXML`, Python `pickle.load(s)`
  / `cPickle` / `dill` / `joblib.load`, `yaml.load` (Loader default),
  `numpy.load(allow_pickle=True)`, `torch.load`, PHP `unserialize`,
  .NET `BinaryFormatter` / `ObjectStateFormatter` /
  `NetDataContractSerializer` / `LosFormatter`, Ruby `Marshal.load` /
  `YAML.load` (Psych ≤ 3.0). Adicionar uma delas a um code path de
  handling de request exige review de segurança explícito.

### NUNCA
- Passe bytes não confiáveis a qualquer um dos primitivos acima sem
  um wrapper HMAC-autenticado. Mesmo com wrapper, prefira um formato
  não polimórfico.
- Use Java Jackson com `objectMapper.enableDefaultTyping()` ou
  `@JsonTypeInfo(use = Id.CLASS)`. O default
  `LAMINAR_INTERNAL_DEFAULT` produz uma cadeia de gadgets por
  class-id (ysoserial / marshalsec).
- Use SnakeYAML `new Yaml()` sem especificar explicitamente um
  `SafeConstructor` (ou `Constructor` com allowlist). O constructor
  default é a fonte das CVEs comuns de RCE em YAML no Java.
- Use Python `pickle.loads` em dados vindos de um socket de rede,
  coluna de banco, chave de cache no Redis ou qualquer lugar que
  atravesse uma fronteira de confiança. Nenhuma quantidade de
  validação torna pickle seguro.
- Use Python `yaml.load(data)` (sem `Loader=yaml.SafeLoader`). O
  PyYAML mudou o default em 6.0 para falhar ruidosamente — code paths
  mais antigos ainda trazem o default inseguro.
- Use Python `torch.load(path)` em um checkpoint baixado sem
  `weights_only=True` (PyTorch ≥ 2.6 default é True; versões mais
  antigas alcançam pickle e executam código arbitrário).
- Use PHP `unserialize()` em dados de cookie / POST / GET. O formato
  serializado do PHP tem um longo histórico de cadeias de gadgets via
  métodos mágicos (`__wakeup`, `__destruct`, `__toString`).
- Use .NET `BinaryFormatter`, `NetDataContractSerializer`,
  `ObjectStateFormatter`, `LosFormatter` em qualquer input que
  atravesse uma fronteira de confiança. A Microsoft marca
  `BinaryFormatter` como obsoleto e inseguro.
- Confie no conteúdo de um Ruby `Marshal.load` vindo de fora do mesmo
  processo. Mesma restrição para `YAML.load` em Psych antigo.

### FALSOS POSITIVOS CONHECIDOS
- RPC interno em que ambos os lados são controlados pelo operador, os
  dados são autenticados end-to-end (mTLS + HMAC) e a escolha de
  formato é pragmática (ex.: serviços Java usando ObjectInputStream
  sobre socket TLS+mTLS-only podem ser aceitáveis em alguns stacks
  legacy).
- Desserialização em build-time / configuration-time de arquivos
  versionados no repositório (fixtures de teste com pickle, etc.) —
  mas marque-os claramente e nunca os carregue a partir de download.
- Formatos de sessão criptograficamente autenticados como as sessões
  por cookie assinadas default do Rails são uso intencional de
  Marshal, mas só porque o HMAC gateia a desserialização.

## Contexto (para humanos)

Vulnerabilidades de desserialização são o primitivo de RCE mais
confiável em stacks empresariais modernos. A economia é simples:
quando o serializador permite instanciação arbitrária de classes, o
codebase já importou milhares de classes — muitas com side-effects
em seus callbacks `readObject`, `__reduce__`, `__wakeup`, `Read*`.
Uma cadeia de gadgets combina esses side-effects em RCE.

ysoserial (Java), ysoserial.net (.NET), marshalsec (Java) e os
catálogos de gadgets de pickle do Python são tooling maduro. Toda
pergunta "isso é explorável?" se responde com "sim, com os gadgets
que já estão no seu classpath".

A correção não é filtrar — é usar um formato que não permita
instanciação arbitrária de classes em primeiro lugar. A maioria dos
serviços modernos entrega JWTs assinados / JSON sobre mTLS. Onde um
formato polimórfico é inevitável, allowlist de tipos + HMAC são
inegociáveis.

## Referências

- `rules/unsafe_deserializers.json`
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html).
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- [ysoserial](https://github.com/frohoff/ysoserial).
- [ysoserial.net](https://github.com/pwntester/ysoserial.net).
- [marshalsec](https://github.com/frohoff/marshalsec).
