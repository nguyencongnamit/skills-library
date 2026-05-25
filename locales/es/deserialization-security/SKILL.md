---
id: deserialization-security
language: es
source_revision: "4c215e6f"
version: "1.0.0"
title: "Seguridad de deserialización"
description: "Bloquear deserialización insegura en Java, Python, .NET, PHP, Ruby, Node.js — cadenas de gadgets, allowlist de tipos, alternativas más seguras"
category: prevention
severity: critical
applies_to:
  - "al generar código que deserialice datos desde cualquier fuente no confiable"
  - "al cablear cookies, sesiones, message queues o payloads RPC"
  - "al revisar uso de pickle / unserialize / Marshal / ObjectInputStream / BinaryFormatter"
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

# Seguridad de deserialización

## Reglas (para agentes de IA)

### SIEMPRE
- Preferir formatos **estructurales y validados por schema** (JSON con
  un validador de JSON Schema, Protobuf, FlatBuffers, MessagePack con
  un mapa de tipos explícito) antes que serializadores nativos
  polimórficos. El trade-off "ahorro 10 líneas de código de mapping"
  nunca vale el primitivo de RCE.
- Cuando un deserializador polimórfico es inevitable, configurar una
  **allowlist estricta de tipos** a nivel framework
  (`PolymorphicTypeValidator` de Jackson, fastjson safeMode,
  `KnownTypeAttribute` de .NET, `Whitelist` de XStream). El default
  "any class" es la fuente de todos los CVE modernos de
  deserialización en Java.
- Firmar y autenticar cualquier cookie o token que cargue datos
  serializados con una clave aleatoria nueva (HMAC-SHA-256, mínimo).
  Nunca deserializar antes de la verificación HMAC.
- Correr los code paths de deserialización con las capacidades mínimas
  que el formato necesita (sin filesystem, sin red, sin subprocess,
  sin reflection) — p. ej. patrones `ObjectInputFilter` en Java;
  Python en un namespace restringido.
- Tratar cualquiera de las siguientes funciones como "primitivos de
  deserialización de input no confiable": Java
  `ObjectInputStream.readObject`, Jackson con `enableDefaultTyping`,
  SnakeYAML `Yaml.load()`, XStream `fromXML`, Python `pickle.load(s)`
  / `cPickle` / `dill` / `joblib.load`, `yaml.load` (Loader por
  default), `numpy.load(allow_pickle=True)`, `torch.load`, PHP
  `unserialize`, .NET `BinaryFormatter` / `ObjectStateFormatter` /
  `NetDataContractSerializer` / `LosFormatter`, Ruby `Marshal.load` /
  `YAML.load` (Psych ≤ 3.0). Agregar una de éstas a un code path de
  manejo de request requiere review de seguridad explícito.

### NUNCA
- Pasar bytes no confiables a ninguno de los primitivos anteriores sin
  un wrapper HMAC-autenticado. Aún con wrapper, preferir un formato no
  polimórfico.
- Usar Jackson de Java con `objectMapper.enableDefaultTyping()` o
  `@JsonTypeInfo(use = Id.CLASS)`. El default
  `LAMINAR_INTERNAL_DEFAULT` produce una cadena de gadgets por
  class-id (ysoserial / marshalsec).
- Usar SnakeYAML `new Yaml()` sin especificar explícitamente un
  `SafeConstructor` (o `Constructor` con allowlist). El constructor
  por default es la fuente de los CVE comunes de RCE por YAML en Java.
- Usar Python `pickle.loads` sobre datos de un socket de red, columna
  de DB, clave de Redis cache o cualquier lugar que cruce un trust
  boundary. Ninguna cantidad de validación hace seguro a pickle.
- Usar Python `yaml.load(data)` (sin `Loader=yaml.SafeLoader`). PyYAML
  cambió el default en 6.0 para fallar ruidosamente — code paths más
  viejos todavía traen el default inseguro.
- Usar Python `torch.load(path)` sobre un checkpoint descargado sin
  `weights_only=True` (PyTorch ≥ 2.6 default es True; versiones más
  viejas alcanzan pickle y ejecutan código arbitrario).
- Usar PHP `unserialize()` sobre datos de cookie / POST / GET. El
  formato serializado de PHP tiene una larga historia de cadenas de
  gadgets por métodos mágicos (`__wakeup`, `__destruct`, `__toString`).
- Usar .NET `BinaryFormatter`, `NetDataContractSerializer`,
  `ObjectStateFormatter`, `LosFormatter` para cualquier input que
  cruce un trust boundary. Microsoft marca `BinaryFormatter` como
  obsoleto e inseguro.
- Confiar en el contenido de un Ruby `Marshal.load` proveniente de
  fuera del mismo proceso. Misma restricción para `YAML.load` en Psych
  viejo.

### FALSOS POSITIVOS CONOCIDOS
- RPC interno donde ambos lados están controlados por el operador,
  los datos están autenticados end-to-end (mTLS + HMAC), y la
  elección del formato es pragmática (p. ej. servicios Java usando
  ObjectInputStream sobre un socket TLS+mTLS-only puede ser aceptable
  en algunos stacks legacy).
- Deserialización build-time / configuration-time de archivos que
  vienen en el repositorio (fixtures de tests con pickle, etc.) —
  pero marcarlos claramente y nunca cargarlos desde una descarga.
- Formatos de sesión criptográficamente autenticados como las
  sesiones por cookie firmadas por default de Rails son uso intencional
  de Marshal, pero solo porque el HMAC compuerta la deserialización.

## Contexto (para humanos)

Las vulnerabilidades de deserialización son el primitivo de RCE más
confiable en stacks empresariales modernos. La economía es simple:
cuando el serializador permite instanciación arbitraria de clases, el
codebase ya importó miles de clases — muchas de las cuales tienen
side-effects en sus callbacks `readObject`, `__reduce__`, `__wakeup`,
`Read*`. Una cadena de gadgets combina estos side-effects en RCE.

ysoserial (Java), ysoserial.net (.NET), marshalsec (Java) y los
catálogos de gadgets de pickle de Python son tooling maduro. Toda
pregunta "¿esto es explotable?" se contesta con "sí, con los gadgets
que ya tienes en el classpath".

La fix no es filtrar — es usar un formato que no permita
instanciación arbitraria de clases en primer lugar. La mayoría de los
servicios modernos despacha JWTs firmados / JSON sobre mTLS. Donde un
formato polimórfico es inevitable, allowlist de tipos + HMAC son
no-negociables.

## Referencias

- `rules/unsafe_deserializers.json`
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html).
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- [ysoserial](https://github.com/frohoff/ysoserial).
- [ysoserial.net](https://github.com/pwntester/ysoserial.net).
- [marshalsec](https://github.com/frohoff/marshalsec).
