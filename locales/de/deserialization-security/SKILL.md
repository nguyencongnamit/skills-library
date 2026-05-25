---
id: deserialization-security
language: de
source_revision: "4c215e6f"
version: "1.0.0"
title: "Deserialisierungs-Sicherheit"
description: "Unsichere Deserialisierung in Java, Python, .NET, PHP, Ruby, Node.js blockieren — Gadget-Chains, Type-Allowlisting, sicherere Alternativen"
category: prevention
severity: critical
applies_to:
  - "beim Erzeugen von Code, der Daten aus nicht vertrauenswürdiger Quelle deserialisiert"
  - "beim Verdrahten von Cookies, Sessions, Message Queues oder RPC-Payloads"
  - "beim Review von pickle / unserialize / Marshal / ObjectInputStream / BinaryFormatter"
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

# Deserialisierungs-Sicherheit

## Regeln (für KI-Agenten)

### IMMER
- **Strukturelle, schema-validierte** Formate bevorzugen (JSON mit
  JSON-Schema-Validator, Protobuf, FlatBuffers, MessagePack mit
  explizitem Type-Map) statt polymorpher nativer Serializer. Der
  Trade-off "10 Zeilen Mapping-Code gespart" lohnt sich niemals
  gegen ein RCE-Primitiv.
- Wenn ein polymorpher Deserializer unvermeidbar ist, eine **strikte
  Type-Allowlist** auf Framework-Ebene konfigurieren (Jackson
  `PolymorphicTypeValidator`, fastjson safeMode, .NET
  `KnownTypeAttribute`, XStream `Whitelist`). Der Default "any
  class" ist die Quelle jeder modernen Java-Deserialisierungs-CVE.
- Jedes Cookie oder Token, das serialisierte Daten trägt, mit einem
  frischen Zufallsschlüssel signieren und authentifizieren
  (HMAC-SHA-256, mindestens). Niemals vor der HMAC-Verifizierung
  deserialisieren.
- Deserialisierungs-Code-Pfade mit den minimalen Capabilities laufen
  lassen, die das Format braucht (kein Filesystem, kein Netzwerk,
  kein Subprozess, keine Reflection) — z. B. Java
  `ObjectInputFilter`-Patterns; Python in einem eingeschränkten
  Namespace.
- Folgende Funktionen als "Untrusted-Input-Deserialisierungs-
  Primitive" behandeln: Java `ObjectInputStream.readObject`, Jackson
  mit `enableDefaultTyping`, SnakeYAML `Yaml.load()`, XStream
  `fromXML`, Python `pickle.load(s)` / `cPickle` / `dill` /
  `joblib.load`, `yaml.load` (Default-Loader),
  `numpy.load(allow_pickle=True)`, `torch.load`, PHP `unserialize`,
  .NET `BinaryFormatter` / `ObjectStateFormatter` /
  `NetDataContractSerializer` / `LosFormatter`, Ruby `Marshal.load` /
  `YAML.load` (Psych ≤ 3.0). Eines davon in einem Request-Handling-
  Code-Pfad zu ergänzen, erfordert explizites Security-Review.

### NIE
- Nicht vertrauenswürdige Bytes an eines der obigen Primitive ohne
  HMAC-authentifizierten Wrapper übergeben. Selbst mit Wrapper ein
  nicht-polymorphes Format bevorzugen.
- Java Jackson mit `objectMapper.enableDefaultTyping()` oder
  `@JsonTypeInfo(use = Id.CLASS)` verwenden. Der Default
  `LAMINAR_INTERNAL_DEFAULT` erzeugt eine Class-ID-Gadget-Chain
  (ysoserial / marshalsec).
- SnakeYAML `new Yaml()` ohne expliziten `SafeConstructor` (oder
  `Constructor` mit Allowlist) verwenden. Der Default-Constructor ist
  die Quelle der gängigen Java-YAML-RCE-CVEs.
- Python `pickle.loads` auf Daten aus einem Netzwerk-Socket, einer
  DB-Column, einem Redis-Cache-Key oder irgendwo, was eine Trust-
  Boundary überquert, ausführen. Keine Validierung macht pickle
  sicher.
- Python `yaml.load(data)` (ohne `Loader=yaml.SafeLoader`) verwenden.
  PyYAML hat den Default in 6.0 auf "laut scheitern" geändert —
  ältere Code-Pfade liefern noch den unsicheren Default.
- Python `torch.load(path)` auf einem heruntergeladenen Checkpoint
  ohne `weights_only=True` ausführen (PyTorch ≥ 2.6 hat True als
  Default; ältere Versionen erreichen pickle und führen beliebigen
  Code aus).
- PHP `unserialize()` auf Cookie- / POST- / GET-Daten verwenden. Das
  serialisierte PHP-Format hat eine lange Geschichte von Magic-
  Method-Gadget-Chains (`__wakeup`, `__destruct`, `__toString`).
- .NET `BinaryFormatter`, `NetDataContractSerializer`,
  `ObjectStateFormatter`, `LosFormatter` für irgendeinen Input, der
  eine Trust-Boundary überquert, verwenden. Microsoft markiert
  `BinaryFormatter` als obsolet und unsicher.
- Dem Inhalt eines Ruby `Marshal.load` von ausserhalb desselben
  Prozesses vertrauen. Gleiche Einschränkung für `YAML.load` auf
  älterem Psych.

### BEKANNTE FALSCH-POSITIVE
- Internes RPC, bei dem beide Seiten betreiberkontrolliert sind, die
  Daten End-to-End authentifiziert sind (mTLS + HMAC) und die
  Formatwahl pragmatisch ist (z. B. Java-Services, die
  ObjectInputStream über einen TLS+mTLS-only-Socket nutzen, können in
  manchen Legacy-Stacks akzeptabel sein).
- Build-Time- / Configuration-Time-Deserialisierung von Files, die
  im Repository mitgeliefert werden (pickle-Test-Fixtures etc.) —
  aber klar markieren und nie aus einem Download laden.
- Kryptographisch authentifizierte Session-Formate wie Rails'
  signierte Cookie-Sessions sind beabsichtigter Marshal-Einsatz, aber
  nur, weil HMAC die Deserialisierung gatet.

## Kontext (für Menschen)

Deserialisierungs-Vulnerabilities sind das verlässlichste RCE-
Primitiv in modernen Enterprise-Stacks. Die Ökonomie ist einfach:
Wenn der Serializer beliebige Class-Instanziierung erlaubt, hat die
Codebase bereits tausende Klassen importiert — viele davon mit Side-
Effects in ihren `readObject`-, `__reduce__`-, `__wakeup`-, `Read*`-
Callbacks. Eine Gadget-Chain kombiniert diese Side-Effects zu RCE.

ysoserial (Java), ysoserial.net (.NET), marshalsec (Java) und die
Python-pickle-Gadget-Kataloge sind reifes Tooling. Jede "ist das
ausnutzbar?"-Frage beantwortet sich mit "ja, mit den Gadgets, die du
bereits im Classpath hast".

Der Fix ist nicht zu filtern — sondern ein Format zu verwenden, das
beliebige Class-Instanziierung gar nicht zulässt. Die meisten
modernen Services liefern signierte JWTs / JSON über mTLS aus. Wo ein
polymorphes Format unvermeidbar ist, sind Type-Allowlist + HMAC nicht
verhandelbar.

## Referenzen

- `rules/unsafe_deserializers.json`
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html).
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- [ysoserial](https://github.com/frohoff/ysoserial).
- [ysoserial.net](https://github.com/pwntester/ysoserial.net).
- [marshalsec](https://github.com/frohoff/marshalsec).
