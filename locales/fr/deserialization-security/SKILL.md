---
id: deserialization-security
language: fr
source_revision: "4c215e6f"
version: "1.0.0"
title: "Sécurité de la désérialisation"
description: "Bloquer la désérialisation non sûre en Java, Python, .NET, PHP, Ruby, Node.js — chaînes de gadgets, allowlist de types, alternatives plus sûres"
category: prevention
severity: critical
applies_to:
  - "lors de la génération de code désérialisant des données d'une source non fiable"
  - "lors du câblage de cookies, sessions, message queues ou payloads RPC"
  - "lors de la revue d'usages de pickle / unserialize / Marshal / ObjectInputStream / BinaryFormatter"
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

# Sécurité de la désérialisation

## Règles (pour les agents IA)

### TOUJOURS
- Préférer des formats **structurels, validés par schéma** (JSON avec
  un validateur JSON Schema, Protobuf, FlatBuffers, MessagePack avec
  une carte de types explicite) plutôt que des sérialiseurs natifs
  polymorphes. Le trade-off "économiser 10 lignes de mapping" ne
  vaut jamais une primitive RCE.
- Quand un désérialiseur polymorphe est inévitable, configurer une
  **allowlist stricte de types** au niveau du framework
  (`PolymorphicTypeValidator` de Jackson, fastjson safeMode,
  `KnownTypeAttribute` de .NET, `Whitelist` de XStream). Le défaut
  "any class" est la source de toute CVE moderne de désérialisation
  Java.
- Signer et authentifier tout cookie ou token portant des données
  sérialisées avec une clé aléatoire fraîche (HMAC-SHA-256, minimum).
  Ne jamais désérialiser avant la vérification HMAC.
- Faire tourner les chemins de désérialisation avec les capacités
  minimales requises par le format (pas de filesystem, pas de réseau,
  pas de subprocess, pas de réflexion) — p. ex. patterns
  `ObjectInputFilter` Java ; Python dans un namespace restreint.
- Traiter chacune des fonctions suivantes comme des "primitives de
  désérialisation d'input non fiable" : Java
  `ObjectInputStream.readObject`, Jackson avec `enableDefaultTyping`,
  SnakeYAML `Yaml.load()`, XStream `fromXML`, Python
  `pickle.load(s)` / `cPickle` / `dill` / `joblib.load`, `yaml.load`
  (Loader par défaut), `numpy.load(allow_pickle=True)`, `torch.load`,
  PHP `unserialize`, .NET `BinaryFormatter` /
  `ObjectStateFormatter` / `NetDataContractSerializer` /
  `LosFormatter`, Ruby `Marshal.load` / `YAML.load` (Psych ≤ 3.0).
  Ajouter l'une d'elles à un chemin de gestion de requête exige une
  revue de sécurité explicite.

### JAMAIS
- Passer des octets non fiables à l'une des primitives ci-dessus sans
  wrapper HMAC-authentifié. Même avec wrapper, préférer un format non
  polymorphe.
- Utiliser Java Jackson avec `objectMapper.enableDefaultTyping()` ou
  `@JsonTypeInfo(use = Id.CLASS)`. Le défaut
  `LAMINAR_INTERNAL_DEFAULT` produit une chaîne de gadgets par
  class-id (ysoserial / marshalsec).
- Utiliser SnakeYAML `new Yaml()` sans spécifier explicitement un
  `SafeConstructor` (ou `Constructor` avec allowlist). Le constructeur
  par défaut est la source des CVE communes de RCE YAML en Java.
- Utiliser Python `pickle.loads` sur des données venant d'un socket
  réseau, d'une colonne DB, d'une clé de cache Redis ou de tout
  endroit traversant une frontière de confiance. Aucune validation ne
  rend pickle sûr.
- Utiliser Python `yaml.load(data)` (sans `Loader=yaml.SafeLoader`).
  PyYAML a changé le défaut en 6.0 pour échouer bruyamment — d'anciens
  chemins de code livrent encore le défaut non sûr.
- Utiliser Python `torch.load(path)` sur un checkpoint téléchargé
  sans `weights_only=True` (PyTorch ≥ 2.6 a True par défaut ; les
  versions plus anciennes atteignent pickle et exécutent du code
  arbitraire).
- Utiliser PHP `unserialize()` sur des données cookie / POST / GET.
  Le format sérialisé PHP a une longue histoire de chaînes de gadgets
  par méthodes magiques (`__wakeup`, `__destruct`, `__toString`).
- Utiliser .NET `BinaryFormatter`, `NetDataContractSerializer`,
  `ObjectStateFormatter`, `LosFormatter` sur tout input traversant
  une frontière de confiance. Microsoft marque `BinaryFormatter`
  comme obsolète et non sûr.
- Faire confiance au contenu d'un Ruby `Marshal.load` venant de hors
  du même processus. Même restriction pour `YAML.load` sur un Psych
  ancien.

### FAUX POSITIFS CONNUS
- RPC interne où les deux côtés sont contrôlés par l'opérateur, les
  données sont authentifiées de bout en bout (mTLS + HMAC), et le
  choix de format est pragmatique (p. ex. des services Java utilisant
  ObjectInputStream sur un socket TLS+mTLS-only peuvent être
  acceptables dans certains stacks legacy).
- Désérialisation au build-time / configuration-time de fichiers
  livrés dans le dépôt (fixtures de test pickle, etc.) — mais les
  marquer clairement et ne jamais les charger depuis un téléchargement.
- Les formats de session cryptographiquement authentifiés comme les
  sessions cookie signées par défaut de Rails sont un usage
  intentionnel de Marshal, mais seulement parce que le HMAC
  conditionne la désérialisation.

## Contexte (pour les humains)

Les vulnérabilités de désérialisation sont la primitive RCE la plus
fiable des stacks d'entreprise modernes. L'économie est simple :
quand le sérialiseur autorise l'instanciation arbitraire de classes,
la codebase a déjà importé des milliers de classes — dont beaucoup
ont des side-effects dans leurs callbacks `readObject`, `__reduce__`,
`__wakeup`, `Read*`. Une chaîne de gadgets combine ces side-effects
en RCE.

ysoserial (Java), ysoserial.net (.NET), marshalsec (Java) et les
catalogues de gadgets pickle Python sont du tooling mature. À toute
question "est-ce exploitable ?", la réponse est "oui, avec les
gadgets déjà sur ton classpath".

Le fix n'est pas de filtrer — c'est d'utiliser un format qui
n'autorise pas l'instanciation arbitraire de classes en premier
lieu. La plupart des services modernes embarquent du JWT signé /
JSON sur mTLS. Là où un format polymorphe est inévitable, allowlist
de types + HMAC ne sont pas négociables.

## Références

- `rules/unsafe_deserializers.json`
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html).
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- [ysoserial](https://github.com/frohoff/ysoserial).
- [ysoserial.net](https://github.com/pwntester/ysoserial.net).
- [marshalsec](https://github.com/frohoff/marshalsec).
