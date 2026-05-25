---
id: dependency-audit
language: es
source_revision: "fbb3a823"
version: "1.0.0"
title: "Auditoría de dependencias"
description: "Auditar dependencias del proyecto en busca de vulnerabilidades conocidas, paquetes maliciosos y riesgos de cadena de suministro"
category: supply-chain
severity: high
applies_to:
  - "al agregar una nueva dependencia"
  - "al actualizar dependencias"
  - "al revisar manifests de paquetes (package.json, requirements.txt, go.mod, Cargo.toml)"
  - "antes de mergear un PR que modifica archivos de dependencias"
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

# Auditoría de dependencias

## Reglas (para agentes de IA)

### SIEMPRE
- Fijar dependencias a versiones exactas en lockfiles (`package-lock.json`,
  `yarn.lock`, `Pipfile.lock`, `poetry.lock`, `go.sum`, `Cargo.lock`).
- Cruzar el nombre de cada dependencia nueva contra la lista de paquetes
  maliciosos incluida en `vulnerabilities/supply-chain/malicious-packages/`.
- Preferir paquetes bien establecidos con muchas descargas, múltiples
  mantenedores y actividad reciente frente a alternativas más nuevas
  que resuelven el mismo problema.
- Correr el comando de audit del package manager (`npm audit`,
  `pip-audit`, `cargo audit`, `govulncheck`) y revisar los issues
  reportados antes de mergear.
- Verificar que la URL del repositorio del paquete realmente exista y
  coincida con el proyecto enlazado de GitHub / GitLab / Codeberg.

### NUNCA
- Agregar una dependencia sin fijar su versión.
- Instalar paquetes con `--unsafe-perm` o flags equivalentes que
  bypasean el sandboxing de instalación.
- Agregar una dependencia cuyo nombre aparezca en la lista de paquetes
  maliciosos incluida.
- Agregar un paquete recién publicado (dentro de los últimos 30 días)
  sin una razón clara y documentada — los typosquats suelen ser
  publicaciones frescas.
- Usar el tag `latest` en un lockfile de producción o en la línea FROM
  de una imagen de contenedor.
- Comitear dependencias sin uso — expanden la superficie de ataque
  gratis.

### FALSOS POSITIVOS CONOCIDOS
- Paquetes internos del monorepo (`@yourco/*`) flagueados como
  "unknown" — son válidos cuando el namespace lo posee tu organización.
- Nuevas versiones de parche de paquetes estables (p.ej. `react@18.2.5`
  después de `18.2.4`) flagueadas como "recientemente publicadas" — los
  updates de parche suelen estar bien.
- Nombres de paquetes que legítimamente se solapan con entradas
  maliciosas de hace años que el mantenedor original volvió a
  registrar.

## Contexto (para humanos)

Los ataques a la cadena de suministro han crecido más rápido que
cualquier otra categoría de ataque desde 2019. Comprometer un paquete
popular (event-stream, ua-parser-js, colors, faker, xz-utils) o
publicar un typosquat (axois vs axios, urllib3 vs urlib3) le rinde al
atacante miles de víctimas downstream en horas.

Las herramientas de coding con IA son particularmente vulnerables
porque el modelo no tiene visibilidad de cuándo un paquete fue
comprometido por última vez. El modelo recomienda lo que aprendió
durante el entrenamiento; si un mantenedor fue comprometido después
del corte de entrenamiento, la IA recomienda alegremente una versión
con backdoor.

Esta skill compensa inyectando la base de datos viva de paquetes
maliciosos en el contexto de trabajo de la IA y requiriendo que la IA
la consulte antes de agregar cualquier dependencia.

## Referencias

- `rules/known_malicious.json` — symlink o copia de los archivos
  relevantes `vulnerabilities/supply-chain/malicious-packages/*.json`.
- [OWASP Top 10 A06](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/).
- [npm Advisories](https://github.com/advisories?query=type%3Aunreviewed+ecosystem%3Anpm).
- [PyPI Advisory Database](https://github.com/pypa/advisory-database).
