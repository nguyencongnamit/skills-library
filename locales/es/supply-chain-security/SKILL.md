---
id: supply-chain-security
language: es
source_revision: "fbb3a823a2a0"
version: "1.0.0"
title: "Seguridad de la cadena de suministro"
description: "Detectar paquetes maliciosos, typosquats, confusión de dependencias y compromisos del registro"
category: prevention
severity: critical
applies_to:
  - "al instalar dependencias nuevas"
  - "al actualizar versiones bloqueadas (lockfiles)"
  - "al añadir registros privados o de organización"
languages: ["*"]
token_budget:
  minimal: 900
  compact: 1300
  full: 2200
rules_path: "rules/"
related_skills: ["dependency-audit", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "OWASP Top 10 — A06: Componentes vulnerables y obsoletos"
  - "MITRE ATT&CK T1195.002 — Compromiso de cadena de suministro de software"
  - "NIST SP 800-161r1: Gestión de riesgos en la cadena de suministro"
---

# Seguridad de la cadena de suministro

## Reglas (para agentes de IA)

### SIEMPRE
- Verificar el nombre del paquete frente a la base de typosquats antes de
  instalarlo. Errores comunes: `reqests`/`request` por `requests`,
  `colourama` por `colorama`, `lodahs` por `lodash`.
- Fijar versiones con un lockfile (`package-lock.json`, `poetry.lock`,
  `Cargo.lock`, `go.sum`). Habilitar la verificación de integridad
  (`npm ci`, `pip install --require-hashes`).
- Comprobar contra la base de incidentes documentados (xz-utils
  CVE-2024-3094, `coa`, `eslint-scope`, `ultralytics`, `polyfill.io`,
  `pytorch-nightly`).
- Bloquear ejecución de hooks de instalación cuando sea posible
  (`--ignore-scripts`, `npm config set ignore-scripts true`).

### NUNCA
- Instalar un paquete porque "su nombre se ve correcto" sin verificación.
- Permitir que un paquete privado y otro público coincidan en nombre
  (confusión de dependencias).
- Confiar en una URL `curl | bash` sin pin de SHA-256.
- Aceptar actualizaciones de mantenedores que se publicaron en las últimas
  72 horas sin auditoría.

### FALSOS POSITIVOS CONOCIDOS
- Paquetes oficiales con nombres muy cortos (`fs`, `os`, `re`).
- Forks legítimos con prefijos `@org/`.

## Contexto

La cadena de suministro de software es uno de los vectores de ataque con
mayor amplificación: comprometer un mantenedor puede afectar a miles de
consumidores. Mantén el inventario (SBOM), exige firmas y revisa cualquier
cambio de propiedad o publicación inusual.

## Referencias

- OWASP A06:2021
- MITRE ATT&CK T1195.002
- NIST SP 800-161r1
- SLSA — Supply-chain Levels for Software Artifacts
