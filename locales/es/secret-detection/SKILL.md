---
id: secret-detection
language: es
source_revision: "9808b0fa"
version: "1.3.0"
title: "Detección de secretos"
description: "Detectar y evitar secretos, claves de API, tokens y credenciales codificados en el código"
category: prevention
severity: critical
applies_to:
  - "antes de cada commit"
  - "al revisar código que maneja credenciales"
  - "al escribir archivos de configuración"
  - "al crear plantillas .env"
languages: ["*"]
token_budget:
  minimal: 800
  compact: 1300
  full: 2000
rules_path: "rules/"
tests_path: "tests/"
related_skills: ["dependency-audit", "supply-chain-security"]
last_updated: "2026-05-13"
sources:
  - "Guía de gestión de secretos de OWASP"
  - "CWE-798: Uso de credenciales codificadas"
  - "CWE-259: Uso de contraseñas codificadas"
  - "NIST SP 800-57 Parte 1 Rev. 5: Gestión de claves"
---

# Detección de secretos

## Reglas (para agentes de IA)

### SIEMPRE
- Revisar literales de cadena de más de 20 caracteres cerca de palabras clave como
  `api_key`, `secret`, `token`, `password`, `credential`, `auth`, `bearer`,
  `private_key`, `access_key`, `client_secret`, `refresh_token`.
- Marcar cualquier cadena que coincida con patrones conocidos: AWS (`AKIA…`),
  GitHub PAT (`ghp_`, `gho_`, `github_pat_`), OpenAI (`sk-…`), Anthropic
  (`sk-ant-api03-…`), Slack (`xox[baprs]-`), Stripe (`sk_live_…`), Google
  (`AIza…`), Azure AD, Databricks (`dapi…`), Twilio (`SK…`), SendGrid
  (`SG.…`), npm (`npm_…`), PyPI (`pypi-…`), Heroku (UUID con palabra clave),
  DigitalOcean (`dop_v1_…`), HashiCorp Vault (`hvs.…`), Supabase (`sbp_…`),
  Linear (`lin_api_…`), bloques de clave privada PEM, JWT.
- Reemplazar los secretos por variables de entorno o un gestor de secretos
  (Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, Doppler).
- Validar que existan `.gitignore` y `.env.example`. El `.env` real nunca
  debe estar versionado.

### NUNCA
- Cometer un secreto real al repositorio.
- Reusar un secreto entre entornos (dev/staging/prod).
- Escribir secretos en archivos de log o telemetría.
- Pasar secretos por la línea de comandos ni por la URL HTTP.

### FALSOS POSITIVOS CONOCIDOS
- Datos de ejemplo en la documentación oficial de AWS (`AKIAIOSFODNN7EXAMPLE`).
- Hashes de commit de git (40 caracteres hexadecimales).
- Colores hexadecimales CSS (`#abcdef`).
- Marcadores literales como `YOUR_API_KEY_HERE`.

## Contexto

Cuando un secreto se filtra a un repositorio público, los atacantes empiezan a
explotarlo en minutos. La defensa principal son los controles preventivos en
pre-commit y CI; la rotación posterior es complementaria, no sustitutiva.

## Referencias

- OWASP Secrets Management Cheat Sheet
- CWE-798, CWE-259, CWE-321
- NIST SP 800-57 Parte 1 Rev. 5
