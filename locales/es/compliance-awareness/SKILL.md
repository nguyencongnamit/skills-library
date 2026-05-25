---
id: compliance-awareness
language: es
source_revision: "8e503523"
version: "1.0.0"
title: "Conciencia de cumplimiento"
description: "Mapear el código generado contra controles de OWASP, CWE y SANS Top 25 para trazabilidad"
category: compliance
severity: medium
applies_to:
  - "al generar código en entornos regulados"
  - "al escribir comentarios o documentación relevantes para auditoría"
  - "al refactorizar código que cruza fronteras de cumplimiento (PII, PHI, ámbito PCI)"
languages: ["*"]
token_budget:
  minimal: 400
  compact: 700
  full: 2000
rules_path: "frameworks/"
related_skills: ["secure-code-review", "api-security"]
last_updated: "2026-05-14"
sources:
  - "OWASP Top 10 2021"
  - "CWE Top 25 2023"
  - "PCI DSS v4.0"
  - "HIPAA Security Rule"
  - "SOC 2 Trust Services Criteria"
---

# Conciencia de cumplimiento

## Reglas (para agentes de IA)

### SIEMPRE
- Etiquetar funciones que manejan datos PII / PHI / PCI con un comentario que
  indique la clasificación (p. ej. `// classification: PII`).
- Registrar eventos de auditoría para acciones relevantes para la seguridad
  (login, cambio de permisos, exportación de datos, operaciones admin) —
  registra el quién, el qué, el cuándo, NO el payload sensible.
- Identificar la categoría CWE / OWASP del código relevante para la seguridad
  en comentarios cuando la convención del equipo sea incluir trazabilidad
  (`// addresses CWE-79 — XSS`).
- Para el ámbito PCI, segregar el código de manejo de datos de tarjeta en
  módulos con nombre claro para que las fronteras del ámbito sean visibles.
- Para cargas de trabajo HIPAA, preferir cifrado en reposo Y en tránsito,
  con gestión de claves documentada.

### NUNCA
- Incluir PII / PHI / PCI en mensajes de log, mensajes de error o eventos de
  telemetría.
- Almacenar números de tarjeta, CVV o datos completos de banda magnética
  fuera de un servicio de tokenización conforme a PCI DSS.
- Mezclar código que maneja PII con módulos utilitarios generales sin
  clasificación explícita.
- Generar código que procesa datos personales de residentes de la UE sin
  considerar las obligaciones del RGPD (derecho al olvido, minimización de
  datos, base legal).
- Sugerir workarounds que evaden controles de cumplimiento "para desarrollo"
  — esos workarounds siempre acaban filtrándose a producción.

### FALSOS POSITIVOS CONOCIDOS
- Logs de los *tipos* de datos accedidos ("el usuario accedió al registro de
  reclamo") suelen estar bien; la regla es contra registrar el *contenido*
  de campos sensibles.
- Fixtures de prueba con datos claramente ficticios (números de teléfono
  `555-0100`, PAN `4111-1111-1111-1111`, `John Doe`) no son PII.
- La retención de logs de auditoría es intencionadamente larga (a menudo
  años) y no debería ser filtrada por barridos generales de retención.

## Contexto (para humanos)

Los marcos de cumplimiento (PCI DSS, HIPAA, SOC 2, ISO 27001, RGPD)
prescriben controles pero no dicen al desarrollador qué código escribir.
Esta skill cierra el hueco al adjuntar guía relevante al control a los
pasos de generación de IA, para que el código resultante sea audit-friendly
por defecto.

## Referencias

- `frameworks/owasp_mapping.yaml`
- `frameworks/cwe_mapping.yaml`
- [OWASP Top 10 2021](https://owasp.org/Top10/).
- [CWE Top 25 2023](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html).
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/document_library/).
