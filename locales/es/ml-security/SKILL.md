---
id: ml-security
language: es
source_revision: "afe376a8"
version: "1.0.0"
title: "Seguridad de ML / LLM"
description: "Prompt injection, poisoning de modelos, ataques de deserialización, PII en datos de entrenamiento, filtraciones de secretos en notebooks"
category: prevention
severity: high
applies_to:
  - "al generar código que llama a un API de LLM o construye un agente impulsado por LLM"
  - "al generar código que carga modelos de ML desde disco / Hub / S3"
  - "al generar pipelines de datos que ingieren contenido de usuarios para fine-tuning"
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

# Seguridad de ML / LLM

## Reglas (para agentes de IA)

### SIEMPRE
- Tratar cada entrada al modelo — incluidos los outputs de tools y los
  documentos recuperados que se vuelven a meter al prompt — como no
  confiable. La inyección indirecta de prompt vía una página web o
  documento recuperado es el ataque a LLM más común en la naturaleza.
- Sanitizar y re-codificar cualquier cosa que el modelo emita antes de
  pasarla a un sistema downstream: query builder de SQL, shell,
  escritor de archivos, request HTTP, evaluador de código. El output
  del modelo nunca es una clave primaria para la confianza.
- Forzar un **schema de output** con generación estructurada (JSON
  Schema, modo function-call, decoding restringido) cuando el
  siguiente paso consume el output programáticamente. Rechazar todo
  lo que falle validación.
- Mantener un allowlist de tools / nombres de función que el modelo
  puede invocar; rechazar cualquier otra invocación. Aplicar
  autorización por-tool al *usuario humano* del agente, no sólo al
  modelo.
- Para RAG: estampar los documentos recuperados con procedencia, y
  segregar "instrucciones" de "contexto" en el prompt; no dejar que
  los datos recuperados pisen las instrucciones de sistema.
- Al cargar modelos, usar **safetensors** para PyTorch y Hugging
  Face; usar `weights_only=True` con `torch.load` en PyTorch 2.4+;
  jamás cargar archivos `.pkl` / `.pt` arbitrarios desde fuentes no
  confiables.
- Quitar PII, credenciales y secretos de los datos de entrenamiento
  — en la fuente (ingesta de datos), en almacenamiento (cifrado +
  control de acceso) y en el output (filtros / detectores de
  respuesta).
- Rate-limit / cuota en cada endpoint respaldado por LLM. Trackear
  gasto de tokens por tenant.
- Trackear cada prompt + versión de modelo + contexto recuperado
  como log de auditoría; redactar los secretos primero.

### NUNCA
- Hacer `pickle.loads` / `joblib.load` / `dill.loads` / `torch.load`
  de un artefacto traído en runtime desde una fuente no confiable.
  Estos deserializadores ejecutan código arbitrario por diseño.
- Concatenar input de usuario directamente a un prompt que contiene
  instrucciones de mayor confianza: por ej.
  `f"You are a helpful agent. {user_input}"`. Usar un boundary
  templated más separación explícita de rol-sistema.
- Pasar un string derivado de LLM directo a `eval`, `exec`,
  `os.system`, `subprocess(shell=True)`, `vm.runInNewContext` o un
  `.raw()` de SQL.
- Hardcodear API keys de OpenAI / Anthropic / Cohere en notebooks o
  archivos del repo. Usar variables de entorno y el skill
  `secret-detection`.
- Guardar ejemplos de datos de entrenamiento con PII en
  almacenamiento de largo plazo sin consentimiento explícito,
  ventanas de retención y APIs de borrado.
- Confiar en parámetros de modelo provistos por el cliente (nombre
  del modelo, system prompt, lista de tools) sin validación del
  lado del servidor — los clientes degradarán a modelos más
  baratos / débiles / no autorizados.
- Usar un modelo fine-tuneado por un vendor externo sin
  verificación de procedencia / linaje.
- Cachear respuestas de LLM indexadas sólo por el texto del prompt
  — eso mezcla contextos entre usuarios cuando los prompts
  comparten prefijos.

### FALSOS POSITIVOS CONOCIDOS
- Los notebooks de investigación / red-team que ejercitan
  intencionalmente prompts de jailbreak van en un entorno aislado
  sin credenciales de producción.
- Los modelos académicos pre-publicación de autores confiables
  suelen distribuirse como checkpoints `.pt`; convertir a
  safetensors como primer paso.
- Las pipelines de generación de datos sintéticos pueden
  legítimamente producir output crudo de modelo que luego se
  commitea — asegurarse de que esté etiquetado y revisado por PII
  o secretos alucinados inadvertidos.

## Contexto (para humanos)

El OWASP LLM Top 10 (2025) agrupa los ataques más comunes en diez
clases; **LLM01 Prompt Injection** y **LLM05 Improper Output
Handling** son las principales preocupaciones operativas porque se
aplican prácticamente a cada deploy agéntico. NIST AI 100-2 enmarca
las categorías subyacentes de ML adversarial (evasión, poisoning,
extracción); MITRE ATLAS provee una visión de kill-chain.

Este skill asume que Devin (o cualquier asistente de IA) es quien
está construyendo la app que usa LLM. Tratar a la app resultante
como una frontera de seguridad — incluso cuando el "usuario" es
otro agente de IA.

## Referencias

- `rules/prompt_injection_patterns.json`
- `rules/unsafe_deserialization.json`
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/).
- [NIST AI 100-2](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2023.pdf).
- [MITRE ATLAS](https://atlas.mitre.org/).
- [CWE-1426](https://cwe.mitre.org/data/definitions/1426.html) — Improper Validation of Generative AI Output.
