---
id: mobile-security
language: es
source_revision: "afe376a8"
version: "1.0.0"
title: "Seguridad de aplicaciones móviles"
description: "Hardening Android e iOS: componentes exported, ATS, keychain, certificate pinning, detección de root/jailbreak"
category: hardening
severity: high
applies_to:
  - "al generar código de app Android (Kotlin / Java) o manifests"
  - "al generar código de app iOS (Swift / Objective-C)"
  - "al generar módulos nativos de React Native / Flutter"
languages: ["kotlin", "java", "swift", "objc", "dart", "javascript", "typescript", "xml", "plist"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2500
rules_path: "checklists/"
related_skills: ["crypto-misuse", "secret-detection", "auth-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP MASVS v2.0"
  - "OWASP Mobile Application Security Testing Guide (MASTG)"
  - "CWE-919, CWE-921, CWE-925, CWE-926"
  - "Apple Platform Security Guide"
  - "Android Developers — App Security Best Practices"
---

# Seguridad de aplicaciones móviles

## Reglas (para agentes de IA)

### SIEMPRE
- **Android**: cada `<activity>`, `<service>`, `<receiver>`, `<provider>`
  en `AndroidManifest.xml` tiene `android:exported="false"` *o* declara
  explícitamente un intent filter y se exporta intencionadamente. Desde
  Android 12 (API 31), `android:exported` es obligatorio cuando hay un
  intent-filter declarado.
- **Android**: guardar secretos en el **Android Keystore** (`KeyStore` /
  EncryptedSharedPreferences con `MasterKey`). Jamás en
  `SharedPreferences` planas, archivos planos o `BuildConfig`.
- **iOS**: guardar secretos en el **Keychain** con
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` o más estricto. No
  guardar en `UserDefaults`, plist ni archivos.
- **iOS**: mantener App Transport Security (ATS) habilitado en
  `Info.plist`. Si se requiere excepción, acotarla a un host específico
  con `NSExceptionDomains`.
- Validar el certificado TLS del servidor con **certificate pinning**
  (pinning de public key preferido) para backends que controlas. Usar
  `OkHttp.CertificatePinner` en Android,
  `URLSessionDelegate didReceiveChallenge` en iOS, o el módulo de
  pinning del framework.
- Ofuscar / reducir builds de release (Android R8 / ProGuard con
  `proguard-rules.pro`; iOS bitcode + Swift symbol stripping). Quitar
  logs de debug de los builds de release.
- Detectar dispositivos rooteados / jailbreakeados para apps de alto
  riesgo (banca, pagos, enterprise) y reducir sensibilidad (bloquear
  pagos, rehusar unirse a un managed profile). Usar la Play Integrity
  API en Android y `DeviceCheck` / `AppAttest` en iOS como atestación
  autoritativa.

### NUNCA
- Embarcar API keys, signing keys o secretos de backend en source /
  resources / `strings.xml` / `BuildConfig` / `Info.plist`. Emitir
  tokens de corta duración, scopeados al device, desde un backend.
- Poner `android:allowBackup="true"` en apps que guardan credenciales —
  los datos respaldados son legibles en máquinas de desarrolladores.
  Usar `android:fullBackupContent` para excluir paths sensibles.
- Poner `android:debuggable="true"` en builds de release, o un
  `<application android:networkSecurityConfig>` que permita cleartext a
  hosts arbitrarios.
- Deshabilitar ATS app-wide en iOS (`NSAllowsArbitraryLoads=true`). Si
  hay que debilitarlo, acotar por-host.
- Implementar manejo custom de TLS / certificados que retorne
  "trust all" (`X509TrustManager.checkServerTrusted` con cuerpo vacío,
  `URLSessionDelegate` always-trust). Es el #1 finding de seguridad de
  Android que llega a producción.
- Pasar input de usuario a `WebView.loadUrl` / `WKWebView.load` sin
  validar el scheme; jamás habilitar
  `WebSettings.setAllowFileAccessFromFileURLs(true)` ni
  `setUniversalAccessFromFileURLs(true)`.
- Implementar auth biométrica sin
  `setUserAuthenticationRequired(true)` de `BiometricPrompt` enlazando
  la clave — un biométrico "true" por sí solo no prueba nada sin un
  challenge criptográfico.
- Loggear bodies completos de request/response incluyendo headers
  `Authorization` — terminan en logs de adb / xcrun.

### FALSOS POSITIVOS CONOCIDOS
- IDs públicos de sólo lectura (public key de analytics, DSN público)
  embebidos en el binario no son secretos; están ahí a propósito.
- El default debuggable=true en variantes debug es normal — la regla
  aplica a builds de release.
- URL schemes custom (`myapp://`) para callbacks de OAuth son
  esperados; asegurar que el intent filter correspondiente está
  restringido y que el parámetro `state` se verifica.

## Contexto (para humanos)

La seguridad móvil se parte limpiamente en **qué hay en el binario**
(secretos, debug flags, componentes exported, pinning) y **qué pasa en
runtime** (trust de TLS, acceso al keychain, binding biométrico). OWASP
MASVS v2 provee los controles testables autoritativos; el MASTG es la
guía procedural de testeo.

Los asistentes de IA frecuentemente generan código Android con
`allowBackup=true`, sin ProGuard, con API keys hardcodeadas en
`strings.xml`, y código iOS que llama a `SecCertificateCreateWithData`
sin verificación. Este skill es el contrapeso.

## Referencias

- `checklists/android_manifest.yaml`
- `checklists/ios_keychain_ats.yaml`
- [OWASP MASVS](https://mas.owasp.org/MASVS/).
- [OWASP MASTG](https://mas.owasp.org/MASTG/).
