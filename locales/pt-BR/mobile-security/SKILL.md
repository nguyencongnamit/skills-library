---
id: mobile-security
language: pt-BR
source_revision: "afe376a8"
version: "1.0.0"
title: "Segurança de aplicações móveis"
description: "Hardening Android e iOS: componentes exported, ATS, keychain, certificate pinning, detecção de root/jailbreak"
category: hardening
severity: high
applies_to:
  - "ao gerar código de app Android (Kotlin / Java) ou manifests"
  - "ao gerar código de app iOS (Swift / Objective-C)"
  - "ao gerar módulos nativos React Native / Flutter"
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

# Segurança de aplicações móveis

## Regras (para agentes de IA)

### SEMPRE
- **Android**: toda `<activity>`, `<service>`, `<receiver>`,
  `<provider>` no `AndroidManifest.xml` tem `android:exported="false"`
  *ou* declara explicitamente um intent filter e está exportado de
  propósito. A partir do Android 12 (API 31), `android:exported` é
  obrigatório quando um intent-filter é declarado.
- **Android**: guarde segredos no **Android Keystore** (`KeyStore` /
  EncryptedSharedPreferences com `MasterKey`). Nunca em
  `SharedPreferences` em texto plano, arquivos em texto plano ou
  `BuildConfig`.
- **iOS**: guarde segredos no **Keychain** com
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` ou mais
  restrito. Não guarde em `UserDefaults`, plist ou arquivos.
- **iOS**: mantenha o App Transport Security (ATS) habilitado no
  `Info.plist`. Se for necessária exceção, restrinja a um host
  específico com `NSExceptionDomains`.
- Valide o certificado TLS do servidor com **certificate pinning**
  (pinning de public key preferido) para backends que você controla.
  Use `OkHttp.CertificatePinner` no Android,
  `URLSessionDelegate didReceiveChallenge` no iOS, ou o módulo de
  pinning do framework.
- Ofusque / encurte os builds de release (Android R8 / ProGuard com
  `proguard-rules.pro`; iOS bitcode + Swift symbol stripping).
  Remova debug logs dos builds de release.
- Detecte dispositivos com root / jailbreak para apps de alto risco
  (bancário, pagamento, enterprise) e reduza a sensibilidade
  (bloquear pagamentos, recusar entrada em managed profile). Use a
  Play Integrity API no Android e `DeviceCheck` / `AppAttest` no iOS
  como atestação autoritativa.

### NUNCA
- Embarque API keys, signing keys ou segredos de backend em source /
  resources / `strings.xml` / `BuildConfig` / `Info.plist`. Em vez
  disso, emita tokens de vida curta, escopados ao device, a partir
  de um backend.
- Defina `android:allowBackup="true"` para apps que guardam
  credenciais — os dados do backup são legíveis em máquinas de
  desenvolvedores. Use `android:fullBackupContent` para excluir
  paths sensíveis.
- Defina `android:debuggable="true"` em builds de release, ou um
  `<application android:networkSecurityConfig>` que permita
  cleartext para hosts arbitrários.
- Desabilite ATS app-wide no iOS (`NSAllowsArbitraryLoads=true`). Se
  for necessário enfraquecer, escope por-host.
- Implemente handling custom de TLS / certificado que retorne
  "trust all" (`X509TrustManager.checkServerTrusted` com corpo
  vazio, `URLSessionDelegate` always-trust). É o #1 finding de
  segurança Android que vai para produção.
- Passe input de usuário para `WebView.loadUrl` / `WKWebView.load`
  sem validar o scheme; nunca habilite
  `WebSettings.setAllowFileAccessFromFileURLs(true)` nem
  `setUniversalAccessFromFileURLs(true)`.
- Implemente auth biométrico sem
  `setUserAuthenticationRequired(true)` do `BiometricPrompt`
  amarrando a key — um biométrico "true" sozinho não prova nada sem
  um challenge criptográfico.
- Logue bodies completos de request/response incluindo headers
  `Authorization` — eles vão parar em logs adb / xcrun.

### FALSOS POSITIVOS CONHECIDOS
- IDs públicos somente leitura (public key de analytics, DSN
  público) embutidos no binário não são segredos; eles estão lá de
  propósito.
- O default `debuggable=true` em variantes debug é normal — a regra
  se aplica a builds de release.
- URL schemes custom (`myapp://`) para callbacks OAuth são
  esperados; garanta que o intent filter correspondente está
  restrito e que o parâmetro `state` é verificado.

## Contexto (para humanos)

A segurança mobile separa-se claramente em **o que está no binário**
(segredos, debug flags, componentes exported, pinning) e **o que
acontece em runtime** (trust TLS, acesso ao keychain, binding
biométrico). OWASP MASVS v2 fornece os controles testáveis
autoritativos; o MASTG é o guia procedural de teste.

Assistentes de IA frequentemente geram código Android com
`allowBackup=true`, sem ProGuard, com API keys hardcoded em
`strings.xml`, e código iOS que chama
`SecCertificateCreateWithData` sem verificação. Este skill é o
contrapeso.

## Referências

- `checklists/android_manifest.yaml`
- `checklists/ios_keychain_ats.yaml`
- [OWASP MASVS](https://mas.owasp.org/MASVS/).
- [OWASP MASTG](https://mas.owasp.org/MASTG/).
