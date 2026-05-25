---
id: mobile-security
language: fr
source_revision: "afe376a8"
version: "1.0.0"
title: "Sécurité des applications mobiles"
description: "Hardening Android et iOS : composants exported, ATS, keychain, certificate pinning, détection de root/jailbreak"
category: hardening
severity: high
applies_to:
  - "lors de la génération de code d'app Android (Kotlin / Java) ou de manifests"
  - "lors de la génération de code d'app iOS (Swift / Objective-C)"
  - "lors de la génération de modules natifs React Native / Flutter"
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

# Sécurité des applications mobiles

## Règles (pour les agents IA)

### TOUJOURS
- **Android** : chaque `<activity>`, `<service>`, `<receiver>`,
  `<provider>` dans `AndroidManifest.xml` a soit
  `android:exported="false"`, *soit* déclare explicitement un intent
  filter et est exporté à dessein. Depuis Android 12 (API 31),
  `android:exported` est obligatoire dès qu'un intent-filter est
  déclaré.
- **Android** : stocker les secrets dans le **Android Keystore**
  (`KeyStore` / EncryptedSharedPreferences avec `MasterKey`). Jamais
  dans des `SharedPreferences` en clair, des fichiers en clair, ou
  `BuildConfig`.
- **iOS** : stocker les secrets dans le **Keychain** avec
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` ou plus strict.
  Pas dans `UserDefaults`, plist ou fichiers.
- **iOS** : garder App Transport Security (ATS) activé dans
  `Info.plist`. Si une exception est requise, la scoper à un host
  spécifique avec `NSExceptionDomains`.
- Valider le certificat TLS du serveur avec **certificate pinning**
  (pinning de public key préféré) pour les backends que vous
  contrôlez. Utiliser `OkHttp.CertificatePinner` sur Android,
  `URLSessionDelegate didReceiveChallenge` sur iOS, ou le module de
  pinning du framework.
- Obfusquer / réduire les builds de release (Android R8 / ProGuard
  avec `proguard-rules.pro` ; iOS bitcode + Swift symbol stripping).
  Retirer les debug logs des builds de release.
- Détecter les appareils rootés / jailbreakés pour les apps à fort
  risque (bancaire, paiement, entreprise) et réduire la sensibilité
  (bloquer les paiements, refuser de rejoindre un managed profile).
  Utiliser la Play Integrity API sur Android et
  `DeviceCheck` / `AppAttest` sur iOS comme attestation faisant
  autorité.

### JAMAIS
- Livrer des API keys, signing keys ou secrets de backend dans
  source / resources / `strings.xml` / `BuildConfig` / `Info.plist`.
  Émettre plutôt des tokens courts, scopés à l'appareil, depuis un
  backend.
- Mettre `android:allowBackup="true"` sur des apps qui stockent des
  credentials — les données backupées sont lisibles sur les machines
  de développeurs. Utiliser `android:fullBackupContent` pour exclure
  les paths sensibles.
- Mettre `android:debuggable="true"` dans des builds de release, ou
  un `<application android:networkSecurityConfig>` qui autorise du
  cleartext vers des hosts arbitraires.
- Désactiver ATS au niveau de l'app sur iOS
  (`NSAllowsArbitraryLoads=true`). S'il faut l'affaiblir, scoper
  par host.
- Implémenter un handling custom TLS / certificat qui retourne
  "trust all" (`X509TrustManager.checkServerTrusted` corps vide,
  `URLSessionDelegate` always-trust). C'est le #1 finding de
  sécurité Android livré en production.
- Passer l'input utilisateur à `WebView.loadUrl` / `WKWebView.load`
  sans validation du scheme ; ne jamais activer
  `WebSettings.setAllowFileAccessFromFileURLs(true)` ou
  `setUniversalAccessFromFileURLs(true)`.
- Implémenter l'auth biométrique sans
  `setUserAuthenticationRequired(true)` de `BiometricPrompt` liant
  la clé — un biométrique "true" seul ne prouve rien sans challenge
  cryptographique.
- Logguer les bodies complets de request/response avec les headers
  `Authorization` — ils se retrouvent dans les logs adb / xcrun.

### FAUX POSITIFS CONNUS
- Les IDs publics en lecture seule (public key d'analytics, DSN
  public) embarqués dans le binaire ne sont pas des secrets ; ils
  sont censés être là.
- Le `debuggable=true` par défaut sur les variantes debug est
  normal — la règle s'applique aux builds de release.
- Les URL schemes custom (`myapp://`) pour les callbacks OAuth sont
  attendus ; s'assurer que l'intent filter correspondant est
  restreint et que le paramètre `state` est vérifié.

## Contexte (pour les humains)

La sécurité mobile se sépare proprement en **ce qui est dans le
binaire** (secrets, debug flags, composants exported, pinning) et
**ce qui se passe à l'exécution** (trust TLS, accès keychain,
binding biométrique). OWASP MASVS v2 fournit les controls testables
faisant autorité ; le MASTG est le guide de test procédural.

Les assistants IA génèrent fréquemment du code Android avec
`allowBackup=true`, sans ProGuard, avec des API keys en dur dans
`strings.xml`, et du code iOS qui appelle
`SecCertificateCreateWithData` sans vérification. Ce skill est le
contrepoids.

## Références

- `checklists/android_manifest.yaml`
- `checklists/ios_keychain_ats.yaml`
- [OWASP MASVS](https://mas.owasp.org/MASVS/).
- [OWASP MASTG](https://mas.owasp.org/MASTG/).
