---
id: mobile-security
language: de
source_revision: "afe376a8"
version: "1.0.0"
title: "Mobile-Application-Sicherheit"
description: "Android- und iOS-Härtung: exported Components, ATS, Keychain, Certificate Pinning, Root/Jailbreak-Erkennung"
category: hardening
severity: high
applies_to:
  - "beim Erzeugen von Android- (Kotlin / Java) App-Code oder Manifests"
  - "beim Erzeugen von iOS- (Swift / Objective-C) App-Code"
  - "beim Erzeugen von React-Native- / Flutter-Native-Modulen"
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

# Mobile-Application-Sicherheit

## Regeln (für KI-Agenten)

### IMMER
- **Android**: jede `<activity>`, `<service>`, `<receiver>`,
  `<provider>` in `AndroidManifest.xml` hat entweder
  `android:exported="false"` *oder* deklariert explizit einen
  Intent-Filter und ist absichtlich exported. Ab Android 12 (API 31)
  ist `android:exported` Pflicht, wenn ein Intent-Filter deklariert
  wird.
- **Android**: Secrets im **Android Keystore** ablegen (`KeyStore` /
  EncryptedSharedPreferences mit `MasterKey`). Nie in unverschlüsselten
  `SharedPreferences`, Plain-Files oder `BuildConfig`.
- **iOS**: Secrets im **Keychain** ablegen mit
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` oder strenger.
  Nicht in `UserDefaults`, plist oder Dateien.
- **iOS**: App Transport Security (ATS) in `Info.plist` aktiv halten.
  Wenn eine Ausnahme nötig ist, sie per `NSExceptionDomains` auf einen
  bestimmten Host beschränken.
- TLS-Zertifikat des Servers mit **Certificate Pinning**
  (Public-Key-Pinning bevorzugt) für eigene Backends validieren.
  `OkHttp.CertificatePinner` auf Android,
  `URLSessionDelegate didReceiveChallenge` auf iOS, oder das
  Pinning-Modul des Frameworks verwenden.
- Release-Builds obfuskieren / shrinken (Android R8 / ProGuard mit
  `proguard-rules.pro`; iOS bitcode + Swift-Symbol-Stripping). Debug-
  Logs aus Release-Builds entfernen.
- Rooted-/Jailbroken-Geräte für High-Risk-Apps (Banking, Payment,
  Enterprise) erkennen und Empfindlichkeit reduzieren (Zahlungen
  blocken, Beitritt zu Managed Profile verweigern). Play Integrity API
  auf Android und `DeviceCheck` / `AppAttest` auf iOS als
  autoritative Attestation verwenden.

### NIE
- API-Keys, Signing-Keys oder Backend-Secrets in Source / Resources /
  `strings.xml` / `BuildConfig` / `Info.plist` ausliefern.
  Stattdessen kurzlebige, geräte-scoped Tokens vom Backend ausgeben.
- `android:allowBackup="true"` für Apps setzen, die Credentials
  speichern — die gebackupten Daten sind auf Developer-Maschinen
  lesbar. `android:fullBackupContent` verwenden, um sensible Pfade
  auszuschließen.
- `android:debuggable="true"` in Release-Builds setzen, oder ein
  `<application android:networkSecurityConfig>`, das Cleartext zu
  beliebigen Hosts erlaubt.
- ATS auf iOS App-weit deaktivieren (`NSAllowsArbitraryLoads=true`).
  Wenn es geschwächt werden muss, per Host scopen.
- Custom-TLS-/Zertifikatsbehandlung implementieren, die "trust all"
  zurückgibt (`X509TrustManager.checkServerTrusted` leerer Body,
  `URLSessionDelegate` Always-Trust). Das ist der #1 Android-Security-
  Finding in der Produktion.
- User-Input ohne Scheme-Validierung an `WebView.loadUrl` /
  `WKWebView.load` übergeben; nie
  `WebSettings.setAllowFileAccessFromFileURLs(true)` oder
  `setUniversalAccessFromFileURLs(true)` aktivieren.
- Biometric Auth ohne `setUserAuthenticationRequired(true)` von
  `BiometricPrompt` implementieren, das den Key bindet — Biometric
  "true" allein beweist nichts ohne kryptographischen Challenge.
- Vollständige Request-/Response-Bodies inklusive
  `Authorization`-Header loggen — sie landen in adb-/xcrun-Logs.

### BEKANNTE FALSCH-POSITIVE
- Public-Read-Only-IDs (Analytics-Public-Key, Public-DSN), die im
  Binary eingebettet sind, sind keine Secrets; sie sollen dort sein.
- Default `debuggable=true` auf Debug-Varianten ist normal — die Regel
  gilt für Release-Builds.
- Custom-URL-Schemes (`myapp://`) für OAuth-Callbacks sind erwartet;
  sicherstellen, dass der zugehörige Intent-Filter restriktiv ist und
  der `state`-Parameter verifiziert wird.

## Kontext (für Menschen)

Mobile-Security trennt sich sauber in **was im Binary ist** (Secrets,
Debug-Flags, exported Components, Pinning) und **was zur Laufzeit
passiert** (TLS-Trust, Keychain-Zugriff, Biometric-Binding). OWASP
MASVS v2 liefert die autoritativen testbaren Controls; das MASTG ist
der prozedurale Testleitfaden.

KI-Assistenten erzeugen häufig Android-Code mit `allowBackup=true`,
ohne ProGuard, mit hardcodeten API-Keys in `strings.xml`, und
iOS-Code, der `SecCertificateCreateWithData` ohne Verifizierung
aufruft. Dieser Skill ist das Gegengewicht.

## Referenzen

- `checklists/android_manifest.yaml`
- `checklists/ios_keychain_ats.yaml`
- [OWASP MASVS](https://mas.owasp.org/MASVS/).
- [OWASP MASTG](https://mas.owasp.org/MASTG/).
