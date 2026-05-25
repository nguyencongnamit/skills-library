---
id: mobile-security
version: "1.0.0"
title: "Mobile Application Security"
description: "Android and iOS hardening: exported components, ATS, keychain, certificate pinning, root/jailbreak detection"
category: hardening
severity: high
applies_to:
  - "when generating Android (Kotlin / Java) app code or manifests"
  - "when generating iOS (Swift / Objective-C) app code"
  - "when generating React Native / Flutter native modules"
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

# Mobile Application Security

## Rules (for AI agents)

### ALWAYS
- **Android**: every `<activity>`, `<service>`, `<receiver>`, `<provider>` in
  `AndroidManifest.xml` either has `android:exported="false"` *or* explicitly
  declares an intent filter and is intentionally exported. As of Android 12
  (API 31), `android:exported` is required when an intent-filter is declared.
- **Android**: store secrets in the **Android Keystore** (`KeyStore` /
  EncryptedSharedPreferences with `MasterKey`). Never in plain
  `SharedPreferences`, plain files, or `BuildConfig`.
- **iOS**: store secrets in the **Keychain** with
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` or stricter. Don't store
  in `UserDefaults`, plist, or files.
- **iOS**: keep App Transport Security (ATS) enabled in `Info.plist`. If an
  exception is required, scope it to a specific host with
  `NSExceptionDomains`.
- Validate the server's TLS certificate with **certificate pinning** (public
  key pinning preferred) for backends you control. Use
  `OkHttp.CertificatePinner` on Android,
  `URLSessionDelegate didReceiveChallenge` on iOS, or your framework's
  pinning module.
- Obfuscate / shrink release builds (Android R8 / ProGuard with
  `proguard-rules.pro`; iOS bitcode + Swift symbol stripping). Strip debug
  logs from release builds.
- Detect rooted / jailbroken devices for high-risk apps (banking, payment,
  enterprise) and reduce sensitivity (block payments, refuse to attach to
  a managed profile). Use the Play Integrity API on Android and
  `DeviceCheck` / `AppAttest` on iOS as the authoritative attestation.

### NEVER
- Ship API keys, signing keys, or backend secrets in source / resources /
  `strings.xml` / `BuildConfig` / `Info.plist`. Issue short-lived,
  device-scoped tokens from a backend instead.
- Set `android:allowBackup="true"` for apps that store credentials — the
  backed-up data is readable on developer machines. Use
  `android:fullBackupContent` to exclude sensitive paths.
- Set `android:debuggable="true"` in release builds, or
  `<application android:networkSecurityConfig>` that allows cleartext to
  arbitrary hosts.
- Disable ATS app-wide on iOS (`NSAllowsArbitraryLoads=true`). If you must
  weaken it, scope per-host.
- Implement custom TLS / certificate handling that returns "trust all"
  (`X509TrustManager.checkServerTrusted` empty body,
  `URLSessionDelegate` always-trust). This is the #1 Android security
  finding shipped to production.
- Pass user input to `WebView.loadUrl` / `WKWebView.load` without scheme
  validation; never enable
  `WebSettings.setAllowFileAccessFromFileURLs(true)` or
  `setUniversalAccessFromFileURLs(true)`.
- Implement biometric auth without `BiometricPrompt`'s
  `setUserAuthenticationRequired(true)` binding the key — biometric "true"
  alone proves nothing without a cryptographic challenge.
- Log full request/response bodies including `Authorization` headers — they
  end up in adb / xcrun logs.

### KNOWN FALSE POSITIVES
- Public read-only IDs (analytics public key, public DSN) embedded in the
  binary are not secrets; they're meant to be there.
- The default debuggable=true on debug variants is normal — the rule applies
  to release builds.
- Custom URL schemes (`myapp://`) for OAuth callbacks are expected; ensure
  the corresponding intent filter is restricted and the `state` parameter is
  verified.

## Context (for humans)

Mobile security splits cleanly into **what's in the binary** (secrets, debug
flags, exported components, pinning) and **what happens at runtime** (TLS
trust, keychain access, biometric binding). OWASP MASVS v2 provides the
authoritative testable controls; the MASTG is the procedural test guide.

AI assistants frequently generate Android code with `allowBackup=true`, no
ProGuard, hardcoded API keys in `strings.xml`, and iOS code that calls
`SecCertificateCreateWithData` with no verification. This skill is the
counterweight.

## References

- `checklists/android_manifest.yaml`
- `checklists/ios_keychain_ats.yaml`
- [OWASP MASVS v2.0](https://mas.owasp.org/MASVS/).
- [OWASP MASTG](https://mas.owasp.org/MASTG/).
- [CWE-919 — Weaknesses in Mobile Applications](https://cwe.mitre.org/data/definitions/919.html).
