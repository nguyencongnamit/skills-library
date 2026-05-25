---
id: mobile-security
language: zh-Hans
source_revision: "afe376a8"
version: "1.0.0"
title: "移动应用安全"
description: "Android 和 iOS 加固:exported 组件、ATS、keychain、certificate pinning、root/jailbreak 检测"
category: hardening
severity: high
applies_to:
  - "在生成 Android (Kotlin / Java) 应用代码或 manifest 时"
  - "在生成 iOS (Swift / Objective-C) 应用代码时"
  - "在生成 React Native / Flutter 原生模块时"
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

# 移动应用安全

## 规则(面向 AI 代理)

### 必须
- **Android**:`AndroidManifest.xml` 里每一个 `<activity>`、
  `<service>`、`<receiver>`、`<provider>` 要么 `android:exported="false"`,
  要么显式声明 intent filter 且是有意 export 的。Android 12 (API 31)
  之后,声明了 intent-filter 就必须显式写 `android:exported`。
- **Android**:secret 放在 **Android Keystore** 里(`KeyStore` /
  EncryptedSharedPreferences 配 `MasterKey`)。绝不放在明文
  `SharedPreferences`、明文文件或 `BuildConfig` 里。
- **iOS**:secret 放在 **Keychain** 里,用
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` 或更严。不要放
  在 `UserDefaults`、plist 或文件里。
- **iOS**:`Info.plist` 中保持 App Transport Security (ATS) 开启。如
  果非要例外,用 `NSExceptionDomains` 限定到具体 host。
- 对你掌控的后端,要用 **certificate pinning**(优先 public key
  pinning)验证服务端 TLS 证书。Android 用
  `OkHttp.CertificatePinner`,iOS 用
  `URLSessionDelegate didReceiveChallenge`,或者用框架自带的 pinning
  模块。
- release 构建要做混淆 / 瘦身(Android R8 / ProGuard 配
  `proguard-rules.pro`;iOS bitcode + Swift symbol stripping)。从
  release 构建中剥离 debug 日志。
- 对高风险 app(银行、支付、企业)检测 root / 越狱设备并降低敏感度
  (拒绝支付、拒绝接入受管 profile)。在 Android 上用 Play Integrity
  API,在 iOS 上用 `DeviceCheck` / `AppAttest` 作为权威的远程认证。

### 禁止
- 不要把 API key、签名 key 或后端 secret 放进 source / resources /
  `strings.xml` / `BuildConfig` / `Info.plist`。改用从后端下发的、按
  设备 scope 的短期 token。
- 不要给存储凭据的 app 设 `android:allowBackup="true"` —— 备份的数据
  在开发机上是可读的。用 `android:fullBackupContent` 来排除敏感
  路径。
- 不要在 release 构建里设 `android:debuggable="true"`,也不要用
  `<application android:networkSecurityConfig>` 允许 cleartext 到任意
  host。
- 不要在 iOS 上全 app 关闭 ATS(`NSAllowsArbitraryLoads=true`)。如
  果不得不弱化,要按 host 分别 scope。
- 不要实现返回 "trust all" 的自定义 TLS / 证书处理
  (`X509TrustManager.checkServerTrusted` 空方法体,
  `URLSessionDelegate` 一律信任)。这是流到生产环境里的 Android 头
  号安全问题。
- 不要把用户输入传给 `WebView.loadUrl` / `WKWebView.load` 而不校验
  scheme;绝不要启用 `WebSettings.setAllowFileAccessFromFileURLs(true)`
  或 `setUniversalAccessFromFileURLs(true)`。
- 不要实现生物识别认证而不让 `BiometricPrompt` 的
  `setUserAuthenticationRequired(true)` 把 key 绑定上 —— 单一的生物
  识别 "true" 没有密码学挑战,什么都证明不了。
- 不要把 request/response 的完整 body(包括 `Authorization` header)
  打到日志 —— 它们最后会出现在 adb / xcrun 日志里。

### 已知误报
- 嵌入在二进制里的公开只读 ID(analytics public key、公开 DSN)不
  是 secret;它们本来就要在那里。
- debug variant 默认 `debuggable=true` 是正常的 —— 这条规则只针对
  release 构建。
- 用于 OAuth 回调的自定义 URL scheme(`myapp://`)是预期内的;要确
  保对应的 intent filter 是受限的,而且 `state` 参数有被校验。

## 背景(面向人类)

移动安全清晰地分成两半:**二进制里有什么**(secret、debug flag、
exported 组件、pinning)和**运行时发生了什么**(TLS 信任、keychain
访问、生物识别绑定)。OWASP MASVS v2 给出权威的可测试控制项;MASTG
则是流程化的测试指南。

AI 助手经常会生成 `allowBackup=true`、没开 ProGuard、把 API key 硬
编码在 `strings.xml` 里的 Android 代码,以及不带校验就调
`SecCertificateCreateWithData` 的 iOS 代码。这个 skill 就是用来对
冲这一现象的。

## 参考

- `checklists/android_manifest.yaml`
- `checklists/ios_keychain_ats.yaml`
- [OWASP MASVS](https://mas.owasp.org/MASVS/).
- [OWASP MASTG](https://mas.owasp.org/MASTG/).
