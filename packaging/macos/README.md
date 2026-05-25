# secure-code — macOS .pkg installer

Build a macOS installer package for the `skills-check` CLI (part of
**secure-code**) using `pkgbuild` + `productbuild` from Xcode Command
Line Tools.

## Quick Start

```bash
# Build the binary first (from the repo root):
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o skills-check ./cmd/skills-check

# Build the .pkg:
cd packaging/macos
make BINARY=../../skills-check VERSION=2026.05.12
```

The resulting `.pkg` is at `build/skills-check-2026.05.12.pkg`.

## What the installer does

- Copies `skills-check` to `/usr/local/bin/skills-check`.
- No launch daemons are installed; run `skills-check scheduler install` post-install
  if you want background updates.

## Code-signing (optional)

If you have a Developer ID Installer certificate:

```bash
productsign --sign "Developer ID Installer: Your Name" \
    build/skills-check-2026.05.12.pkg \
    build/skills-check-2026.05.12-signed.pkg
```

## Notarization (optional)

```bash
xcrun notarytool submit build/skills-check-2026.05.12-signed.pkg \
    --apple-id you@example.com \
    --team-id TEAMID \
    --password @keychain:AC_PASSWORD \
    --wait
```
