# secure-code — Linux packaging

Builds Debian (`.deb`) and RPM (`.rpm`) packages of the `skills-check` CLI
(part of **secure-code**) using [nfpm](https://nfpm.goreleaser.com/).

## Prerequisites

- `nfpm` v2 or newer
- A pre-built `skills-check` Linux binary

## Build

```bash
make BINARY=../../dist-build/skills-check-linux-amd64 VERSION=2026.05.13
```

Outputs land in `build/`:

- `skills-check_<VERSION>_amd64.deb`
- `skills-check-<VERSION>.x86_64.rpm`

The packages install the binary to `/usr/local/bin/skills-check`. No system
dependencies are required because the binary is statically linked
(`CGO_ENABLED=0`).

## Configuration validation

```bash
make check
```

The Go test `cmd/skills-check/internal/compiler/packaging_test.go` asserts the
configuration is parseable and lists the binary at the expected path.
