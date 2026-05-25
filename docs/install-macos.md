# Install secure-code on macOS

The `skills-check` CLI runs natively on Intel and Apple Silicon. Pick whichever
install path matches how you manage other CLI tools.

## Homebrew (recommended)

```bash
brew tap kennguy3n/tap
brew install skills-check
```

The tap formula lives at [`packaging/homebrew/skills-check.rb`](../packaging/homebrew/skills-check.rb).

## Go install

```bash
go install github.com/kennguy3n/skills-library/cmd/skills-check@latest
```

Make sure `$(go env GOPATH)/bin` is on your `PATH`.

## .pkg installer

Download the signed `.pkg` from the
[latest GitHub Release](https://github.com/kennguy3n/skills-library/releases/latest)
and double-click to install. The package places the binary at
`/usr/local/bin/skills-check`.

Reproducible-build details and the signing model live in
[`SIGNING.md`](../SIGNING.md) and
[`packaging/codesign/README.md`](../packaging/codesign/README.md).

## Verify

```bash
skills-check version
```

You should see the CLI version, the embedded public key ID, and the Go
version it was built with.

## Schedule background updates

```bash
skills-check scheduler install            # launchd, 6h interval
skills-check scheduler status             # check what's installed
```

The `skills-check init` command will also offer to set up the scheduled
update interactively on first run. Pass `--no-prompt` to skip the prompt
in CI scripts.
