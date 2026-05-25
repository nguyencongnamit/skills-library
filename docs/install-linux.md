# Install secure-code on Linux

The `skills-check` CLI is a statically linked Go binary with no runtime
dependencies, so any glibc or musl Linux distribution can run it.

> The CLI binary name (`skills-check`) and the hosted APT/YUM repository
> paths (under `kennguy3n.github.io/skills-library/`) are stable technical
> identifiers and are not renamed when the project's brand changed to
> **secure-code**.

## APT (Debian / Ubuntu)

```bash
curl -fsSL https://kennguy3n.github.io/skills-library/apt/pubkey.gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/skills-library.gpg
echo "deb [signed-by=/etc/apt/keyrings/skills-library.gpg] \
  https://kennguy3n.github.io/skills-library/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/skills-library.list
sudo apt update && sudo apt install skills-check
```

## YUM / DNF (RHEL / Fedora)

```bash
sudo tee /etc/yum.repos.d/skills-library.repo <<'EOF'
[skills-library]
name=Skills Library
baseurl=https://kennguy3n.github.io/skills-library/yum
enabled=1
gpgcheck=1
gpgkey=https://kennguy3n.github.io/skills-library/yum/RPM-GPG-KEY-skills-library
EOF
sudo dnf install skills-check
```

## Standalone .deb / .rpm

Download from the [latest GitHub Release](https://github.com/kennguy3n/skills-library/releases/latest):

```bash
sudo dpkg -i skills-check_*.deb     # Debian / Ubuntu
sudo rpm -i  skills-check-*.rpm      # RHEL / Fedora
```

Reproducible-build / packaging details live in
[`packaging/linux/README.md`](../packaging/linux/README.md).

## Go install

```bash
go install github.com/kennguy3n/skills-library/cmd/skills-check@latest
```

## Verify

```bash
skills-check version
```

## Schedule background updates

```bash
skills-check scheduler install      # systemd --user, 6h interval
skills-check scheduler status
```

`skills-check init` will also offer to install the scheduled update on
first run. Pass `--no-prompt` for CI usage.
