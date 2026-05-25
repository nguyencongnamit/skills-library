# secure-code — APT and YUM release repository

This directory holds the tooling that turns the per-release `.deb` and `.rpm`
artifacts (built by `packaging/linux/`) into APT and YUM repositories hosted on
GitHub Pages.

> Repository paths (`kennguy3n.github.io/skills-library/{apt,yum}`),
> repository identifiers (`skills-library`), and the YUM `name=Skills
> Library` display label are stable hosting identifiers and are not renamed
> when the project's brand changed to **secure-code**.

Users install with:

```bash
# APT (Ubuntu / Debian)
curl -fsSL https://kennguy3n.github.io/skills-library/apt/pubkey.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/skills-library.gpg
echo "deb [signed-by=/etc/apt/keyrings/skills-library.gpg] https://kennguy3n.github.io/skills-library/apt stable main" | sudo tee /etc/apt/sources.list.d/skills-library.list
sudo apt update && sudo apt install skills-check

# YUM / DNF (RHEL / Fedora)
sudo tee /etc/yum.repos.d/skills-library.repo <<EOF
[skills-library]
name=Skills Library
baseurl=https://kennguy3n.github.io/skills-library/yum
enabled=1
gpgcheck=1
gpgkey=https://kennguy3n.github.io/skills-library/yum/RPM-GPG-KEY-skills-library
EOF
sudo dnf install skills-check
```

## How the repo is built

`reprepro` is used for the APT side and `createrepo_c` for the YUM side. The
`Makefile` in this directory expects the per-release `.deb` and `.rpm`
artifacts on disk and emits a `site/` tree ready to be pushed to GitHub
Pages.

```bash
make ARTIFACTS=../../release VERSION=2026.05.13 site
```

The signing key is the same GPG key referenced from [SIGNING.md](../../SIGNING.md);
the private half stays offline on the release manager's YubiKey. CI imports
the public half (`pubkey.gpg`) and signs the release files in the same job
that publishes the GitHub Pages branch.

## Layout produced by `make site`

```
site/
├── apt/
│   ├── pubkey.gpg
│   ├── dists/stable/{InRelease,Release,Release.gpg,main/binary-amd64/Packages*}
│   └── pool/main/s/skills-check/skills-check_<VERSION>_amd64.deb
└── yum/
    ├── RPM-GPG-KEY-skills-library
    ├── repodata/...
    └── packages/skills-check-<VERSION>.x86_64.rpm
```

## Reproducibility

The APT and YUM metadata is regenerated on every release; the `.deb` /
`.rpm` artifacts themselves are not rebuilt — they are copied verbatim from
the GitHub Release attachment. This keeps the package SHA-256 stable across
repo refreshes and lets `apt update` honour the same checksum a user would
get from `wget`'ing the release asset directly.
