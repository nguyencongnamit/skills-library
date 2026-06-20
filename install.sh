#!/bin/sh
# install.sh — one-line installer for the skills-check CLI.
#
#   curl -fsSL https://raw.githubusercontent.com/namncqualgo/skills-library/main/install.sh | sh
#
# Downloads the skills-check binary for your OS/arch from the latest GitHub
# release, verifies its SHA-256 against the release's SHA256SUMS.txt, and
# installs it to ~/.local/bin. Override with these environment variables:
#
#   SKILLS_CHECK_BIN_DIR   install directory          (default: ~/.local/bin)
#   SKILLS_CHECK_VERSION   release tag to install     (default: latest)
#   SKILLS_CHECK_BASE_URL  release download base URL  (default: GitHub releases)
#
# POSIX sh, no bashisms — runs under dash/ash/busybox as well as bash.
set -eu

REPO="namncqualgo/skills-library"
BIN="skills-check"
BIN_DIR="${SKILLS_CHECK_BIN_DIR:-$HOME/.local/bin}"
VERSION="${SKILLS_CHECK_VERSION:-latest}"

err() { printf 'install: error: %s\n' "$1" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"; }

need curl
need uname

# Checksum tool: sha256sum (Linux) or shasum (macOS).
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  err "need sha256sum or shasum to verify the download"
fi

# Detect OS.
os=$(uname -s)
case "$os" in
  Linux) os="linux" ;;
  Darwin) os="darwin" ;;
  *) err "unsupported OS: $os (supported: Linux, macOS)" ;;
esac

# Detect architecture.
arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch="amd64" ;;
  arm64 | aarch64) arch="arm64" ;;
  *) err "unsupported architecture: $arch (supported: x86_64/amd64, arm64/aarch64)" ;;
esac

asset="${BIN}-${os}-${arch}"

# Resolve the release tag (skip the API call when a tag is pinned).
if [ -n "${SKILLS_CHECK_BASE_URL:-}" ]; then
  base="$SKILLS_CHECK_BASE_URL"
elif [ "$VERSION" = "latest" ]; then
  tag=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
    sed -n 's/.*"tag_name"[ ]*:[ ]*"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$tag" ] || err "could not resolve the latest release tag (is a release published yet?)"
  base="https://github.com/${REPO}/releases/download/${tag}"
else
  base="https://github.com/${REPO}/releases/download/${VERSION}"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

printf 'install: downloading %s (%s/%s) from %s\n' "$BIN" "$os" "$arch" "$base"
curl -fsSL "${base}/${asset}" -o "${tmp}/${BIN}" || err "download failed: ${base}/${asset}"

# Verify the checksum against the release SHA256SUMS.txt.
if curl -fsSL "${base}/SHA256SUMS.txt" -o "${tmp}/SHA256SUMS.txt" 2>/dev/null; then
  want=$(awk -v a="$asset" '$2 == a || $2 == "*"a {print $1; exit}' "${tmp}/SHA256SUMS.txt")
  if [ -n "$want" ]; then
    got=$(sha256 "${tmp}/${BIN}")
    [ "$want" = "$got" ] || err "checksum mismatch for ${asset} (want ${want}, got ${got})"
    printf 'install: checksum verified.\n'
  else
    printf 'install: warning: %s not listed in SHA256SUMS.txt; skipping verification.\n' "$asset" >&2
  fi
else
  printf 'install: warning: SHA256SUMS.txt unavailable; skipping checksum verification.\n' >&2
fi

chmod +x "${tmp}/${BIN}"
mkdir -p "$BIN_DIR"
mv "${tmp}/${BIN}" "${BIN_DIR}/${BIN}"
printf 'install: installed %s -> %s\n' "$BIN" "${BIN_DIR}/${BIN}"

# Nudge the user if the install dir is not on PATH.
# SC2016: the literal $PATH below is intentional — we print a command for the
# user to copy verbatim, not the expanded value.
# shellcheck disable=SC2016
case ":${PATH}:" in
  *":${BIN_DIR}:"*) ;;
  *) printf 'install: note: %s is not on your PATH. Add it, e.g.:\n  export PATH="%s:$PATH"\n' "$BIN_DIR" "$BIN_DIR" >&2 ;;
esac

"${BIN_DIR}/${BIN}" version || true
