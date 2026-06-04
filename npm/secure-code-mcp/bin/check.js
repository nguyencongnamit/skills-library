#!/usr/bin/env node
'use strict';

// Launcher for the secure-code CLI (`skills-check`), shipped over npm
// alongside the MCP server in the same package.
//
// The CLI is a Go binary shipped per-platform in the SAME optional
// dependency as the MCP server (gated by the package's `os`/`cpu` fields),
// so npm installs ONLY the binary matching the host — no postinstall
// download step, installs work offline and under `npm ci --ignore-scripts`.
//
// The library data tree (skills/, vulnerabilities/, …) ships ONCE in this
// package and is handed to the binary via the SKILLS_LIBRARY_PATH
// environment variable. skills-check resolves its data root from that env;
// its `--path` flag is per-subcommand (not global) so it cannot be injected
// on the command line here. All argv and stdio are forwarded verbatim, and
// the child's exit status is propagated so `secure-code-check gate …` can be
// used directly as a CI / pre-commit gate.

const path = require('node:path');
const { spawnSync } = require('node:child_process');

const platformKey = `${process.platform}-${process.arch}`;
const pkgName = `@namncqualgo/secure-code-mcp-${platformKey}`;
const binName = process.platform === 'win32' ? 'skills-check.exe' : 'skills-check';

let binDir;
try {
  binDir = path.dirname(require.resolve(`${pkgName}/package.json`));
} catch {
  process.stderr.write(
    `secure-code-check: no prebuilt CLI binary for ${platformKey}.\n` +
      `Expected the optional dependency ${pkgName} to be installed.\n` +
      `Supported platforms: darwin-x64, darwin-arm64, linux-x64, linux-arm64, win32-x64.\n` +
      `If your platform is supported, reinstall without --no-optional / --omit=optional.\n`
  );
  process.exit(1);
}

const binPath = path.join(binDir, 'bin', binName);
const dataDir = path.join(__dirname, '..', 'data');

const res = spawnSync(binPath, process.argv.slice(2), {
  stdio: 'inherit',
  env: { ...process.env, SKILLS_LIBRARY_PATH: dataDir },
});

if (res.error) {
  process.stderr.write(
    `secure-code-check: failed to launch ${binPath}: ${res.error.message}\n`
  );
  process.exit(1);
}
// Propagate the child's exit status (0 pass / 1 gate failure); if it was
// killed by a signal, exit 1.
process.exit(res.status === null ? 1 : res.status);
