#!/usr/bin/env node
'use strict';

// Launcher for the secure-code MCP server, distributed over npm.
//
// The server itself is a Go binary (`skills-mcp`). It is shipped per-platform
// in an optional dependency gated by the package's `os`/`cpu` fields, so npm
// installs ONLY the binary that matches the host — there is no postinstall
// download step, which means installs work offline and under
// `npm ci --ignore-scripts`.
//
// The library data tree (skills/, vulnerabilities/, …) ships ONCE in this
// platform-agnostic package and is handed to the binary via `--path`, because
// skills-mcp reads its data from disk (it does not embed it). All argv and
// stdio are forwarded verbatim: MCP speaks JSON-RPC 2.0 over stdio.

const path = require('node:path');
const { spawnSync } = require('node:child_process');

const platformKey = `${process.platform}-${process.arch}`;
const pkgName = `@namncqualgo/secure-code-mcp-${platformKey}`;
const binName = process.platform === 'win32' ? 'skills-mcp.exe' : 'skills-mcp';

let binDir;
try {
  // Resolve via package.json (always resolvable, regardless of any exports
  // map) and derive the binary path from its directory.
  binDir = path.dirname(require.resolve(`${pkgName}/package.json`));
} catch {
  process.stderr.write(
    `secure-code-mcp: no prebuilt server binary for ${platformKey}.\n` +
      `Expected the optional dependency ${pkgName} to be installed.\n` +
      `Supported platforms: darwin-x64, darwin-arm64, linux-x64, linux-arm64, win32-x64.\n` +
      `If your platform is supported, reinstall without --no-optional / --omit=optional.\n`
  );
  process.exit(1);
}

const binPath = path.join(binDir, 'bin', binName);
const dataDir = path.join(__dirname, '..', 'data');

const res = spawnSync(binPath, ['--path', dataDir, ...process.argv.slice(2)], {
  stdio: 'inherit',
});

if (res.error) {
  process.stderr.write(
    `secure-code-mcp: failed to launch ${binPath}: ${res.error.message}\n`
  );
  process.exit(1);
}
// Propagate the child's exit status; if it was killed by a signal, exit 1.
process.exit(res.status === null ? 1 : res.status);
