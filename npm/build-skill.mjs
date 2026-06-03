#!/usr/bin/env node
// Assemble the publishable @namncqualgo/secure-code-skill package: the thin
// CLI (init + connect-mcp) plus the native Claude Code skill bundle. No
// binaries, no platform variants — one package. Nothing is published here.
//
// Usage:
//   node npm/build-skill.mjs --root <repo-root> --version <x.y.z> --out <dir>

import { promises as fs } from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const HERE = path.dirname(url.fileURLToPath(import.meta.url));
const REPO_DEFAULT = path.resolve(HERE, '..');
const PKG = 'secure-code-skill';

function parseArgs(argv) {
  const out = { root: REPO_DEFAULT, version: '0.0.0-dev', out: path.join(HERE, 'dist') };
  for (let i = 0; i < argv.length; i += 2) {
    const k = argv[i].replace(/^--/, '');
    if (!(k in out)) throw new Error(`unknown flag: ${argv[i]}`);
    out[k] = argv[i + 1];
  }
  return out;
}

async function exists(p) {
  try { await fs.access(p); return true; } catch { return false; }
}

async function main() {
  const { root, version, out } = parseArgs(process.argv.slice(2));
  const skel = path.join(HERE, PKG);
  const pkgOut = path.join(out, PKG);

  await fs.rm(pkgOut, { recursive: true, force: true });
  await fs.mkdir(path.join(pkgOut, 'bin'), { recursive: true });

  // CLI + README
  await fs.copyFile(path.join(skel, 'bin', 'cli.js'), path.join(pkgOut, 'bin', 'cli.js'));
  await fs.chmod(path.join(pkgOut, 'bin', 'cli.js'), 0o755);
  await fs.copyFile(path.join(skel, 'README.md'), path.join(pkgOut, 'README.md'));

  // native Claude Code skill bundle (name/description frontmatter)
  const nativeSrc = path.join(root, 'dist', 'claude-skills', '.claude', 'skills');
  if (!(await exists(nativeSrc))) {
    throw new Error(`native skills bundle missing: ${nativeSrc} (run skills-check regenerate)`);
  }
  await fs.cp(nativeSrc, path.join(pkgOut, 'skills-native'), { recursive: true });

  // package.json with stamped version
  const pkg = JSON.parse(await fs.readFile(path.join(skel, 'package.json'), 'utf8'));
  pkg.version = version;
  await fs.writeFile(path.join(pkgOut, 'package.json'), JSON.stringify(pkg, null, 2) + '\n');

  const n = (await fs.readdir(path.join(pkgOut, 'skills-native'))).length;
  console.log(`assembled @namncqualgo/${PKG} @ ${version} (${n} skills)`);
  console.log(`output: ${pkgOut}`);
}

main().catch((e) => {
  console.error(`build-skill.mjs: ${e.message}`);
  process.exit(1);
});
