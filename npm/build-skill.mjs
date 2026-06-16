#!/usr/bin/env node
// Assemble the publishable @namncqualgo/secure-code-skill package: the thin
// CLI plus, under assets/<tool>/, the exact tree each IDE expects dropped into
// a project. `init --tool <tool>` copies assets/<tool>/ into the target dir.
// No binaries, no platform variants. Nothing is published here.
//
// Usage:
//   node npm/build-skill.mjs --root <repo-root> --version <x.y.z> --out <dir>

import { promises as fs } from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const HERE = path.dirname(url.fileURLToPath(import.meta.url));
const REPO_DEFAULT = path.resolve(HERE, '..');
const PKG = 'secure-code-skill';

// Per-tool source (under the repo's dist/) and the path it lands at inside
// assets/<tool>/ — which is also the project-relative install path.
export const TOOLS = {
  claude: { src: ['dist', 'claude-skills', '.claude'], dest: '.claude', scoped: true },
  cursor: { src: ['dist', 'cursor-rules', '.cursor'], dest: '.cursor', scoped: true },
  copilot: { src: ['dist', 'copilot-rules', '.github'], dest: '.github', scoped: true },
  devin: { src: ['dist', 'devin-rules', '.devin'], dest: '.devin', scoped: true },
  cline: { src: ['dist', '.clinerules'], dest: '.clinerules', scoped: false },
  codex: { src: ['dist', 'AGENTS.md'], dest: 'AGENTS.md', scoped: false },
  universal: { src: ['dist', 'SECURITY-SKILLS.md'], dest: 'SECURITY-SKILLS.md', scoped: false },
};

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

  // assets/<tool>/<dest> — the exact tree `init --tool <tool>` drops in.
  for (const [tool, spec] of Object.entries(TOOLS)) {
    const srcPath = path.join(root, ...spec.src);
    if (!(await exists(srcPath))) {
      throw new Error(`missing dist source for ${tool}: ${srcPath} (run skills-check regenerate)`);
    }
    const destPath = path.join(pkgOut, 'assets', tool, spec.dest);
    await fs.mkdir(path.dirname(destPath), { recursive: true });
    await fs.cp(srcPath, destPath, { recursive: true });
  }

  // package.json with stamped version
  const pkg = JSON.parse(await fs.readFile(path.join(skel, 'package.json'), 'utf8'));
  pkg.version = version;
  await fs.writeFile(path.join(pkgOut, 'package.json'), JSON.stringify(pkg, null, 2) + '\n');

  console.log(`assembled @namncqualgo/${PKG} @ ${version} (tools: ${Object.keys(TOOLS).join(', ')})`);
  console.log(`output: ${pkgOut}`);
}

main().catch((e) => {
  console.error(`build-skill.mjs: ${e.message}`);
  process.exit(1);
});
