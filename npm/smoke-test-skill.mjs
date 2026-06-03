#!/usr/bin/env node
// Smoke test for @namncqualgo/secure-code-skill:
//   1. assemble the package (build-skill.mjs)
//   2. `init` into a temp dir -> assert .claude/skills/<id>/SKILL.md appear
//      and carry Claude Code frontmatter (name:)
//   3. `connect-mcp` with no Claude CLI -> asserts it prints the exact
//      `claude mcp add secure-code -- npx -y @namncqualgo/secure-code-mcp` fallback
//
// Usage: node npm/smoke-test-skill.mjs

import { promises as fs } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import url from 'node:url';

const HERE = path.dirname(url.fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');

function die(msg) {
  console.error(`smoke-test-skill: FAIL — ${msg}`);
  process.exit(1);
}

async function main() {
  const work = await fs.mkdtemp(path.join(os.tmpdir(), 'scskill-'));
  const out = path.join(work, 'out');

  // 1. assemble
  console.log('[1/3] assembling secure-code-skill');
  let r = spawnSync('node', [path.join(HERE, 'build-skill.mjs'), '--root', REPO, '--version', '0.0.0-smoke', '--out', out], { stdio: 'inherit' });
  if (r.status !== 0) die('build-skill.mjs failed');
  const cli = path.join(out, 'secure-code-skill', 'bin', 'cli.js');

  // 2. init into a temp project
  console.log('[2/3] init into a temp project');
  const proj = path.join(work, 'proj');
  await fs.mkdir(proj, { recursive: true });
  r = spawnSync(process.execPath, [cli, 'init', proj], { stdio: 'inherit' });
  if (r.status !== 0) die('init exited non-zero');
  const skillsDir = path.join(proj, '.claude', 'skills');
  const ids = (await fs.readdir(skillsDir)).filter((d) => !d.startsWith('.'));
  if (ids.length < 20) die(`expected >=20 skills installed, got ${ids.length}`);
  const sample = await fs.readFile(path.join(skillsDir, 'secret-detection', 'SKILL.md'), 'utf8');
  if (!/^name:\s*secret-detection/m.test(sample)) die('installed SKILL.md missing Claude Code `name:` frontmatter');

  // 3. connect-mcp without claude on PATH -> fallback message
  console.log('[3/3] connect-mcp fallback (no Claude CLI)');
  r = spawnSync(process.execPath, [cli, 'connect-mcp'], { encoding: 'utf8', env: { ...process.env, PATH: '/nonexistent' } });
  const text = (r.stdout || '') + (r.stderr || '');
  if (!text.includes('claude mcp add secure-code -- npx -y @namncqualgo/secure-code-mcp')) {
    die(`connect-mcp fallback did not print the expected command. Got:\n${text}`);
  }

  await fs.rm(work, { recursive: true, force: true });
  console.log(`smoke-test-skill: PASS — installed ${ids.length} skills; connect-mcp resolves the secure-code MCP`);
}

main().catch((e) => die(e.message));
