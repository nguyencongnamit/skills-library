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

  // 2. init each tool into its own temp project; assert the expected files.
  console.log('[2/3] init per --tool');
  const cases = [
    { tool: 'claude', check: '.claude/skills/secret-detection/SKILL.md', needle: /^name:\s*secret-detection/m },
    { tool: 'cursor', check: '.cursor/rules/container-security.mdc', needle: /^globs:/m },
    { tool: 'windsurf', check: '.windsurf/rules/secret-detection.md', needle: /^trigger:\s*model_decision/m },
    { tool: 'copilot', check: '.github/instructions/cicd-security.instructions.md', needle: /^applyTo:/m },
    { tool: 'cline', check: '.clinerules', needle: /secure-code|secret/i },
  ];
  for (const c of cases) {
    const proj = path.join(work, 'proj-' + c.tool);
    await fs.mkdir(proj, { recursive: true });
    const rr = spawnSync(process.execPath, [cli, 'init', proj, '--tool', c.tool], { encoding: 'utf8' });
    if (rr.status !== 0) die(`init --tool ${c.tool} exited ${rr.status}: ${rr.stderr}`);
    const f = path.join(proj, c.check);
    let body;
    try { body = await fs.readFile(f, 'utf8'); } catch { die(`init --tool ${c.tool}: expected ${c.check}`); }
    if (!c.needle.test(body)) die(`init --tool ${c.tool}: ${c.check} missing expected ${c.needle}`);
  }
  // unknown tool must fail
  const bad = spawnSync(process.execPath, [cli, 'init', work, '--tool', 'nope'], { encoding: 'utf8' });
  if (bad.status === 0) die('init --tool nope should have failed');

  // 3. connect-mcp without claude on PATH -> fallback message
  console.log('[3/3] connect-mcp fallback (no Claude CLI)');
  r = spawnSync(process.execPath, [cli, 'connect-mcp'], { encoding: 'utf8', env: { ...process.env, PATH: '/nonexistent' } });
  const text = (r.stdout || '') + (r.stderr || '');
  if (!text.includes('claude mcp add secure-code -- npx -y @namncqualgo/secure-code-mcp')) {
    die(`connect-mcp fallback did not print the expected command. Got:\n${text}`);
  }

  await fs.rm(work, { recursive: true, force: true });
  console.log(`smoke-test-skill: PASS — init works for ${cases.length} tools (scoped + pointer); connect-mcp resolves the secure-code MCP`);
}

main().catch((e) => die(e.message));
