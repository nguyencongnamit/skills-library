#!/usr/bin/env node
'use strict';

// CLI for @namncqualgo/secure-code-skill — a tiny, binary-free installer:
//
//   secure-code-skill init [dir]              install the secure-code skills into
//                                             <dir>/.claude/skills (default: cwd)
//   secure-code-skill connect-mcp [--user]    register the secure-code MCP server
//                                             with Claude Code (claude mcp add)
//   secure-code-skill connect-mcp <name> -- <cmd> [args...]
//                                             register ANY MCP server by name
//
// The skills are self-contained knowledge (no MCP required); connecting an MCP
// adds active scanning. This package ships only the skill files — the MCP
// engine lives in @namncqualgo/secure-code-mcp and is fetched by npx on demand.

const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const MCP_PKG = '@namncqualgo/secure-code-mcp';
const DEFAULT_MCP_NAME = 'secure-code';

const argv = process.argv.slice(2);
const sub = argv[0];

if (sub === 'init') {
  initSkills(argv.slice(1));
} else if (sub === 'connect-mcp') {
  connectMcp(argv.slice(1));
} else {
  printHelp();
  process.exit(sub === 'help' || sub === '--help' || sub === '-h' ? 0 : 1);
}

// ----------------------------------------------------------------------------

// initSkills copies the bundled native skills into <dir>/.claude/skills/<id>/SKILL.md.
function initSkills(args) {
  const targetDir = args[0] ? path.resolve(args[0]) : process.cwd();
  const srcDir = path.join(__dirname, '..', 'skills-native');
  if (!fs.existsSync(srcDir)) {
    process.stderr.write(`secure-code-skill: skills bundle missing from the package (${srcDir}).\n`);
    process.exit(1);
  }
  const destRoot = path.join(targetDir, '.claude', 'skills');
  fs.mkdirSync(destRoot, { recursive: true });

  let n = 0;
  for (const id of fs.readdirSync(srcDir)) {
    const srcSkill = path.join(srcDir, id, 'SKILL.md');
    if (!fs.existsSync(srcSkill)) continue;
    const destDir = path.join(destRoot, id);
    fs.mkdirSync(destDir, { recursive: true });
    fs.copyFileSync(srcSkill, path.join(destDir, 'SKILL.md'));
    n++;
  }

  process.stdout.write(
    `Installed ${n} secure-code skills into ${destRoot}\n` +
      `Claude Code will use them automatically in this project — no MCP required.\n\n` +
      `For active scanning (secrets, deps, Dockerfile, …), connect the MCP engine:\n` +
      `  npx ${pkgName()} connect-mcp\n`
  );
}

// connectMcp registers an MCP server with Claude Code via `claude mcp add`.
// With no args it wires up the secure-code MCP; otherwise it registers any
// server given as `<name> -- <cmd> [args...]`.
function connectMcp(args) {
  const userScope = args.includes('--user');
  const rest = args.filter((a) => a !== '--user');

  let name;
  let cmd;
  if (rest.length === 0) {
    name = DEFAULT_MCP_NAME;
    cmd = ['npx', '-y', MCP_PKG];
  } else if (rest[1] === '--' && rest.length > 2) {
    name = rest[0];
    cmd = rest.slice(2);
  } else {
    process.stderr.write(
      `secure-code-skill: invalid connect-mcp usage.\n` +
        `  npx ${pkgName()} connect-mcp                       # the secure-code MCP\n` +
        `  npx ${pkgName()} connect-mcp <name> -- <cmd> ...   # any MCP server\n`
    );
    process.exit(1);
  }

  const addArgs = ['mcp', 'add', ...(userScope ? ['-s', 'user'] : []), name, '--', ...cmd];
  const res = spawnSync('claude', addArgs, { stdio: 'inherit' });
  if (res.error) {
    process.stderr.write(
      `secure-code-skill: the Claude CLI was not found on PATH.\n\n` +
        `Run this yourself once Claude Code is installed:\n` +
        `  claude ${addArgs.join(' ')}\n\n` +
        `Or add to your MCP client config manually:\n` +
        `  "mcpServers": { "${name}": { "command": "${cmd[0]}", "args": ${JSON.stringify(cmd.slice(1))} } }\n`
    );
    process.exit(1);
  }
  process.exit(res.status === null ? 1 : res.status);
}

function pkgName() {
  return '@namncqualgo/secure-code-skill';
}

function printHelp() {
  process.stdout.write(
    `${pkgName()} — secure-code skills for Claude Code\n\n` +
      `Usage:\n` +
      `  npx ${pkgName()} init [dir]                        install skills into <dir>/.claude/skills (default: cwd)\n` +
      `  npx ${pkgName()} connect-mcp [--user]              connect the secure-code MCP server\n` +
      `  npx ${pkgName()} connect-mcp <name> -- <cmd> ...   connect any MCP server\n`
  );
}
