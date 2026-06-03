#!/usr/bin/env node
'use strict';

// CLI for @namncqualgo/secure-code-skill — a tiny, binary-free installer:
//
//   secure-code-skill init [dir] [--tool <name>]
//        install the secure-code skills into <dir> for the chosen IDE
//        (default --tool claude). See TOOLS below for the full list.
//   secure-code-skill connect-mcp [--user]
//        register the secure-code MCP server with Claude Code (claude mcp add)
//   secure-code-skill connect-mcp <name> -- <cmd> [args...]
//        register ANY MCP server by name
//
// The skills are self-contained knowledge (no MCP required); connecting an MCP
// adds active scanning. This package ships only skill files — the MCP engine
// lives in @namncqualgo/secure-code-mcp and is fetched by npx on demand.

const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const MCP_PKG = '@namncqualgo/secure-code-mcp';
const PKG = '@namncqualgo/secure-code-skill';
const DEFAULT_MCP_NAME = 'secure-code';

// Each tool's installed path (relative to the project) + whether it gets the
// context-scoped (progressive-disclosure) format or a single always-on file.
// The asset tree under assets/<tool>/ already mirrors these paths.
const TOOLS = {
  claude: { dest: '.claude/skills/', scoped: true, label: 'Claude Code (native skills)' },
  cursor: { dest: '.cursor/rules/', scoped: true, label: 'Cursor (scoped rules)' },
  copilot: { dest: '.github/instructions/', scoped: true, label: 'GitHub Copilot / VS Code (scoped instructions)' },
  windsurf: { dest: '.windsurf/rules/', scoped: true, label: 'Windsurf (scoped rules)' },
  cline: { dest: '.clinerules', scoped: false, label: 'Cline (single rules file)' },
  codex: { dest: 'AGENTS.md', scoped: false, label: 'Codex / AGENTS.md (single file)' },
  universal: { dest: 'SECURITY-SKILLS.md', scoped: false, label: 'universal (single file, any tool)' },
};

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

// initSkills copies assets/<tool>/ (which mirrors the project layout) into the
// target dir.
function initSkills(args) {
  let tool = 'claude';
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--tool') tool = args[++i];
    else if (args[i].startsWith('--tool=')) tool = args[i].slice('--tool='.length);
    else positional.push(args[i]);
  }

  const meta = TOOLS[tool];
  if (!meta) {
    process.stderr.write(
      `secure-code-skill: unknown --tool "${tool}".\n` +
        `Valid tools: ${Object.keys(TOOLS).join(', ')}\n`
    );
    process.exit(1);
  }

  const targetDir = positional[0] ? path.resolve(positional[0]) : process.cwd();
  const assetDir = path.join(__dirname, '..', 'assets', tool);
  if (!fs.existsSync(assetDir)) {
    process.stderr.write(`secure-code-skill: assets for "${tool}" missing from the package (${assetDir}).\n`);
    process.exit(1);
  }

  fs.mkdirSync(targetDir, { recursive: true });
  fs.cpSync(assetDir, targetDir, { recursive: true, force: true });

  const where = path.join(targetDir, meta.dest);
  process.stdout.write(
    `Installed secure-code skills for ${meta.label}\n` +
      `  -> ${where}\n` +
      (meta.scoped
        ? `  context-scoped: only the rule relevant to the files in play loads (token-efficient).\n`
        : `  single always-on rules file (this tool has no per-rule scoping).\n`) +
      `\nFor active scanning (secrets, deps, Dockerfile, …), connect the MCP engine:\n` +
      `  npx ${PKG} connect-mcp\n`
  );
}

// connectMcp registers an MCP server with Claude Code via `claude mcp add`.
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
        `  npx ${PKG} connect-mcp                       # the secure-code MCP\n` +
        `  npx ${PKG} connect-mcp <name> -- <cmd> ...   # any MCP server\n`
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

function printHelp() {
  const tools = Object.entries(TOOLS)
    .map(([k, v]) => `      ${k.padEnd(10)} ${v.dest}`)
    .join('\n');
  process.stdout.write(
    `${PKG} — secure-code skills for AI coding tools\n\n` +
      `Usage:\n` +
      `  npx ${PKG} init [dir] [--tool <name>]   install skills (default --tool claude)\n` +
      `  npx ${PKG} connect-mcp [--user]         connect the secure-code MCP server\n` +
      `  npx ${PKG} connect-mcp <name> -- <cmd>  connect any MCP server\n\n` +
      `Tools (--tool):\n${tools}\n`
  );
}
