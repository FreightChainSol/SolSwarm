import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const BRIDGE_SCRIPT = path.join(HERE, 'docker-mcp-bridge.mjs');
const SKILL_FILE = path.resolve(HERE, '..', 'skills', 'security-audit', 'SKILL.md');
export function resolveExecutable(name, env = process.env) {
  for (const dir of (env.PATH || '').split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, name);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      const real = fs.realpathSync(candidate);
      if (fs.statSync(real).isFile()) return real;
    } catch { /* continue */ }
  }
  return null;
}

export function stageAuditSkill(workDir) {
  if (!fs.existsSync(SKILL_FILE)) return;
  const skillText = fs.readFileSync(SKILL_FILE, 'utf8');
  for (const rel of ['.claude/skills/security-audit', '.agents/skills/security-audit']) {
    const dir = path.join(workDir, rel);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(dir, 'SKILL.md'), skillText, { mode: 0o600 });
  }
}

export function buildCliInvocation({ agent, model, prompt, workDir, bridgeArgs, conversationId, nodeBin = process.execPath, env = process.env }) {
  if (conversationId && (agent !== 'agy' || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(conversationId))) throw new Error('Invalid AGY conversation identity');
  const exe = resolveExecutable(agent, env);
  if (!exe) throw new Error(`CLI executable not found on PATH: ${agent}`);
  const fullBridgeArgs = [BRIDGE_SCRIPT, ...bridgeArgs];
  stageAuditSkill(workDir);

  if (agent === 'agy') {
    spawnSync('git', ['init', '-q'], { cwd: workDir, stdio: 'ignore' });
    const pluginDir = path.join(workDir, '.agents', 'plugins', 'audit-docker');
    fs.mkdirSync(pluginDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(pluginDir, 'plugin.json'), JSON.stringify({
      name: 'audit-docker',
      description: 'One-shot Docker container MCP bridge for security auditing',
    }, null, 2));
    fs.writeFileSync(path.join(pluginDir, 'mcp_config.json'), JSON.stringify({
      mcpServers: { audit_docker: { command: nodeBin, args: fullBridgeArgs } },
    }, null, 2));
    const shellQuote = value => `'${String(value).replaceAll("'", "'\\''")}'`;
    const skillFiles = ['.agents', '.claude'].flatMap(dir => {
      const file = path.join(workDir, dir, 'skills', 'security-audit', 'SKILL.md');
      return [file, fs.realpathSync(file)];
    });
    const denyCmd = [nodeBin, path.join(HERE, 'audit-tool-policy.mjs'), ...new Set(skillFiles)].map(shellQuote).join(' ');
    fs.writeFileSync(path.join(pluginDir, 'hooks.json'), JSON.stringify({
      'audit-docker': {
        PreToolUse: [{
          matcher: '.*',
          hooks: [{ type: 'command', command: denyCmd }],
        }],
      },
    }, null, 2));
    return {
      executable: exe,
      args: ['--output-format', 'stream-json', '--dangerously-skip-permissions', '--disable-slash-commands', '--model', model, ...(conversationId ? ['--conversation', conversationId] : []), `--print=${prompt}`],
      stdin: '',
      cwd: workDir,
    };
  }

  throw new Error(`Unsupported agent: ${agent}`);
}

