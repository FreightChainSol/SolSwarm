import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { brokerEnvironment, createClaudeAdapter, ConnectorError } from './model-cli-claude.mjs';

export const MODEL_CLIS = Object.freeze(['claude', 'codex', 'grok', 'agy', 'gemini', 'ollama']);
function executableFor(provider, env) {
  for (const dir of (env.PATH || '').split(path.delimiter)) {
    if (!dir || !path.isAbsolute(dir)) continue;
    try {
      const file = fs.realpathSync(path.join(dir, provider));
      fs.accessSync(file, fs.constants.X_OK);
      if (fs.statSync(file).isFile()) return file;
    } catch { /* continue through operator PATH */ }
  }
  return null;
}
// Fixed --version only. Unsupported providers never receive source or auth requests.
async function versionOf(file, env, signal) {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'fc-cli-status-'));
  fs.chmodSync(cwd, 0o700);
  try {
    return await new Promise((resolve) => {
      if (signal?.aborted) { resolve(null); return; }
      const child = spawn(file, ['--version'], { cwd, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
      let bytes = 0;
      let text = '';
      let stopped = false;
      const kill = () => {
        stopped = true;
        if (child.pid) { try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); } }
      };
      const timer = setTimeout(kill, 5000);
      signal?.addEventListener('abort', kill, { once: true });
      child.stdout.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > 8192) kill();
        else text += chunk.toString('utf8');
      });
      child.stderr.on('data', (chunk) => { bytes += chunk.length; if (bytes > 8192) kill(); });
      child.on('error', () => { stopped = true; });
      child.on('close', (code) => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', kill);
        const match = text.match(/\b(\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?)\b/);
        const version = !stopped && code === 0 && match && match[1].length <= 128 ? match[1] : null;
        kill();
        resolve(version);
      });
      if (signal?.aborted) kill();
    });
  } finally { fs.rmSync(cwd, { recursive: true, force: true }); }
}
export async function checkModelCli(provider, { environment = process.env, signal, adapter } = {}) {
  if (!MODEL_CLIS.includes(provider)) throw new ConnectorError('provider_unknown');
  if (signal?.aborted) throw new ConnectorError('connector_cancelled');
  const env = brokerEnvironment(environment);
  const executable = executableFor(provider, env);
  const base = { provider, supported: provider === 'claude', scope: 'explicit_local_text_review_only' };
  if (!executable) return { ...base, state: 'unavailable', reason: 'cli_unavailable', available: false, authStatus: 'not_checked' };
  if (provider !== 'claude') {
    const cliVersion = await versionOf(executable, env, signal);
    if (signal?.aborted) throw new ConnectorError('connector_cancelled');
    return { ...base, state: 'blocked', reason: 'provider_tool_free_mode_unverified', available: true, cliVersion, authStatus: 'not_checked' };
  }
  try {
    return await (adapter || createClaudeAdapter({ executable, environment })).withSession(async (session) => ({
      ...base, state: 'ready', available: true, cliVersion: session.version, authMethod: session.authMethod,
    }), { signal });
  } catch (err) {
    if (signal?.aborted) throw new ConnectorError('connector_cancelled');
    return { ...base, state: 'blocked', available: true, reason: err instanceof ConnectorError ? err.code : 'connector_failed' };
  }
}
export async function checkAllModelClis(options = {}) {
  const providers = [];
  for (const provider of MODEL_CLIS) providers.push(await checkModelCli(provider, options));
  return { state: 'diagnostics', scope: 'explicit_local_text_review_only', providers, note: 'Inventory completed; this does not mean every provider is supported or inference was tested.' };
}
