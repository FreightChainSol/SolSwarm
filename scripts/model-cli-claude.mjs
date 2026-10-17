import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { REVIEW_INSTRUCTION, validateReviewRequest, validateResult } from './terminal-review-contract.mjs';

const REQUIRED = ['--restricted', '--tools', '--strict-mcp-config', '--mcp-config', '--disable-slash-commands', '--no-session-persistence', '--setting-sources', '--settings', '--output-format', '--system-prompt', '--permission-mode'];
const VERSION_PATTERN = /^2\.1\.\d+$/;
const OUTPUT_BYTES = 2 * 1024 * 1024;
const EVENT_TYPES = new Set(['system', 'assistant', 'result', 'rate_limit_event', 'user', 'stream_event', 'control_request', 'control_response', 'tool_progress', 'tool_use_summary', 'auth_status']);
const EVENT_SUBTYPES = new Set(['init', 'thinking_tokens', 'status', 'api_retry', 'hook_started', 'hook_progress', 'hook_response', 'compact_boundary', 'task_started', 'task_progress', 'task_notification', 'turn_duration', 'success']);
const TOKEN_FIELDS = new Set(['type', 'subtype', 'estimated_tokens', 'estimated_tokens_delta', 'session_id', 'uuid']);
export class ConnectorError extends Error {
  constructor(code, event) {
    super(code);
    this.code = code;
    // Fixed labels only: no event payloads, account data, IDs or reasoning.
    if (event) this.event = {
      type: EVENT_TYPES.has(event.type) ? event.type : 'unknown',
      subtype: event.subtype == null ? null : EVENT_SUBTYPES.has(event.subtype) ? event.subtype : 'unknown',
      index: Number.isInteger(event.index) && event.index > 0 && event.index <= OUTPUT_BYTES ? event.index : null,
    };
  }
}
export function brokerEnvironment(source = process.env) {
  const env = {};
  // Claude's macOS subscription discovery needs the ordinary host user identity.
  for (const key of ['HOME', 'USER', 'PATH', 'LANG', 'LC_ALL', 'TMPDIR', 'CLAUDE_CONFIG_DIR']) {
    if (typeof source[key] === 'string') env[key] = source[key];
  }
  // API keys, OAuth token env overrides, endpoint routing, proxies, NODE_OPTIONS,
  // shell startup hooks and agent/project variables are intentionally absent.
  return env;
}
function resolveClaude(env) {
  for (const dir of (env.PATH || '').split(path.delimiter)) {
    if (!dir || !path.isAbsolute(dir)) continue;
    const file = path.join(dir, 'claude');
    try {
      fs.accessSync(file, fs.constants.X_OK);
      const actual = fs.realpathSync(file);
      if (fs.statSync(actual).isFile()) return actual;
    } catch { /* try the next trusted operator PATH entry */ }
  }
  throw new ConnectorError('cli_unavailable');
}
function killGroup(child, signal) {
  if (!child.pid) return;
  try { process.kill(-child.pid, signal); } catch { try { child.kill(signal); } catch { /* already reaped */ } }
}
// The runner is private: callers cannot supply commands, argv, URLs or hooks.
function run(executable, args, input, { cwd, env, signal, timeoutMs = 10_000 } = {}) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new ConnectorError('connector_cancelled')); return; }
    const child = spawn(executable, args, { cwd, env, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
    const chunks = [];
    let bytes = 0;
    let failure;
    let escalation;
    const stop = (code) => {
      if (failure) return;
      failure = code;
      killGroup(child, 'SIGTERM');
      escalation = setTimeout(() => killGroup(child, 'SIGKILL'), 300);
    };
    const timer = timeoutMs == null ? null : setTimeout(() => stop('connector_deadline'), timeoutMs);
    const abort = () => stop('connector_cancelled');
    signal?.addEventListener('abort', abort, { once: true });
    child.stdin.on('error', () => {});
    child.stdout.on('data', (data) => {
      bytes += data.length;
      if (bytes > OUTPUT_BYTES) stop('cli_output_limit');
      else chunks.push(data);
    });
    child.stderr.on('data', (data) => {
      // Never retain or print account, provider error, thinking or credential data.
      bytes += data.length;
      if (bytes > OUTPUT_BYTES) stop('cli_output_limit');
    });
    child.on('error', () => { failure = 'cli_unavailable'; });
    child.on('close', (code) => {
      clearTimeout(timer);
      clearTimeout(escalation);
      signal?.removeEventListener('abort', abort);
      // Reap any remaining owned subprocesses before releasing the neutral cwd.
      killGroup(child, 'SIGKILL');
      if (failure) { reject(new ConnectorError(failure)); return; }
      let stdout;
      try { stdout = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)); } catch { reject(new ConnectorError('cli_output_encoding')); return; }
      resolve({ code, stdout });
    });
    child.stdin.end(input || '');
    if (signal?.aborted) abort();
  });
}
export function parseClaudeReview(stdout, request) {
  let init;
  let result;
  let index = 0;
  for (const line of stdout.split('\n').filter((s) => s.trim())) {
    index++;
    let event;
    try { event = JSON.parse(line); } catch { throw new ConnectorError('cli_output_not_jsonl'); }
    if (!event || typeof event !== 'object') throw new ConnectorError('cli_event_rejected');
    const diagnostic = { type: event.type, subtype: event.subtype, index };
    if (result && event.type !== 'rate_limit_event') throw new ConnectorError('cli_event_after_result', diagnostic);
    if (event.type === 'system' && event.subtype === 'init') {
      if (init || !Array.isArray(event.tools) || event.tools.length || !Array.isArray(event.mcp_servers) || event.mcp_servers.length) throw new ConnectorError('cli_tools_not_empty');
      init = event;
    } else if (event.type === 'system' && event.subtype === 'thinking_tokens') {
      const counter = (value) => Number.isFinite(value) && value >= 0 && value <= 1_000_000_000;
      const id = (value) => typeof value === 'string' && /^[A-Za-z0-9-]{1,128}$/.test(value);
      if (!init || Object.keys(event).length !== TOKEN_FIELDS.size || Object.keys(event).some((key) => !TOKEN_FIELDS.has(key))
        || !counter(event.estimated_tokens) || !counter(event.estimated_tokens_delta) || !id(event.session_id) || !id(event.uuid)
        || (init.session_id !== undefined && init.session_id !== event.session_id)) throw new ConnectorError('cli_telemetry_rejected', diagnostic);
      // Numeric progress only. It is neither reasoning text nor review evidence.
    } else if (event.type === 'assistant') {
      if (!init || !Array.isArray(event.message?.content) || event.message.content.some((c) => !c || !['text', 'thinking', 'redacted_thinking'].includes(c.type))) throw new ConnectorError('cli_tool_or_content_rejected');
    } else if (event.type === 'result') {
      if (!init || result || event.is_error !== false || event.subtype !== 'success' || typeof event.result !== 'string' || event.structured_output != null) throw new ConnectorError('cli_result_rejected');
      result = event;
    } else if (event.type === 'rate_limit_event') {
      // Usage metadata only; never retained or used as proof.
    } else {
      throw new ConnectorError('cli_execution_event_rejected', diagnostic);
    }
  }
  if (!init || !result) throw new ConnectorError('cli_result_missing');
  let review;
  try { review = JSON.parse(result.result); } catch { throw new ConnectorError('cli_review_not_json'); }
  try { validateResult(review, request); } catch { throw new ConnectorError('cli_review_schema'); }
  return { review, cliReportedModel: typeof init.model === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(init.model) ? init.model : 'unknown' };
}

// executable/env injection is for deterministic unit tests only, never a CLI/RPC option.
export function createClaudeAdapter({ executable, environment = process.env, inferenceTimeoutMs = null } = {}) {
  if (inferenceTimeoutMs != null && (!Number.isSafeInteger(inferenceTimeoutMs) || inferenceTimeoutMs < 10 || inferenceTimeoutMs > 2_147_483_647)) throw new ConnectorError('connector_deadline_rejected');
  const env = brokerEnvironment(environment);
  const cli = executable || resolveClaude(env);
  return {
    async withSession(callback, { signal } = {}) {
      const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'fc-model-'));
      fs.chmodSync(cwd, 0o700);
      try {
        const version = await run(cli, ['--version'], '', { cwd, env, signal, timeoutMs: 5000 });
        const match = version.stdout.match(/^(\d+\.\d+\.\d+) \(Claude Code\)\s*$/);
        if (version.code !== 0 || !match || !VERSION_PATTERN.test(match[1])) throw new ConnectorError('cli_version_unverified');
        const help = await run(cli, ['--help'], '', { cwd, env, signal, timeoutMs: 5000 });
        if (help.code !== 0 || REQUIRED.some((flag) => !help.stdout.includes(flag))) throw new ConnectorError('cli_capability_missing');
        const auth = await run(cli, ['auth', 'status'], '', { cwd, env, signal, timeoutMs: 10_000 });
        let status;
        try { status = JSON.parse(auth.stdout); } catch { throw new ConnectorError('cli_auth_unknown'); }
        if (auth.code !== 0 || status?.loggedIn !== true || status.authMethod !== 'claude.ai') throw new ConnectorError('subscription_login_required');
        return await callback({
          provider: 'claude', version: match[1], authMethod: 'claude.ai',
          review: async (request, model) => {
            validateReviewRequest(request);
            if (typeof model !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(model)) throw new ConnectorError('requested_model_rejected');
            // Validate ordinary JSON text locally. Do not introduce a formatter
            // tool to obtain structured output: the inventory must remain empty.
            const args = ['--print', '--restricted', '--tools', '', '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}', '--disable-slash-commands', '--no-session-persistence', '--setting-sources', '', '--settings', '{"disableAllHooks":true,"autoMemoryEnabled":false,"forceLoginMethod":"claudeai"}', '--permission-mode', 'dontAsk', '--system-prompt', REVIEW_INSTRUCTION, '--output-format', 'stream-json', '--verbose', '--model', model];
            // This connector supplies approved text only, not socket/claim/job
            // identity. Installed-CLI and trusted user/admin context are separate
            // inputs; these flags do not attest universal context suppression.
            const prompt = JSON.stringify({ instruction: REVIEW_INSTRUCTION, files: request.files });
            const response = await run(cli, args, prompt, { cwd, env, signal, timeoutMs: inferenceTimeoutMs });
            if (response.code !== 0) throw new ConnectorError('cli_inference_failed');
            return parseClaudeReview(response.stdout, request);
          },
        });
      } finally { fs.rmSync(cwd, { recursive: true, force: true }); }
    },
  };
}
