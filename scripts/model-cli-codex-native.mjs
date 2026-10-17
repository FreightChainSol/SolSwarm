import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { brokerEnvironment, ConnectorError } from './model-cli-claude.mjs';
import { exactKeys, validateReviewRequest, validateResult } from './terminal-review-contract.mjs';
import { nativeIdentity } from '../native/codex-review/build.mjs';
import { matchesAdmission } from '../native/codex-review/admit.mjs';
import { providerDiagnostic } from './provider-error-diagnostic.mjs';

export const CODEX_SOURCE = '092d3acd6bec3e3a14bdc7e7a2810ab628ab759d';
export const DEFAULT_CODEX_MODEL = 'gpt-6.1-sol';
const CACHE = fileURLToPath(new URL('../native/.cache/', import.meta.url));
const BINARY = path.join(CACHE, 'target/debug/freightchain-codex-review');
const REASONS = new Set(['native_input_contract_rejected', 'native_output_contract_rejected', 'native_startup_policy_incompatible', 'native_configuration_rejected', 'native_subscription_auth_required', 'native_runtime_failed', 'native_execution_event_rejected', 'native_deadline_exceeded']);
const modelName = (value) => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value);
const CODEX_PROFILE = Object.freeze({
  provider: 'codex', sourceCommit: CODEX_SOURCE, authMethod: 'chatgpt', version: '0.162.1-native',
  tempPrefix: 'fc-codex-session-', environmentKeys: ['CODEX_HOME'], inventories: ['tools','mcpServers'],
  admissionError: 'native_broker_not_admitted', resolveBinary: admittedBinary, reasons: REASONS,
});

async function admittedBinary() {
  const parent = fs.lstatSync(CACHE);
  if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== process.getuid() || (parent.mode & 0o077)) throw new ConnectorError('native_broker_not_admitted');
  const file = path.join(CACHE, 'runtime-admission.json');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  let receipt;
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== process.getuid() || (stat.mode & 0o077) || stat.size > 16_384) throw new Error('receipt rejected');
    receipt = JSON.parse(fs.readFileSync(fd, 'utf8'));
  } finally { fs.closeSync(fd); }
  if (!matchesAdmission(receipt, nativeIdentity())) throw new ConnectorError('native_broker_not_admitted');
  const stat = fs.lstatSync(BINARY);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== process.getuid() || stat.size > 4 * 1024 ** 3) throw new ConnectorError('native_broker_not_admitted');
  fs.accessSync(BINARY, fs.constants.X_OK);
  const hash = crypto.createHash('sha256');
  for await (const chunk of fs.createReadStream(BINARY)) hash.update(chunk);
  if (hash.digest('hex') !== receipt.binarySha256) throw new ConnectorError('native_broker_not_admitted');
  return { executable: BINARY, identity: { sourceCommit: CODEX_SOURCE, packageDigest: receipt.packageDigest, recipeDigest: receipt.recipeDigest, binarySha256: receipt.binarySha256 } };
}

// Executable injection is test-only; no CLI/RPC option chooses an executable.
export function createCodexNativeAdapter(options = {}) {
  return createNativeReviewAdapter({ ...options, model: options.model === undefined ? DEFAULT_CODEX_MODEL : options.model }, CODEX_PROFILE);
}

// Shared internal transport only. Public CLI profile selection supplies fixed descriptors.
export function createNativeReviewAdapter({ model, environment = process.env, executable, checkOnly = false } = {}, profile) {
  if (!modelName(model)) throw new ConnectorError('requested_model_rejected');
  return {
    async withSession(callback, { signal } = {}) {
      if (signal?.aborted) throw new ConnectorError('connector_cancelled');
      let admitted;
      try { admitted = executable ? { executable } : await profile.resolveBinary(); } catch { throw new ConnectorError(profile.admissionError); }
      const cwd = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), profile.tempPrefix)));
      fs.chmodSync(cwd, 0o700);
      const identity = fs.lstatSync(cwd);
      const env = brokerEnvironment(environment);
      delete env.CLAUDE_CONFIG_DIR;
      for (const key of profile.environmentKeys) if (typeof environment[key] === 'string') env[key] = environment[key];
      env.TMPDIR = cwd;
      const child = spawn(admitted.executable, admitted.args || [checkOnly ? '--check' : '--review', '--model', model], { cwd, env, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
      let readyResolve;
      let readyReject;
      const ready = new Promise((yes, no) => { readyResolve = yes; readyReject = no; });
      ready.catch(() => {});
      let completedResolve;
      let completedReject;
      const completed = new Promise((yes, no) => { completedResolve = yes; completedReject = no; });
      completed.catch(() => {});
      let header;
      let answer;
      let request;
      let used = false;
      let failure;
      let bytes = 0;
      let pending = '';
      let escalation;
      let timer;
      const kill = (sig) => {
        if (child.pid) { try { process.kill(-child.pid, sig); } catch { child.kill(sig); } }
      };
      const stop = (reason, diagnostic) => {
        if (failure) return;
        failure = new ConnectorError(reason);
        if (diagnostic) failure.diagnostic = diagnostic;
        readyReject(failure);
        kill('SIGTERM');
        escalation = setTimeout(() => kill('SIGKILL'), 300);
      };
      const deadline = (ms) => { clearTimeout(timer); timer = setTimeout(() => stop('connector_deadline'), ms); };
      const abort = () => stop('connector_cancelled');
      const decoder = new TextDecoder('utf-8', { fatal: true });
      const frame = (line) => {
        const event = JSON.parse(line);
        if (event.state === 'blocked_or_incomplete') {
          const hasDiagnostic = profile.diagnostics && Object.hasOwn(event, 'diagnostic');
          exactKeys(event, ['version', 'state', 'reason', ...(hasDiagnostic ? ['diagnostic'] : [])]);
          if (event.version !== 1) throw new Error('native protocol version rejected');
          const diagnostic = hasDiagnostic ? providerDiagnostic(event.diagnostic) : undefined;
          if (hasDiagnostic && !diagnostic) throw new Error('native diagnostic rejected');
          stop(profile.reasons.has(event.reason) ? event.reason : 'native_runtime_failed', diagnostic);
        } else if (!header) {
          exactKeys(event, ['version', 'state', 'provider', 'authMethod', 'sourceCommit', ...profile.inventories, ...(profile.sourceRevision ? ['sourceRevision'] : []), 'clientReportedModel']);
          if (event.version !== 1 || event.state !== 'preflight_ready' || event.provider !== profile.provider || event.authMethod !== profile.authMethod || event.sourceCommit !== profile.sourceCommit
            || (profile.sourceRevision && event.sourceRevision !== profile.sourceRevision)
            || profile.inventories.some((key) => !Array.isArray(event[key]) || event[key].length)
            || !modelName(event.clientReportedModel)) throw new Error('preflight rejected');
          header = event;
          clearTimeout(timer);
          readyResolve(event);
        } else {
          exactKeys(event, ['version', 'state', 'provider', 'clientReportedModel', 'result']);
          if (checkOnly || !request || answer || event.version !== 1 || event.state !== 'result' || event.provider !== profile.provider
            || !(profile.allowUnknownModel && event.clientReportedModel === null) && !modelName(event.clientReportedModel)) throw new Error('result rejected');
          validateResult(event.result, request);
          answer = { review: event.result, cliReportedModel: event.clientReportedModel };
        }
      };
      deadline(55_000);
      child.stdin.on('error', () => {});
      child.stdout.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > 2 * 1024 * 1024) { stop('cli_output_limit'); return; }
        try {
          pending += decoder.decode(chunk, { stream: true });
          for (let at; (at = pending.indexOf('\n')) >= 0;) {
            const line = pending.slice(0, at);
            pending = pending.slice(at + 1);
            if (failure) break;
            if (!line.trim()) throw new Error('empty native frame');
            frame(line);
          }
        } catch { stop('native_protocol_rejected'); }
      });
      child.stderr.on('data', (chunk) => { bytes += chunk.length; if (bytes > 2 * 1024 * 1024) stop('cli_output_limit'); });
      child.on('error', () => stop('cli_unavailable'));
      child.on('close', (code) => {
        clearTimeout(timer);
        clearTimeout(escalation);
        kill('SIGKILL');
        signal?.removeEventListener('abort', abort);
        try { pending += decoder.decode(); } catch { failure ||= new ConnectorError('native_protocol_rejected'); }
        if (pending.length) failure ||= new ConnectorError('native_protocol_rejected');
        if (!failure && (code !== 0 || !header || (!checkOnly && (!used || !answer)))) failure = new ConnectorError('native_result_missing');
        if (failure) { readyReject(failure); completedReject(failure); } else completedResolve(answer);
      });
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) abort();
      try {
        const status = await ready;
        if (checkOnly) await completed;
        const result = await callback({
          provider: profile.provider, version: profile.version, authMethod: profile.authMethod, sourceCommit: profile.sourceCommit,
          ...(profile.sourceRevision ? { sourceRevision: profile.sourceRevision } : {}),
          brokerIdentity: admitted.identity,
          review: async (approved, requested) => {
            if (checkOnly || used || requested !== model || failure || signal?.aborted) throw new ConnectorError('native_request_rejected');
            validateReviewRequest(approved);
            used = true;
            request = approved;
            clearTimeout(timer);
            child.stdin.write(JSON.stringify({ version: 1, instruction: approved.instruction, files: approved.files }) + '\n');
            return await completed;
          },
          cliReportedModel: status.clientReportedModel,
        });
        if (failure) throw failure;
        if (!checkOnly && !used) throw new ConnectorError('native_request_rejected');
        return result;
      } finally {
        if (child.exitCode === null && child.signalCode === null) stop('connector_cancelled');
        await completed.catch(() => {});
        const stat = fs.lstatSync(cwd);
        if (stat.isSymbolicLink() || stat.ino !== identity.ino || stat.dev !== identity.dev) throw new ConnectorError('native_session_cleanup_unverified');
        fs.rmSync(cwd, { recursive: true, force: true });
      }
    },
  };
}
