import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { REVIEW_IMAGE, LIMITS, ADAPTERS, hash, backendStatus, createSnapshot, disposeSnapshot, requireOwnedSnapshot, createJob, validateOutput, expectedFiles } from './worker-isolation.mjs';
import { writeReportFile } from './report-contract.mjs';
import { validateReviewRequest, validateResult, encodeFrame, readJsonLine } from './terminal-review-contract.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RUNTIME_FILES = ['worker-runtime.mjs', 'worker-isolation.mjs', 'report-contract.mjs', 'verification-health.mjs', 'scanner-evidence.mjs', 'audit-process.mjs', 'audit-submission.mjs', 'review-workflow.mjs', 'terminal-review-contract.mjs'];
const IMAGE = /^(?:[a-z0-9][a-z0-9./:_-]*@)?sha256:[a-f0-9]{64}$/;
const OWNED_RECORDS = new Map();
export function createRecordDirectory() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-review-ledger-'));
  fs.chmodSync(dir, 0o700);
  const stat = fs.lstatSync(dir);
  OWNED_RECORDS.set(dir, { dev: stat.dev, ino: stat.ino });
  return dir;
}
export function disposeRecordDirectory(dir) {
  const identity = OWNED_RECORDS.get(dir);
  const stat = identity && fs.lstatSync(dir);
  if (!identity || !stat.isDirectory() || stat.isSymbolicLink() || stat.dev !== identity.dev || stat.ino !== identity.ino) throw new Error('refusing cleanup of an unowned or replaced ledger directory');
  fs.rmSync(dir, { recursive: true, force: true });
  OWNED_RECORDS.delete(dir);
}
const STATES = {
  pending: ['running', 'blocked', 'failed', 'cancelled'],
  running: ['failed', 'timed_out', 'cancelled', 'rejected_output', 'collected'],
};
export function transition(job, state, detail = {}) {
  if (!STATES[job.state]?.includes(state)) throw new Error('invalid worker state transition');
  Object.assign(job, detail, { state });
}
export function runtimeDigest() {
  return hash(JSON.stringify(RUNTIME_FILES.map((name) => [name, hash(fs.readFileSync(path.join(HERE, name)))])));
}

// Only trusted fixed Docker invocations use this helper; no target command API.
async function docker(args, { maxBytes = LIMITS.logBytes, timeoutMs = 15_000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    let size = 0;
    let exceeded = false;
    const timer = setTimeout(() => { exceeded = true; child.kill('SIGKILL'); }, timeoutMs);
    const receive = (target) => (data) => {
      size += data.length;
      if (size > maxBytes) { exceeded = true; child.kill('SIGKILL'); return; }
      target.push(data);
    };
    child.stdout.on('data', receive(out));
    child.stderr.on('data', receive(err));
    child.on('error', (error) => { clearTimeout(timer); reject(error); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (exceeded) { reject(new Error('Docker control command exceeded its byte/deadline budget')); return; }
      resolve({ code, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') });
    });
  });
}
async function requireDocker(args, options) {
  const result = await docker(args, options);
  if (result.code !== 0) throw new Error('Docker control operation failed');
  return result;
}

function security(image, name, label, runtime) {
  if (!IMAGE.test(image)) throw new Error('review runtime requires an immutable image identity');
  const args = ['--pull=never', '--name', name, '--label', `freightchain.review.job=${label}`, '--network', 'none', '--ipc', 'private', '--user', '10001:10001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only', '--pids-limit', '64', '--memory', '128m', '--cpus', '1', '--log-driver', 'json-file', '--log-opt', 'max-size=1m', '--log-opt', 'max-file=1', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777', '--env', 'HOME=/home/reviewer', '--entrypoint', '/usr/local/bin/node', '--tmpfs', '/home/reviewer:rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=700'];
  for (const file of RUNTIME_FILES) args.push('--mount', `type=bind,src=${path.join(runtime.snapshot, file)},dst=/trusted/${file},readonly`);
  return args;
}

async function removeOwned(type, name, label) {
  const result = await docker(type === 'volume'
    ? ['volume', 'inspect', name, '--format', '{{index .Labels "freightchain.review.job"}}']
    : ['inspect', name, '--format', '{{index .Config.Labels "freightchain.review.job"}}']);
  if (result.code !== 0) {
    if (/no such (container|object|volume)/i.test(result.stderr)) return;
    throw new Error('Docker cleanup could not be verified');
  }
  if (result.stdout.trim() !== label) throw new Error('refusing cleanup of an unowned Docker resource');
  await requireDocker(type === 'volume' ? ['volume', 'rm', name] : ['rm', '--force', name]);
}

export function runFixture(snapshot, job, options = {}) {
  if (job.phase === 'terminal') throw new Error('terminal jobs require the explicit terminal entry point');
  return runIsolated(snapshot, job, options);
}
export function runTerminalReview(snapshot, job, request, onReview, options = {}) {
  validateReviewRequest(request);
  if (job.phase !== 'terminal' || request.jobId !== job.id || request.sourceDigest !== job.sourceDigest || typeof onReview !== 'function') throw new Error('terminal job authorization rejected');
  return runIsolated(snapshot, job, { ...options, terminalRequest: structuredClone(request), onReview });
}
function abortable(promise, signal) {
  return new Promise((resolve, reject) => {
    const abort = () => reject(Object.assign(new Error('terminal exchange aborted'), { code: signal.reason?.name === 'TimeoutError' ? 'terminal_timeout' : 'terminal_cancelled' }));
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve(promise).then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
    if (signal.aborted) abort();
  });
}
function attachTerminal(worker) {
  const child = spawn('docker', ['start', '--attach', '--interactive', worker], { stdio: ['pipe', 'pipe', 'pipe'] });
  let errorBytes = 0;
  const errors = [];
  const closed = new Promise((resolve, reject) => {
    child.on('error', () => reject(new Error('terminal Docker attach failed')));
    child.on('close', (code) => resolve(code));
  });
  closed.catch(() => {});
  child.stdin.on('error', () => {});
  child.stderr.on('data', (chunk) => {
    errorBytes += chunk.length;
    if (errorBytes > LIMITS.logBytes) child.kill('SIGKILL');
    else errors.push(chunk);
  });
  return { child, closed, errors: () => Buffer.concat(errors).toString('utf8') };
}

async function runIsolated(snapshot, job, { fixture = 'probe', image = REVIEW_IMAGE, deadlineMs = null, signal, onStarted, recordDir, terminalRequest, onReview } = {}) {
  if (!['probe', 'wait', 'malformed', 'extra', 'oversized'].includes(fixture) || (deadlineMs != null && (!Number.isSafeInteger(deadlineMs) || deadlineMs < 50 || deadlineMs > 2_147_483_647))) throw new Error('invalid fixture limits');
  requireOwnedSnapshot(snapshot);
  if (!IMAGE.test(image) || job.state !== 'pending' || job.sourceDigest !== snapshot.manifest.digest || job.runtimeDigest !== runtimeDigest() || JSON.stringify(job.expected) !== JSON.stringify(expectedFiles(job.phase)) || job.assignmentDigest !== hash(JSON.stringify(job.claims))) throw new Error('invalid immutable job runtime');
  const label = crypto.randomUUID();
  const prefix = `fc-review-${label}`;
  const volume = `${prefix}-out`;
  const worker = `${prefix}-worker`;
  const collector = `${prefix}-collect`;
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-job-'));
  fs.chmodSync(work, 0o700);
  const input = path.join(work, 'input');
  const collected = path.join(work, 'collected');
  const records = recordDir || createRecordDirectory();
  try {
  const recordStat = fs.lstatSync(records);
  if (!recordStat.isDirectory() || recordStat.isSymbolicLink() || (recordStat.mode & 0o077) !== 0 || recordStat.uid !== process.getuid() || fs.readdirSync(records).length) {
    fs.rmSync(work, { recursive: true, force: true });
    throw new Error('ledger requires a fresh private parent-owned directory');
  }
  fs.mkdirSync(input, { mode: 0o755 });
  fs.mkdirSync(collected, { mode: 0o700 });
  fs.writeFileSync(path.join(input, 'job.json'), JSON.stringify(terminalRequest
    ? { job, executionMode: 'terminal_supplied_unverified', terminalRequest, terminalDeadlineMs: deadlineMs }
    : { job, executionMode: 'inert_fixture', fixture }), { mode: 0o444 });
  fs.chmodSync(input, 0o555);
  } catch (err) {
    fs.rmSync(work, { recursive: true, force: true });
    throw err;
  }
  const ledger = { version: 1, executionMode: terminalRequest ? 'terminal_supplied_unverified' : 'inert_fixture', image, job, recordDirectory: records, resources: { worker, volume, collector, label }, credentialPolicy: 'none_in_worker', toolPolicy: 'no_shell_or_target_execution', limits: { executionDeadlineMs: deadlineMs, controlDeadlineMs: 15_000, outputBytes: LIMITS.outputBytes, logBytes: LIMITS.logBytes, outboxBytes: 16 * 1024 * 1024, memoryBytes: 128 * 1024 * 1024, cpus: 1, pids: 64 } };
  ledger.policyDigest = hash(JSON.stringify({ credentials: ledger.credentialPolicy, tools: ledger.toolPolicy, limits: ledger.limits }));
  const save = () => writeReportFile(records, 'ledger.json', JSON.stringify(ledger, null, 2));
  const outcome = { ledger };
  let artifacts;
  let runtime;
  let terminal;
  let stage = 'setup';
  const interrupted = new AbortController();
  const cancelled = signal ? AbortSignal.any([signal, interrupted.signal]) : interrupted.signal;
  const onSignal = () => { interrupted.abort(); process.exitCode = 130; };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);
  try {
    save();
    if (cancelled.aborted) { transition(job, 'cancelled'); return outcome; }
    runtime = createSnapshot(HERE, { only: RUNTIME_FILES });
    requireOwnedSnapshot(runtime);
    const capturedDigest = hash(JSON.stringify(RUNTIME_FILES.map((name) => [name, runtime.manifest.files.find((f) => f.path === name)?.sha256])));
    if (capturedDigest !== job.runtimeDigest) throw new Error('trusted runtime changed before sealed capture');
    await requireDocker(['image', 'inspect', image, '--format', '{{.Id}}']);
    if (cancelled.aborted) { transition(job, 'cancelled'); return outcome; }
    const allowedEnv = new Set(['HOME', 'PATH', 'NODE_VERSION', 'YARN_VERSION']);
    const imageKeys = (await requireDocker(['image', 'inspect', image, '--format', '{{range .Config.Env}}{{println (index (split . "=") 0)}}{{end}}'])).stdout.trim().split(/\s+/).filter(Boolean);
    if (imageKeys.some((k) => !allowedEnv.has(k))) throw new Error('runtime image environment rejected');
    if (cancelled.aborted) { transition(job, 'cancelled'); return outcome; }
    await requireDocker(['volume', 'create', '--driver', 'local', '--opt', 'type=tmpfs', '--opt', 'device=tmpfs', '--opt', 'o=size=16m,uid=10001,gid=10001,mode=0700,noexec,nosuid,nodev', '--label', `freightchain.review.job=${label}`, volume]);
    const out = ['--mount', `type=volume,src=${volume},dst=/out`];
    const inputMount = ['--mount', `type=bind,src=${input},dst=/input,readonly`];
    await requireDocker(['run', '--detach', ...security(image, collector, label, runtime), '--mount', `type=volume,src=${volume},dst=/out,readonly`, ...inputMount, image, '/trusted/worker-runtime.mjs', 'hold']);
    if (cancelled.aborted) { transition(job, 'cancelled'); return outcome; }
    await requireDocker(['create', ...(terminalRequest ? ['--interactive'] : []), ...security(image, worker, label, runtime), ...out, ...inputMount, '--mount', `type=bind,src=${snapshot.snapshot},dst=/source,readonly`, image, '/trusted/worker-runtime.mjs', terminalRequest ? 'terminal-review' : 'fixture']);
    const inspected = await requireDocker(['inspect', worker, '--format', '{{json .}}']);
    const spec = JSON.parse(inspected.stdout);
    ledger.boundary = { network: spec.HostConfig.NetworkMode, ipc: spec.HostConfig.IpcMode, pid: spec.HostConfig.PidMode, user: spec.Config.User, readOnly: spec.HostConfig.ReadonlyRootfs, capDrop: spec.HostConfig.CapDrop, securityOpt: spec.HostConfig.SecurityOpt, mounts: spec.Mounts.map((m) => ({ destination: m.Destination, readOnly: !m.RW, type: m.Type })), environmentKeys: spec.Config.Env.map((e) => e.split('=')[0]) };
    if (ledger.boundary.network !== 'none' || ledger.boundary.user !== '10001:10001' || !ledger.boundary.readOnly || !ledger.boundary.capDrop.includes('ALL') || !ledger.boundary.securityOpt.some((s) => s.startsWith('no-new-privileges')) || ledger.boundary.environmentKeys.some((k) => !allowedEnv.has(k))) throw new Error('runtime security specification rejected');
    if (terminalRequest) terminal = attachTerminal(worker);
    else await requireDocker(['start', worker]);
    transition(job, 'running', { startedAt: new Date().toISOString() });
    stage = 'execution';
    save();
    const deadline = deadlineMs == null ? Infinity : Date.now() + deadlineMs;
    const executionSignal = deadlineMs == null ? cancelled : AbortSignal.any([cancelled, AbortSignal.timeout(deadlineMs)]);
    if (onStarted) await abortable(onStarted(ledger), executionSignal);
    if (terminalRequest) {
      const exchangeSignal = executionSignal;
      const frame = await readJsonLine(terminal.child.stdout, { timeoutMs: deadlineMs, signal: exchangeSignal });
      validateReviewRequest(frame);
      if (JSON.stringify(frame) !== JSON.stringify(terminalRequest)) throw new Error('worker requested an unauthorized review');
      ledger.relay = { requestId: frame.requestId, requestDigest: hash(JSON.stringify(frame)), origin: 'terminal_supplied_unverified', modelIdentity: 'unverified', toolsDisabled: 'unverified' };
      save();
      const result = await abortable(onReview(frame), exchangeSignal);
      validateResult(result, terminalRequest);
      terminal.child.stdin.end(encodeFrame({ version: 1, type: 'review.result', requestId: frame.requestId, jobId: frame.jobId, sourceDigest: frame.sourceDigest, result }));
      if (await abortable(terminal.closed, exchangeSignal) !== 0) throw new Error('terminal worker exited unsuccessfully');
      ledger.relay.resultDigest = hash(JSON.stringify(result));
    }
    for (;;) {
      if (cancelled.aborted) { transition(job, 'cancelled'); break; }
      if (Date.now() >= deadline) { transition(job, 'timed_out'); break; }
      const state = JSON.parse((await requireDocker(['inspect', worker, '--format', '{{json .State}}'])).stdout);
      if (!state.Running) {
        job.observedExitCode = state.ExitCode;
        if (state.ExitCode !== 0 || state.OOMKilled) transition(job, 'failed');
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    if (job.state === 'cancelled' || job.state === 'timed_out') await requireDocker(['kill', worker]);
    const waited = await requireDocker(['wait', worker]);
    if (/^\d+\s*$/.test(waited.stdout)) job.observedExitCode = Number(waited.stdout.trim());
    const logs = await docker(['logs', worker]);
    ledger.logs = { stdout: logs.stdout, stderr: logs.stderr };
    if (job.state !== 'running') return outcome;
    if (cancelled.aborted) { transition(job, 'cancelled'); return outcome; }
    stage = 'collection';
    // A separate trusted process sees one stopped outbox, not the source tree.
    const exported = await requireDocker(['exec', '--user', '10001:10001', collector, '/usr/local/bin/node', '/trusted/worker-runtime.mjs', 'collect'], { maxBytes: LIMITS.outputBytes * 3 });
    const envelope = JSON.parse(exported.stdout);
    if (envelope.version !== 1 || !envelope.files || JSON.stringify(Object.keys(envelope.files).sort()) !== JSON.stringify([...job.expected].sort())) throw new Error('collector envelope rejected');
    for (const name of job.expected) {
      const base64 = envelope.files[name];
      if (typeof base64 !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(base64) || base64.length > Math.ceil(LIMITS.outputBytes / 3) * 4) throw new Error('collector bytes rejected');
      const bytes = Buffer.from(base64, 'base64');
      if (bytes.length > LIMITS.outputBytes || bytes.toString('base64') !== base64) throw new Error('collector encoding rejected');
      fs.writeFileSync(path.join(collected, name), bytes, { flag: 'wx', mode: 0o600 });
    }
    artifacts = validateOutput(job, collected);
    if (cancelled.aborted) { transition(job, 'cancelled'); return outcome; }
    transition(job, 'collected', { outputHashes: artifacts.hashes });
    outcome.artifacts = artifacts;
    return outcome;
  } catch (err) {
    if (job.state === 'running') transition(job, err.code === 'terminal_timeout' ? 'timed_out' : cancelled.aborted || err.code === 'terminal_cancelled' ? 'cancelled' : stage === 'collection' ? 'rejected_output' : 'failed', { reason: stage === 'collection' ? 'output_contract_rejected' : 'isolation_runtime_failure' });
    else if (job.state === 'pending') transition(job, 'failed', { reason: 'isolation_runtime_unavailable' });
    return outcome;
  } finally {
    job.finishedAt = new Date().toISOString();
    try { save(); } catch { ledger.recordPersistence = 'failed'; }
    const cleanupErrors = [];
    for (const name of [worker, collector]) {
      try { await removeOwned('container', name, label); } catch { cleanupErrors.push(name); }
    }
    try { await removeOwned('volume', volume, label); } catch { cleanupErrors.push(volume); }
    if (terminal && terminal.child.exitCode === null) terminal.child.kill('SIGKILL');
    process.removeListener('SIGINT', onSignal);
    process.removeListener('SIGTERM', onSignal);
    try {
      fs.chmodSync(input, 0o700);
      fs.rmSync(work, { recursive: true, force: true });
    } catch { cleanupErrors.push(work); }
    if (runtime) {
      try { disposeSnapshot(runtime); } catch { cleanupErrors.push(runtime.staging); }
    }
    ledger.cleanup = cleanupErrors.length ? { state: 'failed', resources: cleanupErrors } : { state: 'removed' };
    if (ledger.recordPersistence !== 'failed') ledger.recordPersistence = 'saved';
    try { save(); } catch { ledger.recordPersistence = 'failed'; }
    if (ledger.recordPersistence === 'failed' || cleanupErrors.length) {
      ledger.runStatus = 'incomplete';
      delete outcome.artifacts;
    }
  }
}

export function recordBlockedRun(request) {
  if (!request || !Array.isArray(request.agents) || !request.agents.length || !request.agents.every((a) => ADAPTERS.includes(a)) || new Set(request.agents).size !== request.agents.length) throw new Error('invalid requested adapters');
  const output = path.resolve(request.out);
  if (output === fs.realpathSync(request.target)) throw new Error('output cannot be the source root');
  if (fs.existsSync(output) && fs.readdirSync(output).length) throw new Error('output directory must be empty');
  fs.mkdirSync(output, { recursive: true, mode: 0o700 });
  fs.chmodSync(output, 0o700);
  fs.mkdirSync(path.join(output, 'auditors'), { mode: 0o700 });
  let snapshot;
  try {
    snapshot = createSnapshot(request.target, { exclude: [output] });
    const runtime = runtimeDigest();
    const slugs = ['auth', 'input', 'logic', 'config', 'deps', 'client'];
    const surface = request.surface === 'all' ? 'all' : /^s[1-6]$/.test(request.surface) ? request.surface : `s${slugs.indexOf(request.surface) + 1}`;
    const ids = surface === 'all' ? [1, 2, 3, 4, 5, 6] : [Number(surface.slice(1))];
    const jobs = ids.flatMap((id, i) => (surface === 'all' ? [request.agents[i % request.agents.length]] : request.agents).map((adapter) => createJob({ adapter, model: request.models[adapter], surface: `s${id}`, sourceDigest: snapshot.manifest.digest, runtimeDigest: runtime })));
    const manifest = { version: 1, runId: crypto.randomUUID(), policy: 'read_only_source_review', sourceDigest: snapshot.manifest.digest, runtimeDigest: runtime, image: REVIEW_IMAGE, jobs };
    writeReportFile(output, 'workers.json', `${JSON.stringify(manifest, null, 2)}\n`);
    for (const job of jobs) transition(job, 'blocked', { reason: backendStatus(job.adapter).reason, observedExitCode: null });
    writeReportFile(output, 'workers.json', `${JSON.stringify(manifest, null, 2)}\n`);
    writeReportFile(output, 'source-manifest.json', `${JSON.stringify(snapshot.manifest, null, 2)}\n`);
    const meta = { name: request.name || path.basename(request.target), mode: request.mode, source: request.source, ref: request.ref || null, commit: request.commit || null, date: new Date().toISOString(), surface, agents: request.agents, models: request.models, auditors: jobs.map((j) => j.name), workerExits: Object.fromEntries(jobs.map((j) => [j.name, null])), crosscheckExits: {}, stageFailures: ['subscription_bridge_unverified'], finalized: true, isolation: { policy: manifest.policy, sourceDigest: manifest.sourceDigest, liveTransport: 'blocked', privateOutputs: 'required', workerManifest: 'workers.json' } };
    writeReportFile(output, 'meta.json', `${JSON.stringify(meta, null, 2)}\n`);
    return manifest;
  } finally { if (snapshot) disposeSnapshot(snapshot); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [mode, file] = process.argv.slice(2);
    if (mode !== 'blocked-run') throw new Error('supervisor command refused');
    const request = JSON.parse(fs.readFileSync(file, 'utf8'));
    recordBlockedRun(request);
    console.error('BLOCKED: legacy multi-surface adapters are not integrated with the selected-file terminal connector. A ready Claude login does not enable audit run. No host fallback or target execution.');
    process.exitCode = 2;
  } catch (err) {
    console.error(`review isolation: ${err.message}`);
    process.exitCode = 2;
  }
}
