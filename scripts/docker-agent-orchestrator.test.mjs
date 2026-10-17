import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { runOrchestratedAudit, savedTurnCompleted } from './docker-agent-orchestrator.mjs';
import { commitSubmission } from './audit-submission.mjs';
import { readReportJson } from './report-contract.mjs';

// Inert reviewer gates expose scheduling without provider requests or target execution.
function fixture(t, agents = ['claude', 'grok', 'agy', 'codex'], surface = 'all') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-parallel-'));
  const target = path.join(root, 'source'), out = path.join(root, 'report');
  fs.mkdirSync(target);
  fs.writeFileSync(path.join(target, 'source.js'), 'export const inert = true;\n');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const started = new Map(), active = new Set(), completed = [];
  let stopped = false;
  let loseSandbox;
  const lost = new Promise(resolve => { loseSandbox = resolve; });
  const review = async options => {
    const { identity } = options;
    assert.equal(stopped, false);
    assert.equal(active.has(identity.agent), false, 'one active session per provider');
    active.add(identity.agent);
    const result = await new Promise(resolve => started.set(identity.name, { ...options, release: resolve }));
    try {
      if (result?.throw) throw new Error('Inert reviewer transport failure');
      if (!result?.code && !result?.missingReport) {
        const payload = identity.role === 'auditor' ? [{
          title: `Inert finding ${identity.name}`, surface: identity.surface,
          severity: 'low', confidence: 'probable', location: ['source.js:1'],
          impact: 'Fixture only', preconditions: 'Inert fixture', analysis: 'Inspected source.js:1',
          validation: 'No target execution', attack: [], poc: '', fix: 'Fixture guidance',
        }, { verified_safe: [] }] : readReportJson(out, `crosscheck/${identity.agent}.json`).map(claim => ({
          id: claim.id, verdict: 'upheld', reason: 'Inert source evidence', evidence: ['source.js:1'],
        }));
        commitSubmission(out, identity.name, identity, payload);
      }
      return { code: 0, observedExitCode: 0, elapsedMs: 1, sessionId: identity.name, directory: options.directory, ...result };
    } finally { active.delete(identity.agent); completed.push(identity.name); }
  };
  const startSandbox = async () => ({ container: 'inert-sandbox', lost, hostRunDir: path.join(root, 'container-output'), stop: async () => {
    assert.equal(active.size, 0, 'cleanup waits for every active session');
    stopped = true;
  } });
  const request = { target, out, name: 'inert-scheduling-fixture', agents, surface, models: Object.fromEntries(agents.map(agent => [agent, 'fixture-model'])) };
  const run = runOrchestratedAudit(request, { review, startSandbox });
  const waitFor = async predicate => {
    const deadline = performance.now() + 3000;
    while (!predicate()) {
      assert.ok(performance.now() < deadline, 'scheduler reached the expected state');
      await delay(5);
    }
  };
  return { out, started, active, completed, run, waitFor, loseSandbox, get stopped() { return stopped; } };
}

test('sandbox loss cancels active sessions, preserves queued assignments and starts no peer checks', async t => {
  const f = fixture(t);
  await f.waitFor(() => f.started.size === 4);
  f.loseSandbox(new Error('Inert sandbox loss'));
  await f.waitFor(() => [...f.started.values()].every(options => options.signal.aborted));
  for (const options of f.started.values()) options.release({ code: 130, failureReason: 'cancelled' });
  const result = await f.run;
  assert.equal(result.cancelled, false, 'infrastructure loss is not an operator cancellation');
  assert.ok(result.stageFailures.includes('sandbox_unavailable'));
  assert.equal(f.started.size, 4);
  const jobs = readReportJson(f.out, 'workers.json').jobs;
  assert.ok(jobs.every(job => job.failure.reason === 'sandbox_unavailable'));
  assert.ok(jobs.filter(job => ['s5', 's6'].includes(job.surface.id)).every(job => job.state === 'pending'));
  assert.equal(f.stopped, true);
});

test('providers overlap, their own surfaces queue, and peer reviews start together after all surfaces finish', { timeout: 10_000 }, async t => {
  const f = fixture(t);
  await f.waitFor(() => f.started.size === 4);
  assert.equal(f.active.size, 4);
  assert.deepEqual([...f.started.keys()], ['claude-s1-auth', 'grok-s2-input', 'agy-s3-logic', 'codex-s4-config']);
  const workers = readReportJson(f.out, 'workers.json');
  assert.equal(workers.jobs.filter(job => job.state === 'running').length, 4);
  assert.equal(workers.jobs.filter(job => job.state === 'pending').length, 2);

  f.started.get('grok-s2-input').release();
  await f.waitFor(() => f.started.has('grok-s6-client'));
  assert.equal(f.completed.includes('claude-s1-auth'), false, 'fast providers advance without waiting for slow peers');
  f.started.get('claude-s1-auth').release();
  await f.waitFor(() => f.started.has('claude-s5-deps'));
  for (const name of ['agy-s3-logic', 'codex-s4-config', 'claude-s5-deps']) f.started.get(name).release();
  await f.waitFor(() => f.completed.length === 5);
  assert.equal(f.started.size, 6, 'cross-checks wait for the last surface');
  assert.equal(f.stopped, false);
  f.started.get('grok-s6-client').release();

  await f.waitFor(() => f.started.size === 10);
  assert.equal(f.active.size, 4, 'all peer reviewers run concurrently');
  for (const agent of ['claude', 'grok', 'agy', 'codex']) {
    const claims = readReportJson(f.out, `crosscheck/${agent}.json`);
    assert.equal(claims.length, ['claude', 'grok'].includes(agent) ? 4 : 5);
    assert.ok(claims.every(claim => claim.model !== agent));
    f.started.get(`crosscheck-${agent}`).release();
  }
  assert.deepEqual((await f.run).stageFailures, []);
  assert.equal(f.stopped, true);
  assert.ok(readReportJson(f.out, 'workers.json').jobs.every(job => job.state === 'collected'));
  assert.ok(Object.values(readReportJson(f.out, 'meta.json').crosscheckExits).every(code => code === 0));
});

test('a failed reviewer stays incomplete while other providers and its remaining surfaces finish', { timeout: 10_000 }, async t => {
  const f = fixture(t, ['claude', 'grok']);
  await f.waitFor(() => f.started.size === 2);
  f.started.get('claude-s1-auth').release({ code: 1, observedExitCode: 7, failureReason: 'invalid_report' });
  await f.waitFor(() => f.started.has('claude-s3-logic'));
  assert.equal(f.completed.includes('grok-s2-input'), false);
  for (const name of ['claude-s3-logic', 'claude-s5-deps', 'grok-s2-input', 'grok-s4-config', 'grok-s6-client', 'crosscheck-claude', 'crosscheck-grok']) {
    await f.waitFor(() => f.started.has(name));
    f.started.get(name).release();
  }
  const result = await f.run;
  assert.deepEqual(result.stageFailures, ['auditor_error:claude-s1-auth']);
  const failed = readReportJson(f.out, 'workers.json').jobs.find(job => job.name === 'claude-s1-auth');
  assert.equal(failed.state, 'failed');
  assert.equal(failed.failure.reason, 'invalid_report');
  assert.equal(failed.observedExitCode, 7);
  assert.equal(f.started.size, 8, 'no retry or provider substitution');
  assert.equal(f.stopped, true);
});

test('cancellation reaches all active providers, skips queued surfaces and waits before teardown', { timeout: 10_000 }, async t => {
  const f = fixture(t);
  await f.waitFor(() => f.started.size === 4);
  process.emit('SIGINT');
  assert.ok([...f.started.values()].every(options => options.signal.aborted));
  for (const name of ['claude-s1-auth', 'grok-s2-input', 'agy-s3-logic']) f.started.get(name).release({ code: 130, failureReason: 'cancelled' });
  await f.waitFor(() => f.completed.length === 3);
  assert.equal(f.stopped, false, 'the last active provider still owns the sandbox');
  f.started.get('codex-s4-config').release({ code: 130, failureReason: 'cancelled' });
  assert.equal((await f.run).cancelled, true);
  assert.equal(f.started.size, 4);
  const queued = readReportJson(f.out, 'workers.json').jobs.filter(job => ['s5', 's6'].includes(job.surface.id));
  assert.ok(queued.every(job => job.state === 'cancelled'));
  assert.equal(f.stopped, true);
});

test('quota failures defer that provider’s queued work while other providers finish', async t => {
  const f = fixture(t, ['claude', 'grok']);
  await f.waitFor(() => f.started.size === 2);
  f.started.get('claude-s1-auth').release({ code: 1, failureReason: 'usage_limit' });
  for (const name of ['grok-s2-input', 'grok-s4-config', 'grok-s6-client']) {
    await f.waitFor(() => f.started.has(name));
    f.started.get(name).release();
  }
  const result = await f.run;
  assert.ok(result.stageFailures.includes('crosscheck_deferred:claude'));
  assert.deepEqual([...f.started.keys()], ['claude-s1-auth', 'grok-s2-input', 'grok-s4-config', 'grok-s6-client']);
  const jobs = readReportJson(f.out, 'workers.json').jobs;
  assert.ok(jobs.filter(job => ['claude-s3-logic', 'claude-s5-deps'].includes(job.name)).every(job => job.state === 'pending' && !job.sessionId));
  assert.equal(readReportJson(f.out, 'meta.json').providerFailures.claude, 'usage_limit');
});

test('resume reuses successful immutable reports and reruns peer checks when claims change', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-selective-resume-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const target = path.join(root, 'source');
  fs.mkdirSync(target);
  fs.writeFileSync(path.join(target, 'source.js'), 'export const inert = true;');
  let phase = 0;
  const calls = [];
  const review = async options => {
    const { identity, directory, bridgeArgs } = options;
    calls.push(identity.name);
    fs.mkdirSync(directory, { recursive: true });
    fs.writeFileSync(path.join(directory, 'state.json'), JSON.stringify({ identity, sessionId: identity.name }));
    const out = bridgeArgs[bridgeArgs.indexOf('--report-dir') + 1];
    const failed = phase === 0 && ['claude-s5-deps', 'crosscheck-claude'].includes(identity.name);
    if (!failed) {
      const payload = identity.role === 'auditor' ? [{ title: identity.name, surface: identity.surface, severity: 'info', confidence: 'probable', location: ['source.js:1'], impact: 'Inert', preconditions: '', analysis: 'Source read', validation: 'Fixture', attack: [], poc: '', fix: 'Fixture' }, { verified_safe: [] }] : readReportJson(out, `crosscheck/${identity.agent}.json`).map(row => ({ id: row.id, verdict: 'upheld', reason: 'Inert source', evidence: ['source.js:1'] }));
      commitSubmission(out, identity.name, identity, payload);
    }
    return { code: failed ? 1 : 0, failureReason: failed ? 'usage_limit' : null, sessionId: identity.name, directory, elapsedMs: 1, observedExitCode: 0 };
  };
  const startSandbox = async ({ out }) => ({ container: 'inert', hostRunDir: out, stop: async () => {} });
  const request = { target, out: path.join(root, 'initial'), surface: 'all', agents: ['claude', 'grok'], models: { claude: 'fixture', grok: 'fixture' } };
  await runOrchestratedAudit(request, { review, startSandbox });
  phase = 1; calls.length = 0;
  const recovered = path.join(root, 'recovered');
  const result = await runOrchestratedAudit({ ...request, out: recovered, resumeFrom: request.out }, { review, startSandbox });
  assert.deepEqual(result.stageFailures, []);
  assert.deepEqual(calls.sort(), ['claude-s5-deps', 'crosscheck-claude', 'crosscheck-grok']);
  assert.equal(readReportJson(recovered, 'workers.json').jobs.filter(row => row.reusedFrom).length, 5);
  calls.length = 0;
  await runOrchestratedAudit({ ...request, out: path.join(root, 'again'), resumeFrom: recovered }, { review, startSandbox });
  assert.deepEqual(calls, []);
});


test('saved completion repair requires a normal turn, clean process exit and no RPC error', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-completion-repair-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root,'harness/sandbox-run'),{recursive:true});
  const directory=path.join(root,'session'); fs.mkdirSync(directory);
  const state={failureReason:'usage_limit',observedExitCode:0};
  const writeState=()=>fs.writeFileSync(path.join(directory,'state.json'),JSON.stringify(state));
  writeState();
  const file=path.join(root,'harness/sandbox-run/agent-claude-s1-auth.log');
  const end=JSON.stringify({jsonrpc:'2.0',id:3,result:{stopReason:'end_turn'}})+'\n';
  fs.writeFileSync(file,end);
  assert.equal(savedTurnCompleted(root,'claude-s1-auth',directory),true);
  fs.writeFileSync(file,JSON.stringify({jsonrpc:'2.0',id:3,error:{message:'RESOURCE_EXHAUSTED'}})+'\n'+end);
  assert.equal(savedTurnCompleted(root,'claude-s1-auth',directory),false);
  fs.writeFileSync(file,end);state.observedExitCode=1;writeState();
  assert.equal(savedTurnCompleted(root,'claude-s1-auth',directory),false);
  state.observedExitCode=0;state.failureReason='protocol_error';writeState();
  assert.equal(savedTurnCompleted(root,'claude-s1-auth',directory),false);
});

test('resume preserves a report committed before a failed turn and requires a clean acknowledgement', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-committed-resume-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const target = path.join(root, 'source'); fs.mkdirSync(target);
  fs.writeFileSync(path.join(target, 'source.js'), 'export const inert = true;');
  let phase = 0;
  const review = async ({ identity, directory, bridgeArgs }) => {
    fs.mkdirSync(directory, { recursive: true });
    fs.writeFileSync(path.join(directory, 'state.json'), JSON.stringify({ identity, sessionId: identity.name }));
    const out = bridgeArgs[bridgeArgs.indexOf('--report-dir') + 1];
    if (!phase) commitSubmission(out, identity.name, identity, [{ verified_safe: [] }]);
    else assert.ok(readReportJson(out, `submissions/${identity.name}.json`).hash, 'the saved report is retained without another submission');
    return { code: phase ? 0 : 1, observedExitCode: 0, failureReason: phase ? null : 'native_turn_failed', sessionId: identity.name, directory };
  };
  const startSandbox = async ({ out }) => ({ container: 'inert', hostRunDir: out, stop: async () => {} });
  const request = { target, out: path.join(root, 'first'), surface: 's3', agents: ['agy'], models: { agy: 'fixture' } };
  assert.ok((await runOrchestratedAudit(request, { review, startSandbox })).stageFailures.length);
  phase = 1;
  const recovered = path.join(root, 'recovered');
  assert.deepEqual((await runOrchestratedAudit({ ...request, out: recovered, resumeFrom: request.out }, { review, startSandbox })).stageFailures, []);
  assert.equal(readReportJson(recovered, 'workers.json').jobs[0].state, 'collected');
});

test('explicit restart gives a failed local session a new full review without reusing its failed report', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-restart-local-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const target = path.join(root, 'source'); fs.mkdirSync(target);
  fs.writeFileSync(path.join(target, 'source.js'), 'export const inert = true;');
  let phase = 0, firstDirectory, secondDirectory;
  const review = async ({ identity, directory, bridgeArgs, resume }) => {
    const out = bridgeArgs[bridgeArgs.indexOf('--report-dir') + 1];
    if (phase) { secondDirectory = directory; assert.equal(resume, false); assert.equal(fs.existsSync(path.join(out, `submissions/${identity.name}.json`)), false); assert.ok(fs.existsSync(path.join(out, `harness/prior-${identity.name}.json`)), 'old work is retained only as untrusted notes'); }
    else firstDirectory = directory;
    fs.mkdirSync(directory, { recursive: true });
    fs.writeFileSync(path.join(directory, 'state.json'), JSON.stringify({ identity, sessionId: identity.name, failureReason: phase ? null : 'native_turn_failed' }));
    commitSubmission(out, identity.name, identity, [{ verified_safe: [] }]);
    return { code: phase ? 0 : 1, observedExitCode: 0, failureReason: phase ? null : 'native_turn_failed', sessionId: identity.name, directory };
  };
  const startSandbox = async ({ out }) => ({ container: 'inert', hostRunDir: out, stop: async () => {} });
  const request = { target, out: path.join(root, 'first'), surface: 's3', agents: ['agy'], models: { agy: 'fixture' } };
  await runOrchestratedAudit(request, { review, startSandbox });
  phase = 1;
  const recovered = path.join(root, 'fresh');
  const result = await runOrchestratedAudit({ ...request, out: recovered, resumeFrom: request.out, restartFailed: true }, { review, startSandbox });
  assert.deepEqual(result.stageFailures, []);
  assert.notEqual(secondDirectory, firstDirectory);
  assert.equal(readReportJson(recovered, 'workers.json').jobs[0].restartedFrom, firstDirectory);

  const workers = readReportJson(request.out, 'workers.json'); workers.jobs[0].failure.reason = 'provider_policy';
  fs.writeFileSync(path.join(request.out, 'workers.json'), JSON.stringify(workers));
  let calls = 0;
  const blocked = path.join(root, 'blocked');
  const failed = await runOrchestratedAudit({ ...request, out: blocked, resumeFrom: request.out, restartFailed: true }, { review: async () => { calls++; assert.fail('Provider refusals cannot receive a fresh conversation'); }, startSandbox });
  assert.ok(failed.stageFailures.length);
  assert.equal(calls, 0);
  assert.equal(readReportJson(blocked, 'workers.json').jobs[0].failure.reason, 'provider_policy');
  workers.jobs[0].failure.reason = 'native_turn_failed';
  fs.writeFileSync(path.join(request.out, 'workers.json'), JSON.stringify(workers));
  const meta = readReportJson(request.out, 'meta.json'); meta.providerFailures = { agy: 'usage_limit' };
  fs.writeFileSync(path.join(request.out, 'meta.json'), JSON.stringify(meta));
  const quota = path.join(root, 'quota');
  await runOrchestratedAudit({ ...request, out: quota, resumeFrom: request.out, restartFailed: true }, { review: async () => assert.fail('Provider-wide limits also block restarts'), startSandbox });
  assert.equal(readReportJson(quota, 'workers.json').jobs[0].failure.reason, 'usage_limit');
});
