import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { REVIEW_IMAGE, createSnapshot, disposeSnapshot, createJob } from './worker-isolation.mjs';
import { runFixture, runtimeDigest, createRecordDirectory, disposeRecordDirectory } from './worker-supervisor.mjs';

const self = fileURLToPath(import.meta.url);
const source = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-docker-fixture-'));
  fs.writeFileSync(path.join(root, 'sample.txt'), 'alpha\n');
  return root;
};
const jobFor = (snapshot, extra = {}) => createJob({ adapter: 'claude', model: 'inert-fixture-not-a-model', sourceDigest: snapshot.manifest.digest, runtimeDigest: runtimeDigest(), ...extra });
function context(t) {
  const root = source();
  const snapshot = createSnapshot(root);
  t.after(() => { disposeSnapshot(snapshot); fs.rmSync(root, { recursive: true, force: true }); });
  return { root, snapshot };
}
function run(t, snapshot, job, options = {}) {
  const recordDir = createRecordDirectory();
  t.after(() => disposeRecordDirectory(recordDir));
  return runFixture(snapshot, job, { ...options, recordDir });
}
function removed(result) {
  assert.equal(result.ledger.cleanup.state, 'removed');
  if (result.ledger.recordPersistence === 'saved') {
    const saved = JSON.parse(fs.readFileSync(path.join(result.ledger.recordDirectory, 'ledger.json')));
    assert.equal(saved.cleanup.state, 'removed');
    assert.equal(saved.job.state, result.ledger.job.state);
  }
  for (const name of [result.ledger.resources.worker, result.ledger.resources.collector]) {
    assert.notEqual(spawnSync('docker', ['inspect', name], { stdio: 'ignore' }).status, 0);
  }
  assert.notEqual(spawnSync('docker', ['volume', 'inspect', result.ledger.resources.volume], { stdio: 'ignore' }).status, 0);
}

if (process.argv[2] === '--signal-fixture') {
  const root = source();
  const snapshot = createSnapshot(root);
  try {
    const result = await runFixture(snapshot, jobFor(snapshot), { fixture: 'wait', recordDir: process.argv[3], onStarted: () => process.stdout.write('READY\n') });
    process.stdout.write(`${JSON.stringify(result.ledger)}\n`);
  } finally {
    disposeSnapshot(snapshot);
    fs.rmSync(root, { recursive: true, force: true });
  }
} else {
  // Explicit command only: no auto-pull and no "skip means pass" when unavailable.
  assert.equal(spawnSync('docker', ['info', '--format', '{{.ServerVersion}}'], { stdio: 'ignore', timeout: 10_000 }).status, 0, 'Docker must be available for this explicit isolation suite');
  assert.equal(spawnSync('docker', ['image', 'inspect', REVIEW_IMAGE], { stdio: 'ignore', timeout: 10_000 }).status, 0, 'preprovisioned immutable Node image must be cached');

  test('credential-free worker cannot mutate source or see parent/peer controls', async (t) => {
    const { root, snapshot } = context(t);
    fs.writeFileSync(path.join(root, 'sample.txt'), 'changed live checkout\n');
    const result = await run(t, snapshot, jobFor(snapshot));
    assert.equal(result.ledger.job.state, 'collected', JSON.stringify(result.ledger));
    const json = JSON.parse(result.artifacts.files['report.json']);
    const checks = JSON.parse(json[0].verified_safe[0].how_attacked);
    assert.equal(checks.sourceText, 'alpha\n');
    for (const [key, value] of Object.entries(checks)) if (key !== 'sourceText') assert.equal(value, true, key);
    const spec = result.ledger.boundary;
    assert.equal(spec.network, 'none');
    assert.equal(spec.user, '10001:10001');
    assert.equal(spec.readOnly, true);
    assert.ok(spec.capDrop.includes('ALL'));
    assert.ok(spec.securityOpt.some((s) => s.startsWith('no-new-privileges')));
    assert.ok(spec.mounts.filter((m) => m.type === 'bind').every((m) => m.readOnly));
    assert.ok(!spec.mounts.some((m) => /parent|peer|docker\.sock/.test(m.destination)));
    assert.ok(!spec.environmentKeys.includes('OPENAI_API_KEY'));
    removed(result);
  });

  test('two independent jobs have distinct private outboxes and collection hashes', async (t) => {
    const { snapshot } = context(t);
    const [a, b] = await Promise.all([run(t, snapshot, jobFor(snapshot)), run(t, snapshot, jobFor(snapshot, { adapter: 'grok' }))]);
    assert.equal(a.ledger.job.state, 'collected', JSON.stringify(a.ledger));
    assert.equal(b.ledger.job.state, 'collected', JSON.stringify(b.ledger));
    assert.notEqual(a.ledger.resources.volume, b.ledger.resources.volume);
    assert.notEqual(a.ledger.resources.worker, b.ledger.resources.worker);
    assert.notEqual(a.ledger.job.id, b.ledger.job.id);
    assert.equal(Object.keys(a.artifacts.hashes).length, 2);
    removed(a);
    removed(b);
  });

  test('fresh cross-check job receives only its frozen assignment contract', async (t) => {
    const { snapshot } = context(t);
    const job = jobFor(snapshot, { phase: 'crosscheck', claims: [{ id: 'grok-s1-auth#0', title: 'Inert claim', location: ['sample.txt:1'] }] });
    const result = await run(t, snapshot, job);
    assert.equal(job.state, 'collected', JSON.stringify(result.ledger));
    assert.deepEqual(Object.keys(result.artifacts.files), ['report.json']);
    assert.equal(JSON.parse(result.artifacts.files['report.json'])[0].id, 'grok-s1-auth#0');
    removed(result);
  });

  test('malformed, extra and oversized private outputs are rejected', async (t) => {
    const { snapshot } = context(t);
    for (const fixture of ['malformed', 'extra', 'oversized']) {
      const result = await run(t, snapshot, jobFor(snapshot), { fixture });
      assert.equal(result.ledger.job.state, 'rejected_output', `${fixture}: ${JSON.stringify(result.ledger)}`);
      assert.equal(result.artifacts, undefined);
      removed(result);
    }
  });

  test('worker deadline kills and reaps the container before cleanup', async (t) => {
    const { snapshot } = context(t);
    const result = await run(t, snapshot, jobFor(snapshot), { fixture: 'wait', deadlineMs: 200 });
    assert.equal(result.ledger.job.state, 'timed_out');
    removed(result);
  });

  test('cancellation stops the whole worker and removes private resources', async (t) => {
    const { snapshot } = context(t);
    const controller = new AbortController();
    const result = await run(t, snapshot, jobFor(snapshot), { fixture: 'wait', signal: controller.signal, onStarted: () => controller.abort() });
    assert.equal(result.ledger.job.state, 'cancelled');
    removed(result);
  });

  test('unavailable immutable runtime fails without any host adapter fallback', async (t) => {
    const { snapshot } = context(t);
    const result = await run(t, snapshot, jobFor(snapshot), { image: `sha256:${'0'.repeat(64)}` });
    assert.equal(result.ledger.job.state, 'failed');
    assert.equal(result.ledger.job.reason, 'isolation_runtime_unavailable');
    removed(result);
  });

  test('parent journal failure cannot prevent owned Docker cleanup', async (t) => {
    const { snapshot } = context(t);
    const recordDir = createRecordDirectory();
    t.after(() => disposeRecordDirectory(recordDir));
    const controller = new AbortController();
    const result = await runFixture(snapshot, jobFor(snapshot), {
      fixture: 'wait', recordDir, signal: controller.signal,
      onStarted: () => {
        fs.unlinkSync(path.join(recordDir, 'ledger.json'));
        fs.mkdirSync(path.join(recordDir, 'ledger.json'));
        controller.abort();
      },
    });
    assert.equal(result.ledger.job.state, 'cancelled');
    assert.equal(result.ledger.recordPersistence, 'failed');
    assert.equal(result.ledger.runStatus, 'incomplete');
    assert.equal(result.artifacts, undefined);
    removed(result);
  });

  test('SIGTERM reaches the parent supervisor and still reaps owned resources', async (t) => {
    const recordDir = createRecordDirectory();
    t.after(() => disposeRecordDirectory(recordDir));
    const result = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [self, '--signal-fixture', recordDir], { stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      let signalled = false;
      const timeout = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('signal fixture deadline exceeded')); }, 30_000);
      child.stdout.on('data', (chunk) => {
        stdout += chunk;
        if (!signalled && stdout.includes('READY\n')) { signalled = true; child.kill('SIGTERM'); }
      });
      child.stderr.on('data', (chunk) => { stderr += chunk; });
      child.on('error', reject);
      child.on('close', (code) => {
        clearTimeout(timeout);
        try { resolve({ code, ledger: JSON.parse(stdout.split('\n').find((line) => line.startsWith('{')) || '{}'), stderr }); } catch (err) { reject(err); }
      });
    });
    assert.equal(result.code, 130, result.stderr);
    assert.equal(result.ledger.job.state, 'cancelled');
    removed({ ledger: result.ledger });
  });
}
