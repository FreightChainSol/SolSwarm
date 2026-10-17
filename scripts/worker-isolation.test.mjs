import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ADAPTERS, LIMITS, hash, backendStatus, createSnapshot, disposeSnapshot, requireOwnedSnapshot, createJob, validateOutput } from './worker-isolation.mjs';
import { runtimeDigest, transition, recordBlockedRun } from './worker-supervisor.mjs';

const scripts = path.dirname(fileURLToPath(import.meta.url));
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-isolation-unit-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(path.join(root, 'sample.txt'), 'alpha\n');
  return root;
}
const jobFor = (snapshot, extra = {}) => createJob({ adapter: 'claude', model: 'requested-model', sourceDigest: snapshot.manifest.digest, runtimeDigest: runtimeDigest(), ...extra });

test('snapshots record explicit omissions without copying named credentials or links', (t) => {
  const source = fixture(t);
  for (const name of ['.env', '.env.example', '.npmrc', 'wallet-keypair.json', 'auth.json']) fs.writeFileSync(path.join(source, name), 'dummy fixture');
  fs.mkdirSync(path.join(source, 'secrets'));
  fs.writeFileSync(path.join(source, 'secrets', 'fixture.txt'), 'dummy fixture');
  fs.symlinkSync(path.join(source, 'sample.txt'), path.join(source, 'linked.txt'));
  fs.writeFileSync(path.join(source, 'image.png'), 'inert bytes');
  const snapshot = createSnapshot(source);
  t.after(() => disposeSnapshot(snapshot));
  assert.deepEqual(snapshot.manifest.files.map((f) => f.path), ['sample.txt']);
  assert.equal(snapshot.manifest.omissions.find((r) => r.path === 'linked.txt').reason, 'symlink');
  assert.equal(snapshot.manifest.secretFree, 'not_guaranteed');
  assert.equal(snapshot.manifest.digest, hash(JSON.stringify(snapshot.manifest.files)));
});

test('captured source uses fresh inodes and is unchanged by later checkout writes', (t) => {
  const source = fixture(t);
  const snapshot = createSnapshot(source);
  t.after(() => disposeSnapshot(snapshot));
  const copy = path.join(snapshot.snapshot, 'sample.txt');
  assert.notEqual(fs.statSync(copy).ino, fs.statSync(path.join(source, 'sample.txt')).ino);
  const digest = snapshot.manifest.digest;
  fs.writeFileSync(path.join(source, 'sample.txt'), 'beta\n');
  assert.equal(fs.readFileSync(copy, 'utf8'), 'alpha\n');
  assert.equal(snapshot.manifest.digest, digest);
  assert.equal(fs.statSync(copy).mode & 0o222, 0);
  assert.equal(fs.statSync(snapshot.snapshot).mode & 0o222, 0);
});

test('run output is excluded even through canonical path aliases', (t) => {
  const source = fixture(t);
  const out = path.join(source, 'report');
  fs.mkdirSync(out);
  fs.writeFileSync(path.join(out, 'meta.json'), '{}');
  const snapshot = createSnapshot(source, { exclude: [out] });
  t.after(() => disposeSnapshot(snapshot));
  assert.ok(!snapshot.manifest.files.some((f) => f.path.startsWith('report/')));
  assert.equal(snapshot.manifest.omissions.find((f) => f.path === 'report').reason, 'run_output');
});

test('snapshot file/count/entry budgets fail or disclose bounded omissions', (t) => {
  const source = fixture(t);
  const small = createSnapshot(source, { limits: { ...LIMITS, fileBytes: 2 } });
  assert.equal(small.manifest.omissions[0].reason, 'file_byte_limit');
  disposeSnapshot(small);
  assert.throws(() => createSnapshot(source, { limits: { ...LIMITS, files: 0 } }));
  assert.throws(() => createSnapshot(source, { limits: { ...LIMITS, entries: 0 } }));
  assert.throws(() => disposeSnapshot({ staging: source }), /unowned/);
});

test('all subscription adapters are explicitly blocked, not inferred from PATH', () => {
  for (const adapter of ADAPTERS) assert.deepEqual(backendStatus(adapter), { adapter, state: 'blocked', reason: 'subscription_bridge_unverified', credentialFree: false, toolsDisabled: false });
  assert.throws(() => backendStatus('unknown'));
});

test('only owned sealed capture handles can be presented to the runtime', (t) => {
  const source = fixture(t);
  const snapshot = createSnapshot(source);
  assert.equal(requireOwnedSnapshot(snapshot), snapshot.snapshot);
  assert.throws(() => requireOwnedSnapshot({ ...snapshot }));
  disposeSnapshot(snapshot);
  assert.throws(() => requireOwnedSnapshot(snapshot));
});

test('failed owned snapshot deletion can be retried safely', (t) => {
  const source = fixture(t);
  const snapshot = createSnapshot(source);
  const remove = fs.rmSync;
  try {
    fs.rmSync = (dir, options) => {
      if (dir === snapshot.staging) throw new Error('inert deletion-failure fixture');
      return remove(dir, options);
    };
    assert.throws(() => disposeSnapshot(snapshot));
  } finally { fs.rmSync = remove; }
  disposeSnapshot(snapshot);
  assert.equal(fs.existsSync(snapshot.staging), false);
});

test('fixed trusted bundles capture only selected immutable UTF-8 bytes', (t) => {
  const source = fixture(t);
  fs.writeFileSync(path.join(source, 'runtime.mjs'), '// inert trusted fixture\n');
  fs.writeFileSync(path.join(source, 'invalid.txt'), Buffer.from([0xff]));
  const snapshot = createSnapshot(source, { only: ['runtime.mjs'] });
  t.after(() => disposeSnapshot(snapshot));
  fs.writeFileSync(path.join(source, 'runtime.mjs'), '// changed live fixture\n');
  assert.deepEqual(snapshot.manifest.files.map((f) => f.path), ['runtime.mjs']);
  assert.equal(fs.readFileSync(path.join(snapshot.snapshot, 'runtime.mjs'), 'utf8'), '// inert trusted fixture\n');
  const full = createSnapshot(source);
  t.after(() => disposeSnapshot(full));
  assert.equal(full.manifest.omissions.find((f) => f.path === 'invalid.txt').reason, 'non_utf8_text');
});

test('cross-check collection uses the downstream evidence schema', (t) => {
  const source = fixture(t);
  const snapshot = createSnapshot(source);
  t.after(() => disposeSnapshot(snapshot));
  const out = path.join(source, 'out');
  fs.mkdirSync(out);
  const job = jobFor(snapshot, { phase: 'crosscheck', claims: [{ id: 'grok-s1-auth#0' }] });
  for (const extra of [{ reason: 'x'.repeat(20_001) }, { evidence: Array(101).fill('sample.txt:1') }, { severity: ['low'] }]) {
    fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify([{ id: 'grok-s1-auth#0', verdict: 'partial', reason: 'Inert fixture.', evidence: ['sample.txt:1'], ...extra }]));
    assert.throws(() => validateOutput(job, out));
  }
  fs.writeFileSync(path.join(out, 'report.json'), Buffer.from([0xff]));
  assert.throws(() => validateOutput(job, out));
});

test('jobs have independent identities and copied, digested cross-check assignments', (t) => {
  const source = fixture(t);
  const snapshot = createSnapshot(source);
  t.after(() => disposeSnapshot(snapshot));
  const first = jobFor(snapshot);
  const second = jobFor(snapshot);
  assert.notEqual(first.id, second.id);
  assert.deepEqual(first.expected, ['report.json', 'report.md']);
  const claims = [{ id: 'grok-s1-auth#0', title: 'Inert claim', location: ['sample.txt:1'] }];
  const cross = jobFor(snapshot, { phase: 'crosscheck', claims });
  claims[0].title = 'Changed after input capture';
  assert.equal(cross.claims[0].title, 'Inert claim');
  assert.equal(cross.assignmentDigest, hash(JSON.stringify(cross.claims)));
  assert.deepEqual(cross.expected, ['report.json']);
});

test('worker states cannot be silently revived from blocked or collected', (t) => {
  const source = fixture(t);
  const snapshot = createSnapshot(source);
  t.after(() => disposeSnapshot(snapshot));
  const job = jobFor(snapshot);
  transition(job, 'blocked', { reason: 'subscription_bridge_unverified' });
  assert.throws(() => transition(job, 'running'));
});

test('private collection rejects unexpected files, links and incomplete assignments', (t) => {
  const source = fixture(t);
  const snapshot = createSnapshot(source);
  t.after(() => disposeSnapshot(snapshot));
  const out = path.join(source, 'out');
  fs.mkdirSync(out);
  fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify([{ verified_safe: [] }]));
  fs.writeFileSync(path.join(out, 'report.md'), 'Inert fixture, not an audit.\n');
  const job = jobFor(snapshot);
  assert.equal(validateOutput(job, out).hashes['report.json'], hash(fs.readFileSync(path.join(out, 'report.json'))));
  fs.writeFileSync(path.join(out, 'extra.txt'), 'inert');
  assert.throws(() => validateOutput(job, out));
  fs.unlinkSync(path.join(out, 'extra.txt'));
  fs.unlinkSync(path.join(out, 'report.md'));
  fs.symlinkSync(path.join(source, 'sample.txt'), path.join(out, 'report.md'));
  assert.throws(() => validateOutput(job, out));
  fs.unlinkSync(path.join(out, 'report.md'));
  const cross = jobFor(snapshot, { phase: 'crosscheck', claims: [{ id: 'grok-s1-auth#0' }] });
  fs.writeFileSync(path.join(out, 'report.json'), '[]');
  assert.throws(() => validateOutput(cross, out));
});

test('blocked run records parent jobs and source digest without launching any worker', (t) => {
  const source = fixture(t);
  const out = path.join(source, 'report');
  const manifest = recordBlockedRun({ target: source, out, agents: ['claude', 'grok'], models: { claude: 'requested-claude', grok: 'requested-grok' }, surface: 's1', mode: 'local', source });
  assert.equal(manifest.jobs.length, 2);
  assert.ok(manifest.jobs.every((j) => j.state === 'blocked' && j.observedExitCode === null));
  const meta = JSON.parse(fs.readFileSync(path.join(out, 'meta.json')));
  assert.equal(meta.isolation.sourceDigest, manifest.sourceDigest);
  assert.equal(meta.isolation.liveTransport, 'blocked');
  assert.equal(fs.readdirSync(path.join(out, 'auditors')).length, 0);
  assert.throws(() => recordBlockedRun({ target: source, out, agents: ['claude'], models: { claude: 'requested' }, surface: 's1' }), /empty/);
});

test('job output names and models reject non-contract selectors', (t) => {
  const source = fixture(t);
  const snapshot = createSnapshot(source);
  t.after(() => disposeSnapshot(snapshot));
  assert.throws(() => jobFor(snapshot, { model: '--unexpected' }));
  assert.throws(() => jobFor(snapshot, { phase: 'command' }));
});

test('public run preflight blocks before host CLIs, scanners or Docker are invoked', (t) => {
  const source = fixture(t);
  const shims = path.join(source, 'bin');
  const marker = path.join(source, 'unexpected-tool.txt');
  fs.mkdirSync(shims);
  for (const name of ['claude', 'grok', 'agy', 'codex', 'docker', 'gitleaks', 'semgrep', 'osv-scanner']) {
    fs.writeFileSync(path.join(shims, name), `#!/bin/sh\nprintf 'unexpected invocation' > '${marker}'\nexit 1\n`, { mode: 0o755 });
  }
  const out = path.join(source, 'report');
  const run = spawnSync('bash', [path.join(scripts, 'orchestrate.sh'), '--blocked', '--target', source, '--out', out, '--surface', 's1', '--agents', 'claude,grok'], { encoding: 'utf8', timeout: 10_000, env: { ...process.env, PATH: `${shims}${path.delimiter}${process.env.PATH}` } });
  assert.equal(run.status, 2, run.stderr);
  assert.equal(fs.existsSync(marker), false);
  assert.match(run.stderr, /legacy multi-surface adapters are not integrated/);
  assert.match(run.stderr, /A ready Claude login does not enable audit run/);
  assert.match(run.stdout, /persistent ACP sessions/);
  const html = fs.readFileSync(path.join(out, 'report.html'), 'utf8');
  assert.match(html, /Live transport is blocked/);
  assert.match(html, /INCOMPLETE REVIEW/);
  assert.equal(fs.readdirSync(path.join(out, 'auditors')).length, 0);
});

test('plan-only selection preserves requested models without launching a backend', (t) => {
  const source = fixture(t);
  const run = spawnSync('bash', [path.join(scripts, 'orchestrate.sh'), '--target', source, '--plan', '--agents', 'codex', '--model-codex', 'requested-model'], { encoding: 'utf8', timeout: 5000 });
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /codex=requested-model/);
  assert.match(run.stdout, /persistent ACP sessions/);
  assert.equal(fs.readdirSync(source).length, 1);
});
