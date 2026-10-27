import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { verificationHealth } from './verification-health.mjs';

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-verification-'));
  fs.mkdirSync(path.join(root, 'harness'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const data = {
    'source-manifest.json': { digest: 'source', files: [{ path: 'package.json' }] },
    'harness/existing-tests.json': { sourceDigest: 'source', tests: [{ id: 'suite', description: 'Existing fixture suite' }] },
  };
  const evidence = { stdout: '# pass 2\n# fail 0\n# skipped 0\n', stderr: '' };
  const output = 'harness/existing-test-output-verification-0.json';
  data[output] = evidence;
  data['harness/existing-test-results-verification.json'] = [{ testId: 'suite', sourceDigest: 'source', evidenceFile: output, evidenceHash: crypto.createHash('sha256').update(JSON.stringify(evidence)).digest('hex'), exitCode: 0 }];
  fs.writeFileSync(path.join(root, 'harness/existing-test-results-verification.json'), 'fixture-index');
  const checks = [];
  for (const [tool, result] of [['gitleaks', '[]'], ['semgrep', '{"results":[],"errors":[]}'], ['osv-scanner', '{"results":[]}']]) {
    const evidenceFile = `harness/scanner-output-${tool}-0.json`;
    data[evidenceFile] = { code: 0, stdout: result };
    checks.push({ tool, state: 'passed', evidenceFile });
  }
  data['harness/scanner-output-node-deps-0.json'] = { code: 0, stdout: '{"nodeDeps":{"unresolved":0}}' };
  checks.push({ tool: 'cargo-audit', state: 'not_applicable' }, { tool: 'npm-audit', state: 'not_applicable' }, { tool: 'node-deps', state: 'passed', evidenceFile: 'harness/scanner-output-node-deps-0.json' });
  data['harness/scanner-results.json'] = { version: 1, checks };
  const read = name => { if (!(name in data)) throw Error('missing fixture'); return data[name]; };
  return { data, check: () => verificationHealth(root, read), output };
}

test('executed coverage requires tests, scanner evidence, and scope-correct applicability', t => {
  const f = fixture(t);
  assert.equal(f.check().state, 'passed');
  f.data['source-manifest.json'].files.push({ path: 'package-lock.json' });
  assert.match(f.check().gaps.join('\n'), /invalid not-applicable/);
});

test('failed tests, zero tests, skipped tests, stale source, and altered outputs remain gaps', t => {
  const f = fixture(t);
  const row = f.data['harness/existing-test-results-verification.json'][0];
  row.exitCode = 1;
  assert.equal(f.check().state, 'incomplete');
  row.exitCode = 0;
  for (const stdout of ['# pass 0\n# fail 0\n', '# pass 2\n# fail 0\n# skipped 1\n', 'no execution summary']) {
    f.data[f.output].stdout = stdout;
    row.evidenceHash = crypto.createHash('sha256').update(JSON.stringify(f.data[f.output])).digest('hex');
    assert.equal(f.check().state, 'incomplete');
  }
  row.sourceDigest = 'different';
  assert.equal(f.check().suites[0].state, 'not_run');
});

test('scanner error objects and missing output cannot support a recorded pass', t => {
  const f = fixture(t);
  f.data['harness/scanner-output-osv-scanner-0.json'] = { code: 127, stdout: '{"results":[]}' };
  assert.equal(f.check().state, 'incomplete');
  delete f.data['harness/scanner-results.json'];
  assert.match(f.check().gaps.join('\n'), /scanner evidence is missing/);
});

test('a passing attempt cannot conceal another failed attempt in the same run', t => {
  const f = fixture(t);
  const rows = f.data['harness/existing-test-results-verification.json'];
  rows.push({ ...rows[0], exitCode: 1 });
  assert.equal(f.check().state, 'incomplete');
  assert.equal(f.check().suites[0].state, 'failed_or_unverified');
});

test('missing program bytes are explained from the retained compiler output', t => {
  const f = fixture(t);
  const row = f.data['harness/existing-test-results-verification.json'][0];
  row.exitCode = 101;
  f.data[f.output].stderr = "error: couldn't read `/work/target/tmp/../deploy/ratpool_escrow.so`: No such file or directory (os error 2)";
  row.evidenceHash = crypto.createHash('sha256').update(JSON.stringify(f.data[f.output])).digest('hex');
  assert.match(f.check().gaps.join('\n'), /Missing program artifact deploy\/ratpool_escrow.so.*--test-artifacts/);
});

test('a Python tree requires the resolvability check and names the unpinned coverage gap', t => {
  const f = fixture(t);
  f.data['source-manifest.json'].files.push({ path: 'backend/requirements.txt' });
  assert.match(f.check().gaps.join('\n'), /python-deps: required scanner coverage is unavailable/);
  const checks = f.data['harness/scanner-results.json'].checks;
  checks.push({ tool: 'python-deps', state: 'blocked', detail: '3 unpinned requirement(s)' });
  assert.match(f.check().gaps.join('\n'), /python-deps:.*3 unpinned requirement/);
  checks.pop();
  f.data['harness/scanner-output-python-deps-0.json'] = { code: 0, stdout: '{"pythonDeps":{"unresolved":0}}' };
  checks.push({ tool: 'python-deps', state: 'passed', evidenceFile: 'harness/scanner-output-python-deps-0.json' });
  assert.equal(f.check().state, 'passed');
});

test('a failed suite gap carries its counts, dominant cause and capture truncation', t => {
  const f = fixture(t);
  const row = f.data['harness/existing-test-results-verification.json'][0];
  const rehash = () => { row.evidenceHash = crypto.createHash('sha256').update(JSON.stringify(f.data[f.output])).digest('hex'); };
  row.exitCode = 1;
  f.data[f.output] = { stdout: 'E   Failed: requires PG_BINDIR\nE   Failed: requires PG_BINDIR\n= 2 failed, 40 passed, 3 skipped, 308 errors in 9.00s =\n', stderr: '' };
  rehash();
  const gap = f.check().gaps.join('\n');
  assert.match(gap, /Exit 1; 40 passed, 310 failed or errored, 3 skipped\./);
  assert.match(gap, /Most common failure \(2x\): Failed: requires PG_BINDIR/);
  row.exitCode = 0;
  f.data[f.output] = { stdout: '# pass 2\n# fail 0\n# skipped 0\n', stderr: '', omittedBytes: 10 };
  rehash();
  assert.equal(f.check().state, 'incomplete');
  assert.match(f.check().gaps.join('\n'), /capture limit \(10 bytes omitted\)/);
});
