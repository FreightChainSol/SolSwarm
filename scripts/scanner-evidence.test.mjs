import assert from 'node:assert/strict';
import test from 'node:test';
import { dominantTestFailure, scannerEvidence, testCounts } from './scanner-evidence.mjs';

test('scanner failures, error envelopes and malformed output cannot become clean scans', () => {
  for (const code of [127, 124, 2]) assert.equal(scannerEvidence('osv-scanner', { code, stdout: '{"results":[]}' }).state, 'failed');
  for (const tool of ['semgrep', 'osv-scanner', 'cargo-audit', 'npm-audit', 'gitleaks']) {
    for (const stdout of ['', '{"error":"unavailable"}', '{}', 'null']) assert.equal(scannerEvidence(tool, { code: 0, stdout }).state, 'failed');
  }
  assert.equal(scannerEvidence('semgrep', { code: 0, stdout: '{"results":[],"errors":[{"type":"ParseError"}]}' }).state, 'failed');
  assert.equal(scannerEvidence('semgrep', { code: 0, stdout: '{"results":[{}],"errors":[{"level":"warn","type":"Syntax error"},{"level":"error","type":"Rule parse error"}]}' }).state, 'failed');
  assert.deepEqual(scannerEvidence('semgrep', { code: 0, stdout: '{"results":[{},{}],"errors":[{"level":"warn","type":"PartialParsing"}]}' }), { tool: 'semgrep', exitCode: 0, state: 'findings', findings: 2, parseWarnings: 1 });
  assert.equal(scannerEvidence('osv-scanner', { code: 1, stdout: '{"results":[]}' }).state, 'failed');
  assert.equal(scannerEvidence('osv-scanner', { code: 0, stdout: '{"results":[]}' }).state, 'passed');
  assert.equal(scannerEvidence('gitleaks', { code: 0, stdout: '[{"RuleID":"fixture"}]' }).state, 'findings');
  assert.equal(scannerEvidence('python-deps', { code: 0, stdout: '{"pythonDeps":{"unresolved":0}}' }).state, 'passed');
  assert.equal(scannerEvidence('python-deps', { code: 0, stdout: '{"pythonDeps":{"unresolved":3}}' }).state, 'failed');
});

test('execution summaries distinguish nonzero tests, failures, skips and absent evidence', () => {
  assert.deepEqual(testCounts('test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\ntest result: ok. 0 passed; 0 failed; 0 ignored'), { passed: 21, failed: 0, skipped: 0 });
  assert.deepEqual(testCounts('# pass 3\n# fail 1\n# skipped 2\n# todo 1\n'), { passed: 3, failed: 1, skipped: 3 });
  assert.deepEqual(testCounts('...\n== 3 failed, 120 passed, 2 skipped, 1 error in 4.21s =='), { passed: 120, failed: 4, skipped: 2 });
  assert.deepEqual(testCounts('........\n8 passed in 0.31s'), { passed: 8, failed: 0, skipped: 0 });
  assert.equal(testCounts('command completed successfully'), null);
  assert.deepEqual(testCounts('test result: ok. 0 passed; 0 failed; 0 ignored'), { passed: 0, failed: 0, skipped: 0 });
});

test('a shared pytest failure line names the dominant cause', () => {
  const stdout = '_ ERROR at setup of test_a _\nE   Failed: Real PostgreSQL verification requires PG_BINDIR server binaries\n_ ERROR at setup of test_b _\nE   Failed: Real PostgreSQL verification requires PG_BINDIR server binaries\nE   AssertionError: one-off\n';
  assert.deepEqual(dominantTestFailure(stdout), { message: 'Failed: Real PostgreSQL verification requires PG_BINDIR server binaries', count: 2 });
  assert.equal(dominantTestFailure('E   AssertionError: one-off\n'), null);
  assert.equal(dominantTestFailure('8 passed in 0.31s'), null);
});
