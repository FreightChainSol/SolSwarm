import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { callBridgeTool, parseBridgeArgs, renderMarkdownFromFindings } from './docker-mcp-bridge.mjs';
import { readCanonicalSubmission, deriveSubmission } from './audit-submission.mjs';
import { readReportJson } from './report-contract.mjs';

function fixture(t, role = 'auditor') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-commit-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'harness'));
  const identity = { name: role === 'auditor' ? 'agy-s3-logic' : 'crosscheck-agy', agent: 'agy', role, model: 'fixture-model', sourceDigest: 'a'.repeat(64), assignmentDigest: 'b'.repeat(64), ...(role === 'auditor' ? { surface: 'S3' } : {}) };
  const ctx = { reportDir: root, role, surface: 'S3', auditor: role === 'auditor' ? identity.name : '', agent: 'agy', container: '', submissionIdentity: identity };
  return { root, identity, ctx };
}
const report = () => ({ findings: [{ title: 'Inert evidence fixture', surface: 'S3', severity: 'low', confidence: 'probable', location: ['src/rules.rs:12'], impact: 'Fixture impact', preconditions: 'Fixture only', attack: ['Read source'], poc: '', fix: 'Require authorization' }], verified_safe: [], markdown_summary: 'Static fixture only; no actual security audit was performed.' });

test('one MCP commit is authoritative and repeated identical submissions are idempotent', async t => {
  const f = fixture(t);
  const input = report();
  await callBridgeTool(f.ctx, 'submit_audit_report', { report_json: JSON.stringify(input) });
  const first = readCanonicalSubmission(f.root, f.identity.name, f.identity);
  await callBridgeTool(f.ctx, 'submit_audit_report', { verified_safe: [], findings: input.findings, markdown_summary: input.markdown_summary });
  const second = readCanonicalSubmission(f.root, f.identity.name, f.identity);
  assert.equal(first.hash, second.hash);
  assert.equal(first.committedAt, second.committedAt);
  await assert.rejects(callBridgeTool(f.ctx, 'submit_audit_report', { findings: [], verified_safe: [] }), /already committed/);
  assert.equal(readReportJson(f.root, `auditors/${f.identity.name}.json`).length, 2);
});

test('canonical reports are bound to source, model, role and assignment', async t => {
  const f = fixture(t);
  await callBridgeTool(f.ctx, 'submit_audit_report', report());
  for (const patch of [{ sourceDigest: 'c'.repeat(64) }, { assignmentDigest: 'd'.repeat(64) }, { model: 'other-model' }, { role: 'crosscheck' }]) {
    assert.throws(() => readCanonicalSubmission(f.root, f.identity.name, { ...f.identity, ...patch }));
  }
  const file = path.join(f.root, 'submissions', `${f.identity.name}.json`);
  const receipt = JSON.parse(fs.readFileSync(file));
  receipt.report.payload[0].impact = 'Tampered payload';
  fs.writeFileSync(file, JSON.stringify(receipt));
  assert.throws(() => readCanonicalSubmission(f.root, f.identity.name, f.identity), /hash mismatch/);
});

test('derived JSON and markdown can be rebuilt from the committed report without model output', async t => {
  const f = fixture(t);
  await callBridgeTool(f.ctx, 'submit_audit_report', report());
  const receipt = readCanonicalSubmission(f.root, f.identity.name, f.identity);
  fs.rmSync(path.join(f.root, 'auditors'), { recursive: true });
  deriveSubmission(f.root, receipt, renderMarkdownFromFindings);
  assert.equal(readReportJson(f.root, `auditors/${f.identity.name}.json`)[0].title, 'Inert evidence fixture');
  assert.match(fs.readFileSync(path.join(f.root, 'auditors', `${f.identity.name}.md`), 'utf8'), /Findings \(1\)/);
});

test('bridge role cannot be crossed by calling an unadvertised submission tool', async t => {
  const f = fixture(t, 'crosscheck');
  await assert.rejects(callBridgeTool(f.ctx, 'submit_audit_report', report()), /bridge role/);
  const auditor = fixture(t);
  await assert.rejects(callBridgeTool(auditor.ctx, 'submit_crosscheck_report', { verdicts: [] }), /bridge role/);
});

test('identity file cannot point outside the report or silently change reviewer identity', t => {
  const f = fixture(t);
  const file = path.join(f.root, 'identity.json');
  fs.writeFileSync(file, JSON.stringify(f.identity));
  const flags = ['--report-dir', f.root, '--role', 'auditor', '--agent', 'agy', '--auditor', 'agy-s3-logic', '--surface', 'S3', '--identity-file', file];
  assert.deepEqual(parseBridgeArgs(flags).submissionIdentity, f.identity);
  assert.throws(() => parseBridgeArgs([...flags.slice(0, -1), '/tmp/outside-identity.json']));
  fs.writeFileSync(file, JSON.stringify({ ...f.identity, agent: 'grok' }));
  assert.throws(() => parseBridgeArgs(flags));
});
