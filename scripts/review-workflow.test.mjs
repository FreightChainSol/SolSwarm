import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createSnapshot, disposeSnapshot } from './worker-isolation.mjs';
import { REVIEW_WORKFLOW, REVIEW_TOOLS, buildExistingTestCatalog, selectExistingTest } from './review-workflow.mjs';
import { callBridgeTool, toolDefinitions } from './docker-mcp-bridge.mjs';
import { permissionDecision } from './agent-session.mjs';
import { auditToolDecision } from './audit-tool-policy.mjs';
import { runOrchestratedAudit } from './docker-agent-orchestrator.mjs';

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-review-policy-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: { test: 'node --test existing.test.cjs', build: 'must never be offered' } }));
  fs.writeFileSync(path.join(root, 'existing.test.cjs'), '/* inert source only */');
  fs.writeFileSync(path.join(root, 'test.sh'), '#!/bin/sh\nexit 0\n');
  fs.writeFileSync(path.join(root, 'Cargo.toml'), '[package]\nname="fixture"\nversion="0.1.0"\n');
  const snapshot = createSnapshot(root);
  const catalog = buildExistingTestCatalog(snapshot.snapshot, snapshot.manifest);
  disposeSnapshot(snapshot);
  fs.mkdirSync(path.join(root, 'harness'));
  fs.writeFileSync(path.join(root, 'harness/existing-tests.json'), JSON.stringify(catalog));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, catalog };
}

test('the fixed test catalog binds existing manifests and reconstructs commands without caller arguments', t => {
  const f = fixture(t);
  assert.equal(f.catalog.workflow, REVIEW_WORKFLOW);
  assert.deepEqual(f.catalog.tests.map(entry => entry.kind).sort(), ['cargo', 'npm', 'shell']);
  const entry = f.catalog.tests.find(test => test.kind === 'npm');
  const selected = selectExistingTest({ ...f.catalog, tests: [{ ...entry, command: 'sh', args: ['-c', 'unapproved'], timeoutMs: 999999999 }] }, entry.id, f.catalog.sourceDigest);
  assert.equal(selected.command, 'npm');
  assert.deepEqual(selected.args, ['--offline', '--ignore-scripts', 'run', 'test']);
  assert.equal(selected.timeoutMs, 90000);
  for (const runner of ['cargo', 'shell']) {
    const row = f.catalog.tests.find(test => test.kind === runner);
    assert.equal(selectExistingTest(f.catalog, row.id).timeoutMs, 900000);
  }
  for (const patch of [{ cwd: '../outside' }, { kind: 'node' }, { id: 'test-' + 'b'.repeat(24) }, { files: [{ path: '/outside', sha256: 'a'.repeat(64) }] }]) {
    const changed = { ...entry, ...patch };
    assert.throws(() => selectExistingTest({ ...f.catalog, tests: [changed] }, changed.id, f.catalog.sourceDigest));
  }
  assert.throws(() => selectExistingTest(f.catalog, entry.id, 'b'.repeat(64)));
});

test('old execution and PoC routes fail through direct MCP, AGY hooks and ACP permissions', async t => {
  const f = fixture(t);
  const options = [{ kind: 'allow_once', optionId: 'allow' }, { kind: 'reject_once', optionId: 'reject' }];
  for (const name of ['run_container_check', 'write_poc', 'get_attack_plan', 'bash', 'node']) {
    assert.equal(REVIEW_TOOLS.has(name), false);
    assert.ok(!toolDefinitions().some(tool => tool.name === name));
    await assert.rejects(callBridgeTool({ reportDir: f.root, dockerBin: '/must/not/execute' }, name, { command: 'node', args: ['-e', 'unapproved'] }), /Tool unavailable/);
    assert.equal(auditToolDecision({ toolCall: { name: 'call_mcp_tool', args: { ServerName: 'audit_docker', ToolName: name } } }).decision, 'deny');
    assert.equal(permissionDecision({ sessionId: 'own', options, toolCall: { _meta: { is_mcp_tool_call: true }, rawInput: { server: 'audit_docker', tool: name } } }, 'own').outcome.optionId, 'reject');
  }
});

test('test invocation rejects injected arguments and unknown IDs before Docker access', async t => {
  const f = fixture(t);
  const ctx = { reportDir: f.root, dockerBin: '/must/not/execute', submissionIdentity: { sourceDigest: f.catalog.sourceDigest } };
  const id = f.catalog.tests[0].id;
  for (const args of [{ test_id: id, args: ['--eval', 'unapproved'] }, { test_id: id, cwd: '/outside' }, { test_id: id, content: 'new test' }, { test_id: 'test-' + '0'.repeat(24) }]) await assert.rejects(callBridgeTool(ctx, 'run_existing_tests', args));
  const inventory = JSON.parse(await callBridgeTool(ctx, 'list_existing_tests'));
  assert.equal(inventory.tests.length, 3);
  assert.ok(inventory.tests.every(entry => !('command' in entry) && !('args' in entry)));
});

test('review reports require analysis and validation and reject exploit payload fields', async t => {
  const f = fixture(t);
  const ctx = { reportDir: f.root, role: 'auditor', auditor: 'claude-s1-auth', surface: 'S1', submissionIdentity: { name: 'claude-s1-auth', agent: 'claude', role: 'auditor', workflow: REVIEW_WORKFLOW, surface: 'S1', model: 'fixture', sourceDigest: f.catalog.sourceDigest, assignmentDigest: 'a'.repeat(64) } };
  const finding = { title: 'Inert review evidence', surface: 'S1', severity: 'info', confidence: 'probable', location: ['package.json:1'], impact: 'Fixture only', preconditions: 'None', analysis: 'Source inspection only', validation: 'No execution evidence', fix: 'Document the boundary' };
  for (const patch of [{ attack: ['unapproved instructions'] }, { poc: 'unapproved code' }, { analysis: '' }, { validation: '' }]) await assert.rejects(callBridgeTool(ctx, 'submit_audit_report', { findings: [{ ...finding, ...patch }], verified_safe: [] }));
  await callBridgeTool(ctx, 'submit_audit_report', { findings: [finding], verified_safe: [{ control: 'Inert fixture', evidence: 'Inspected package.json:1 only', holds: true }] });
  const payload = JSON.parse(fs.readFileSync(path.join(f.root, 'auditors/claude-s1-auth.json')));
  assert.deepEqual(payload[0].attack, []);
  assert.equal(payload[0].poc, '');
  assert.equal(payload[0].analysis, finding.analysis);
});

test('legacy workflow sessions and deployed RPC requests are rejected before reviewer or Docker startup', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'review-workflow-resume-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, 'source'), prior = path.join(root, 'prior');
  fs.mkdirSync(source); fs.mkdirSync(prior);
  fs.writeFileSync(path.join(source, 'source.js'), 'export const inert = true;');
  const snapshot = createSnapshot(source);
  fs.writeFileSync(path.join(prior, 'source-manifest.json'), JSON.stringify(snapshot.manifest));
  disposeSnapshot(snapshot);
  fs.writeFileSync(path.join(prior, 'meta.json'), JSON.stringify({ surface: 's1', agents: ['codex'], models: { codex: 'fixture' } }));
  const request = { target: source, out: path.join(root, 'output'), surface: 's1', agents: ['codex'], models: { codex: 'fixture' }, resumeFrom: prior };
  const review = () => assert.fail('Rejected workflows must never launch a reviewer');
  await assert.rejects(runOrchestratedAudit(request, { review }), /Resume requires the same source digest/);
  await assert.rejects(runOrchestratedAudit({ ...request, rpc: 'https://example.invalid' }, { review }), /excludes deployed RPC/);
  await assert.rejects(runOrchestratedAudit({ ...request, resume: { conversationId: 'legacy' } }, { review }), /legacy adversarial-session/);
});

test('a Python project with tests gets a fixed, hash-bound pytest entry and no caller-controlled interpreter', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-review-python-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'backend/tests'), { recursive: true });
  fs.mkdirSync(path.join(root, 'tools'), { recursive: true });
  fs.writeFileSync(path.join(root, 'backend/requirements.txt'), 'fastapi==0.115.0\n');
  fs.writeFileSync(path.join(root, 'backend/tests/conftest.py'), '');
  fs.writeFileSync(path.join(root, 'backend/tests/test_a.py'), 'def test_a():\n    assert True\n');
  fs.writeFileSync(path.join(root, 'tools/test_orphan.py'), 'def test_b():\n    pass\n');
  const snapshot = createSnapshot(root);
  const catalog = buildExistingTestCatalog(snapshot.snapshot, snapshot.manifest);
  disposeSnapshot(snapshot);
  const rows = catalog.tests.filter(row => row.kind === 'pytest');
  assert.deepEqual(rows.map(row => row.cwd), ['backend']);
  assert.deepEqual(rows[0].files.map(file => file.path).sort(), ['backend/requirements.txt', 'backend/tests/conftest.py']);
  const selected = selectExistingTest({ ...catalog, tests: [{ ...rows[0], command: 'sh', args: ['-c', 'x'] }] }, rows[0].id, catalog.sourceDigest);
  assert.equal(selected.command, '/work/venv/bin/python');
  assert.deepEqual(selected.args, ['-m', 'pytest', '-p', 'no:cacheprovider', '-q', '--tb=line']);
  assert.equal(selected.timeoutMs, 900000);
});
