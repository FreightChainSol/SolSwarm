import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { parseStaticReview, staticCliReview } from './static-cli-review.mjs';
import { connectorFixture } from './connector-fixtures.mjs';
import { createTerminalRelay } from './terminal-relay.mjs';
import { connectTerminal, parseConnectorArgs } from './terminal-model-connector.mjs';
import { ConnectorError } from './model-cli-claude.mjs';

const optionsFor = (f) => ({ repo: f.root, out: path.join(f.root, 'review'), files: ['src/label.mjs'], provider: 'claude', model: 'fixture-model' });
function parentFor(f, onReadyHook = () => {}) {
  return async (options, { signal, onReady }) => {
    fs.mkdirSync(options.out, { mode: 0o700 });
    const relay = await createTerminalRelay(f.request, { signal });
    try {
      relay.activate(f.request);
      onReady({ socketPath: relay.socketPath });
      onReadyHook();
      await relay.completion;
    } finally { await relay.close(); f.cleaned = true; }
  };
}
test('static review parsing rejects remote acquisition, extra flags and unverified providers', () => {
  const args = ['--repo', '/source', '--out', '/output', '--file', 'sample.mjs', '--provider', 'claude', '--model', 'requested'];
  assert.equal(parseStaticReview(args).model, 'requested');
  for (const provider of ['codex', 'grok', 'agy', 'gemini', 'ollama', 'unknown']) {
    assert.throws(() => parseStaticReview([...args.slice(0, 7), provider, ...args.slice(8)]), /provider_tool_free_mode_unverified/);
  }
  for (const extra of [['--github', 'owner/repo'], ['--command', 'sh'], ['--provider', 'claude'], ['--file', '../outside']]) assert.throws(() => parseStaticReview([...args, ...extra]));
  assert.throws(() => parseStaticReview([...args, '--model']));
  assert.deepEqual(parseConnectorArgs(['check', '--all']), { operation: 'check', all: true });
  for (const bad of [['connect', '--all'], ['check', '--all', '--provider', 'claude'], ['check', '--all', '--all'], ['check', '--provider', 'unknown']]) assert.throws(() => parseConnectorArgs(bad));
});
test('unsupported providers and cancellation fail before preflight or local source access', async (t) => {
  const f = connectorFixture(t);
  const dependencies = { adapter: { withSession: () => assert.fail('preflight must not run') }, runLocal: () => assert.fail('source must not be accessed') };
  for (const provider of ['codex', 'grok', 'agy', 'gemini', 'ollama']) await assert.rejects(staticCliReview({ ...optionsFor(f), provider }, dependencies), /provider_tool_free_mode_unverified/);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(staticCliReview(optionsFor(f), { ...dependencies, signal: controller.signal }), /connector_cancelled/);
  assert.equal(fs.existsSync(optionsFor(f).out), false);
});
test('failed preflight creates no source job or output directory', async (t) => {
  const f = connectorFixture(t, { noAuth: true });
  await assert.rejects(staticCliReview(optionsFor(f), { adapter: f.adapter, runLocal: () => assert.fail('source must not be accessed') }), /subscription_login_required/);
  assert.equal(fs.existsSync(optionsFor(f).out), false);
  assert.ok(!fs.readFileSync(f.log, 'utf8').includes('--print'));
});
test('automatic review uses one preflighted session and publishes separate connector provenance', async (t) => {
  const f = connectorFixture(t, { requiredUser: 'fixture-operator' });
  const result = await staticCliReview(optionsFor(f), { adapter: f.adapter, runLocal: parentFor(f) });
  assert.equal(result.state, 'collected');
  assert.equal(result.cliReportedModel, 'fixture-model-not-live');
  assert.equal(result.requestedModel, 'fixture-model');
  assert.equal(result.modelIdentity, 'unverified');
  assert.equal(result.toolsDisabled, 'unverified');
  assert.equal(result.executionEvidence, 'not_collected');
  assert.equal(f.cleaned, true);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(optionsFor(f).out, 'connector-state.json'))), result);
  const calls = fs.readFileSync(f.log, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(calls.length, 4);
  assert.equal(calls.filter((c) => c.args.includes('--version')).length, 1);
  assert.equal(fs.existsSync(calls[0].cwd), false);
});
test('tool-bearing and malformed CLI results abort the parent and record incomplete status', async (t) => {
  for (const fixture of [{ tools: ['Read'] }, { toolCall: true }, { large: true }, { telemetry: { estimated_tokens: -1 } }]) {
    const f = connectorFixture(t, fixture);
    await assert.rejects(staticCliReview(optionsFor(f), { adapter: f.adapter, runLocal: parentFor(f) }), /cli_tools_not_empty|cli_tool_or_content_rejected|cli_output_limit|cli_telemetry_rejected/);
    assert.equal(f.cleaned, true);
    const status = JSON.parse(fs.readFileSync(path.join(optionsFor(f).out, 'connector-state.json')));
    assert.equal(status.state, 'blocked_or_incomplete');
    if (fixture.telemetry) assert.deepEqual(status.event, { type: 'system', subtype: 'thinking_tokens', index: 2 });
  }
});
test('external cancellation reaps the CLI and awaits parent cleanup', async (t) => {
  const f = connectorFixture(t, { hang: true });
  const controller = new AbortController();
  await assert.rejects(staticCliReview(optionsFor(f), { adapter: f.adapter, signal: controller.signal, runLocal: parentFor(f, () => setTimeout(() => controller.abort(), 200)) }), /connector_cancelled/);
  assert.equal(f.cleaned, true);
  const calls = fs.readFileSync(f.log, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(fs.existsSync(calls[0].cwd), false);
});
test('failed submission cancels the parent instead of waiting for its deadline', async (t) => {
  const f = connectorFixture(t);
  const connect = (options, dependencies) => connectTerminal(options, { ...dependencies, call: async (_socket, message) => {
    if (message.method === 'review.claim') return { request: f.request, claimId: 'fixture-claim' };
    if (message.method === 'review.status') return { state: 'claimed' };
    throw new ConnectorError('submission_outcome_unknown');
  } });
  await assert.rejects(staticCliReview(optionsFor(f), { adapter: f.adapter, runLocal: parentFor(f), connect }), /submission_outcome_unknown/);
  assert.equal(f.cleaned, true);
});
test('connector job-loss cancellation reaches the reused CLI session and parent', async (t) => {
  const f = connectorFixture(t, { hang: true });
  const lost = new AbortController();
  const connect = async (_options, { adapter }) => adapter.withSession(async (session) => {
    const timer = setTimeout(() => lost.abort(), 200);
    try { await session.review(f.request, 'fixture-model'); } finally { clearTimeout(timer); }
  }, { signal: lost.signal });
  await assert.rejects(staticCliReview(optionsFor(f), { adapter: f.adapter, runLocal: parentFor(f), connect }), /connector_cancelled/);
  assert.equal(f.cleaned, true);
  const calls = fs.readFileSync(f.log, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(fs.existsSync(calls[0].cwd), false);
});
test('parent failure cancels a running connector before releasing its session', async (t) => {
  const f = connectorFixture(t, { hang: true });
  const runLocal = async (options, { onReady }) => {
    fs.mkdirSync(options.out, { mode: 0o700 });
    onReady({ socketPath: '/unused' });
    await new Promise((resolve) => setTimeout(resolve, 100));
    throw new Error('inert parent failure');
  };
  let cancelled = false;
  const connect = async (_options, { signal }) => new Promise((_resolve, reject) => {
    signal.addEventListener('abort', () => { cancelled = true; reject(new ConnectorError('connector_cancelled')); }, { once: true });
  });
  await assert.rejects(staticCliReview(optionsFor(f), { adapter: f.adapter, runLocal, connect }), /connector_cancelled/);
  assert.equal(cancelled, true);
});
