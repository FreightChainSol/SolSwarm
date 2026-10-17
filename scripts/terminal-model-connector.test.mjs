import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { brokerEnvironment, parseClaudeReview, ConnectorError } from './model-cli-claude.mjs';
import { connectTerminal, parseConnectorArgs } from './terminal-model-connector.mjs';
import { connectorFixture } from './connector-fixtures.mjs';

test('broker environment never forwards API keys, token overrides, routing or runtime injections', () => {
  const env = brokerEnvironment({ HOME: '/operator', PATH: '/trusted/bin', ANTHROPIC_API_KEY: 'dummy', CLAUDE_CODE_OAUTH_TOKEN: 'dummy', NODE_OPTIONS: '--invalid', BASH_ENV: '/invalid', ANTHROPIC_BASE_URL: 'https://invalid.test', HTTPS_PROXY: 'https://invalid.test', SSH_AUTH_SOCK: '/invalid' });
  assert.deepEqual(env, { HOME: '/operator', PATH: '/trusted/bin' });
});

test('numeric thinking-token telemetry is accepted without changing review evidence', (t) => {
  const f = connectorFixture(t);
  const init = { type: 'system', subtype: 'init', tools: [], mcp_servers: [], session_id: 'fixture-session' };
  const result = { type: 'result', subtype: 'success', is_error: false, result: '{"summary":"inert","notes":[]}' };
  const expected = parseClaudeReview([init, result].map(JSON.stringify).join('\n'), f.request);
  for (const value of [0, 8, 8.5, 1_000_000_000]) {
    const telemetry = { type: 'system', subtype: 'thinking_tokens', estimated_tokens: value, estimated_tokens_delta: value, session_id: 'fixture-session', uuid: 'fixture-event' };
    assert.deepEqual(parseClaudeReview([init, telemetry, result].map(JSON.stringify).join('\n'), f.request), expected);
  }
});

test('thinking-token telemetry rejects invalid fields, counters and session metadata', (t) => {
  const f = connectorFixture(t);
  const init = { type: 'system', subtype: 'init', tools: [], mcp_servers: [], session_id: 'fixture-session' };
  const telemetry = { type: 'system', subtype: 'thinking_tokens', estimated_tokens: 8, estimated_tokens_delta: 8, session_id: 'fixture-session', uuid: 'fixture-event' };
  const invalid = [
    { estimated_tokens: -1 }, { estimated_tokens: '8' }, { estimated_tokens: null },
    { estimated_tokens: 1_000_000_001 }, { estimated_tokens: Infinity }, { estimated_tokens: undefined },
    { estimated_tokens_delta: -1 }, { estimated_tokens_delta: '8' }, { estimated_tokens_delta: NaN },
    { session_id: 'other-session' }, { session_id: '' }, { uuid: '\u001bunsafe' },
    { uuid: 'x'.repeat(129) }, { uuid: undefined }, { command: 'not telemetry' }, { message: 'not telemetry' },
  ];
  for (const extra of invalid) assert.throws(() => parseClaudeReview([init, { ...telemetry, ...extra }].map(JSON.stringify).join('\n'), f.request), /cli_telemetry_rejected/);
});

test('telemetry cannot precede initialization, follow the result or hide execution events', (t) => {
  const f = connectorFixture(t);
  const init = { type: 'system', subtype: 'init', tools: [], mcp_servers: [] };
  const telemetry = { type: 'system', subtype: 'thinking_tokens', estimated_tokens: 8, estimated_tokens_delta: 8, session_id: 'fixture-session', uuid: 'fixture-event' };
  const result = { type: 'result', subtype: 'success', is_error: false, result: '{"summary":"inert","notes":[]}' };
  const parse = (events) => parseClaudeReview(events.map(JSON.stringify).join('\n'), f.request);
  assert.throws(() => parse([telemetry, init, result]), /cli_telemetry_rejected/);
  assert.throws(() => parse([init, result, telemetry]), /cli_event_after_result/);
  for (const event of [{ type: 'control_request' }, { type: 'system', subtype: 'hook_started' }, { type: 'system', subtype: 'unknown' }, { type: 'tool_progress' }]) {
    assert.throws(() => parse([init, telemetry, event, result]), /cli_execution_event_rejected/);
  }
  assert.throws(() => parse([{ ...init, tools: ['Read'] }, telemetry, result]), /cli_tools_not_empty/);
});

test('rejection diagnostics expose only fixed event labels and an index, never payloads', (t) => {
  const f = connectorFixture(t);
  const event = { type: 'system', subtype: 'hook_started', message: 'private-fixture-text', session_id: 'private-fixture-id' };
  assert.throws(() => parseClaudeReview(JSON.stringify(event), f.request), (err) => {
    assert.deepEqual(err.event, { type: 'system', subtype: 'hook_started', index: 1 });
    assert.ok(!JSON.stringify(err).includes('private-fixture'));
    return err.code === 'cli_execution_event_rejected';
  });
  assert.throws(() => parseClaudeReview(JSON.stringify({ type: 'private-fixture-type', subtype: 'private-fixture-subtype' }), f.request), (err) => {
    assert.deepEqual(err.event, { type: 'unknown', subtype: 'unknown', index: 1 });
    return true;
  });
});

test('subscription readiness preserves USER without claiming a job or running inference', async (t) => {
  const f = connectorFixture(t, { requiredUser: 'fixture-operator' });
  const response = await connectTerminal({ operation: 'check', provider: 'claude' }, {
    adapter: f.adapter, call: async () => assert.fail('readiness must not contact the relay'),
  });
  assert.equal(response.state, 'ready');
  assert.equal(response.authMethod, 'claude.ai');
  const calls = fs.readFileSync(f.log, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(calls.length, 3);
  assert.ok(calls.every((c) => c.environmentKeys.includes('USER')));
  assert.ok(!calls.some((c) => c.args.includes('--print')));
  assert.ok(calls.every((c) => !c.environmentKeys.some((key) => ['ANTHROPIC_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN', 'NODE_OPTIONS', 'HTTPS_PROXY'].includes(key))));
});

test('inference deadline terminates and cleans up a stalled fake CLI', async (t) => {
  const f = connectorFixture(t, { hang: true, inferenceTimeoutMs: 100 });
  await assert.rejects(f.adapter.withSession((session) => session.review(f.request, 'requested')), /connector_deadline/);
  const calls = fs.readFileSync(f.log, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(fs.existsSync(calls[0].cwd), false);
});

test('malformed requested models fail before preflight or claim', async () => {
  let touched = false;
  await assert.rejects(connectTerminal({ operation: 'connect', provider: 'claude', socket: '/unused', model: '--unexpected' }, { adapter: { withSession: () => { touched = true; } } }), /connector_usage/);
  assert.equal(touched, false);
});

test('cancellation after inference prevents result submission', async (t) => {
  const f = connectorFixture(t);
  const controller = new AbortController();
  let submitted = false;
  const adapter = { withSession: (callback) => callback({
    review: async () => { controller.abort(); return { review: { summary: 'inert', notes: [] }, cliReportedModel: 'unverified' }; },
  }) };
  await assert.rejects(connectTerminal({ operation: 'connect', provider: 'claude', socket: '/unused', model: 'requested' }, {
    adapter, signal: controller.signal, call: async (_socket, message) => {
      if (message.method === 'review.claim') return { request: f.request, claimId: 'fake-claim' };
      submitted = true;
    },
  }), /connector_cancelled/);
  assert.equal(submitted, false);
});

test('public connector accepts fixed options only and refuses unverified providers', () => {
  for (const provider of ['codex', 'grok', 'agy']) assert.throws(() => parseConnectorArgs(['connect', '--provider', provider, '--model', 'requested', '--socket', '/socket']), /provider_tool_free_mode_unverified/);
  for (const flag of ['--command', '--args', '--url', '--env', '--executable']) assert.throws(() => parseConnectorArgs(['connect', flag, 'not-an-operation']));
  assert.deepEqual(parseConnectorArgs(['check', '--provider', 'claude']), { operation: 'check', provider: 'claude' });
});

test('fake subscription adapter uses a private neutral cwd and fixed tool-free flags', async (t) => {
  const f = connectorFixture(t);
  let cwd;
  const response = await f.adapter.withSession(async (session) => {
    const answer = await session.review(f.request, 'requested-model');
    const calls = fs.readFileSync(f.log, 'utf8').trim().split('\n').map(JSON.parse);
    cwd = calls[0].cwd;
    assert.ok(calls.every((c) => c.cwd === cwd && c.cwd !== f.root));
    assert.ok(calls.every((c) => !c.environmentKeys.some((key) => ['ANTHROPIC_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN', 'NODE_OPTIONS', 'HTTPS_PROXY'].includes(key))));
    const invoke = calls.find((c) => c.args.includes('--print'));
    assert.equal(invoke.args[invoke.args.indexOf('--model') + 1], 'requested-model');
    assert.ok(!invoke.args.includes('--bare'));
    assert.ok(!invoke.args.includes('--dangerously-skip-permissions'));
    return answer;
  });
  assert.equal(response.cliReportedModel, 'fixture-model-not-live');
  assert.match(response.review.summary, /FAKE CLI/);
  assert.equal(fs.existsSync(cwd), false);
});

test('missing or API-based authentication fails before a relay claim', async (t) => {
  for (const opts of [{ noAuth: true }, { authMethod: 'api_key' }, { authMethod: 'third_party' }]) {
    const f = connectorFixture(t, opts);
    let claimed = false;
    await assert.rejects(connectTerminal({ operation: 'connect', provider: 'claude', socket: '/unused', model: 'requested' }, { adapter: f.adapter, call: async () => { claimed = true; } }), /subscription_login_required/);
    assert.equal(claimed, false);
    assert.ok(!fs.readFileSync(f.log, 'utf8').includes('--print'));
  }
});

test('unknown CLI versions fail before inference or claiming', async (t) => {
  const f = connectorFixture(t, { version: '99.0.0' });
  await assert.rejects(f.adapter.withSession(() => assert.fail('session must not be admitted')), /cli_version_unverified/);
  assert.equal(fs.readFileSync(f.log, 'utf8').trim().split('\n').length, 1);
});

test('advertised tools or tool-use messages are rejected without submission', async (t) => {
  for (const opts of [{ tools: ['Read'] }, { toolCall: true }]) {
    const f = connectorFixture(t, opts);
    let submitted = false;
    await assert.rejects(connectTerminal({ operation: 'connect', provider: 'claude', socket: '/unused', model: 'requested' }, {
      adapter: f.adapter,
      call: async (_socket, message) => {
        if (message.method === 'review.claim') return { request: f.request, claimId: 'fake-claim' };
        if (message.method === 'review.status') return { state: 'claimed' };
        submitted = true;
      },
    }), /cli_tools_not_empty|cli_tool_or_content_rejected/);
    assert.equal(submitted, false);
  }
});

test('automatic claim/inference/submit preserves all original binding fields', async (t) => {
  const f = connectorFixture(t);
  const messages = [];
  const response = await connectTerminal({ operation: 'connect', provider: 'claude', socket: '/unused', model: 'requested' }, {
    adapter: f.adapter,
    call: async (_socket, message) => {
      messages.push(message);
      if (message.method === 'review.claim') return { request: f.request, claimId: 'fake-claim' };
      if (message.method === 'review.status') return { state: 'claimed' };
      return { state: 'submitted' };
    },
  });
  assert.equal(response.state, 'submitted');
  const submit = messages.find((m) => m.method === 'review.submit');
  for (const key of ['requestId', 'jobId', 'sourceDigest']) assert.equal(submit[key], f.request[key]);
  assert.equal(submit.claimId, 'fake-claim');
  assert.equal(response.modelIdentity, 'unverified');
  assert.equal(response.executionEvidence, 'not_collected');
});

test('CLI cancellation reaps its process group and removes neutral staging', async (t) => {
  const f = connectorFixture(t, { hang: true });
  const controller = new AbortController();
  await assert.rejects(f.adapter.withSession(async (session) => {
    const pending = session.review(f.request, 'requested');
    setTimeout(() => controller.abort(), 100);
    return pending;
  }, { signal: controller.signal }), /connector_cancelled/);
  const calls = fs.readFileSync(f.log, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(fs.existsSync(calls[0].cwd), false);
});

test('oversized CLI output is refused', async (t) => {
  const f = connectorFixture(t, { large: true });
  await assert.rejects(f.adapter.withSession((session) => session.review(f.request, 'requested')), /cli_output_limit/);
});

test('machine-readable parsing rejects prose, unknown events and invalid citations', (t) => {
  const f = connectorFixture(t);
  const init = { type: 'system', subtype: 'init', tools: [], mcp_servers: [] };
  assert.throws(() => parseClaudeReview('not json', f.request), /cli_output_not_jsonl/);
  assert.throws(() => parseClaudeReview(JSON.stringify({ type: 'control_request' }), f.request), /cli_execution_event_rejected/);
  assert.throws(() => parseClaudeReview([init, { type: 'result', subtype: 'success', is_error: false, result: JSON.stringify({ summary: 'inert', notes: [{ path: 'outside.mjs', line: 1, kind: 'hardening', message: 'inert', recommendation: 'inert' }] }) }].map(JSON.stringify).join('\n'), f.request), /cli_review_schema/);
  assert.ok(new ConnectorError('safe_code').message === 'safe_code');
});

test('loss of the claimed relay job cancels a running fake CLI without submitting', async (t) => {
  const f = connectorFixture(t, { hang: true });
  let submitted = false;
  await assert.rejects(connectTerminal({ operation: 'connect', provider: 'claude', socket: '/unused', model: 'requested' }, {
    adapter: f.adapter, call: async (_socket, message) => {
      if (message.method === 'review.claim') return { request: f.request, claimId: 'fake-claim' };
      if (message.method === 'review.status') return { state: 'cancelled' };
      submitted = true;
    },
  }), /connector_cancelled/);
  assert.equal(submitted, false);
});

test('ambiguous success and formatter output are not accepted as plain JSON review', (t) => {
  const f = connectorFixture(t);
  const init = { type: 'system', subtype: 'init', tools: [], mcp_servers: [] };
  for (const extra of [{}, { is_error: 'false' }, { is_error: false, structured_output: { summary: 'inert', notes: [] } }]) {
    const event = { type: 'result', subtype: 'success', result: '{"summary":"inert","notes":[]}', ...extra };
    assert.throws(() => parseClaudeReview([init, event].map(JSON.stringify).join('\n'), f.request), /cli_result_rejected/);
  }
});
