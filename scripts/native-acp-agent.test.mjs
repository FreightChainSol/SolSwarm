import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { NativeAcpAgent } from './native-acp-agent.mjs';

const nativeId = '11111111-2222-4333-8444-555555555555';
function fixture(t, mode = 'success') {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-agy-acp-'));
  t.after(() => fs.rmSync(cwd, { recursive: true, force: true }));
  const cli = path.join(cwd, 'agy-fixture');
  fs.writeFileSync(cli, `#!${process.execPath}\nimport fs from 'node:fs';\nfs.appendFileSync('invocations.jsonl',JSON.stringify(process.argv.slice(2))+'\\n');\nconst emit = value=>process.stdout.write(JSON.stringify(value)+'\\n');\nemit({event:'init',conversation_id:${JSON.stringify(mode === 'wrong-session' ? 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee' : nativeId)}});\n${mode === 'provider-error' ? "emit({event:'step_update',step_update:{step_index:1,tool_name:'call_mcp_tool',state:'STEP_STATE_ERROR'}});emit({event:'usage',tokens:1});\n" : ''}${mode === 'silent' ? 'setInterval(()=>{},1000);' : `const result={event:'result',result:{status:${JSON.stringify(mode === 'provider-error' ? 'ERROR' : 'SUCCESS')},response:'Inert acknowledgement'}};${mode === 'unterminated' ? 'process.stdout.write(JSON.stringify(result));' : mode === 'truncated' ? 'process.stdout.write(JSON.stringify(result).slice(0,-1));' : mode === 'duplicate' ? 'emit(result);emit(result);' : 'emit(result);'}process.exitCode=${mode === 'exit-error' ? 7 : 0};`}\n`, { mode: 0o700 });
  // The extensionless fixture is ESM through a private package marker.
  fs.writeFileSync(path.join(cwd, 'package.json'), '{"type":"module"}');
  const mcpServers = [{ name: 'audit_docker', command: process.execPath, args: ['/inert/bridge.mjs'] }];
  const config = { agent: 'agy', model: 'fixture-model', cwd, cli, mcpServers };
  const events = [];
  const agent = new NativeAcpAgent(config, event => events.push(event));
  return { cwd, config, agent, events, setup: { cwd, mcpServers } };
}

test('AGY ACP resumes its exact native conversation and preserves the requested model', async t => {
  const f = fixture(t);
  const { sessionId } = await f.agent.request('session/new', f.setup);
  assert.deepEqual(await f.agent.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'inert first turn' }] }), { stopReason: 'end_turn' });
  const resumed = new NativeAcpAgent(f.config, event => f.events.push(event));
  await resumed.request('session/load', { ...f.setup, sessionId });
  await resumed.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'inert second turn' }] });
  const args = fs.readFileSync(path.join(f.cwd, 'invocations.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
  assert.ok(!args[0].includes('--conversation'));
  assert.equal(args[1][args[1].indexOf('--conversation') + 1], nativeId);
  assert.ok(args.every(row => row[row.indexOf('--model') + 1] === 'fixture-model'));
  assert.equal(f.events.filter(event => event.params.update.sessionUpdate === 'agent_message_chunk').length, 2);
  await assert.rejects(new NativeAcpAgent({ ...f.config, model: 'different' }).request('session/load', { ...f.setup, sessionId }), /session_identity_rejected/);
  await assert.rejects(resumed.request('session/load', { ...f.setup, cwd: '/different', sessionId }), /session_identity_rejected/);
});

test('AGY structured errors, nonzero exits and conversation substitution stay incomplete', async t => {
  for (const mode of ['provider-error', 'exit-error', 'wrong-session']) {
    const f = fixture(t, mode);
    if (mode === 'wrong-session') f.config.legacyConversationId = nativeId;
    const agent = new NativeAcpAgent(f.config, () => {});
    const { sessionId } = await agent.request('session/new', f.setup);
    await assert.rejects(agent.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'inert' }] }), /native_turn_failed/);
  }
});

test('AGY cancellation interrupts a silent native process and retains session identity', async t => {
  const f = fixture(t, 'silent');
  const { sessionId } = await f.agent.request('session/new', f.setup);
  const turn = f.agent.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'inert' }] });
  await new Promise(resolve => setTimeout(resolve, 100));
  await f.agent.request('session/cancel', { sessionId });
  assert.deepEqual(await turn, { stopReason: 'cancelled' });
  assert.equal(JSON.parse(fs.readFileSync(path.join(f.cwd, 'native-session.json'))).sessionId, sessionId);
});

test('AGY accepts a complete final frame without a newline and retains completion diagnostics', async t => {
  const f = fixture(t, 'unterminated');
  const { sessionId } = await f.agent.request('session/new', f.setup);
  assert.deepEqual(await f.agent.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'inert' }] }), { stopReason: 'end_turn' });
  const state = JSON.parse(fs.readFileSync(path.join(f.cwd, 'native-session.json')));
  assert.deepEqual(state.lastTurn, { exitCode: 0, signal: null, resultStatus: 'success', resultSeen: true, parseFailure: null, sessionBound: true, resultKeys: ['response', 'status'], stepStates: {}, otherEvents: {} });
});

test('AGY truncated or duplicate completion frames remain failures with bounded diagnostic enums', async t => {
  for (const mode of ['truncated', 'duplicate', 'provider-error', 'exit-error']) {
    const f = fixture(t, mode);
    const { sessionId } = await f.agent.request('session/new', f.setup);
    await assert.rejects(f.agent.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'inert' }] }), /native_turn_failed/);
    const state = JSON.parse(fs.readFileSync(path.join(f.cwd, 'native-session.json')));
    assert.equal(state.lastTurn.parseFailure, mode === 'truncated' ? 'invalid_frame' : mode === 'duplicate' ? 'duplicate_result' : null);
    assert.equal(state.lastTurn.exitCode === 7, mode === 'exit-error');
    assert.ok(!JSON.stringify(state.lastTurn).includes('Inert acknowledgement'));
    if (mode === 'provider-error') {
      assert.deepEqual(state.lastTurn.stepStates, { STEP_STATE_ERROR: 1 });
      assert.deepEqual(state.lastTurn.otherEvents, { usage: 1 });
      assert.deepEqual(state.lastTurn.resultKeys, ['response', 'status']);
    }
  }
});
