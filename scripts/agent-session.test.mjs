import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runReviewSession, permissionDecision, preflightBridge } from './agent-session.mjs';
import { openSessionStore } from './agent-session-store.mjs';
import { buildSessionLaunch, sessionEnvironment } from './agent-session-launch.mjs';

const identity = { agent: 'claude', model: 'fixture-model', sourceDigest: 'a'.repeat(64), assignmentDigest: 'b'.repeat(64), role: 'auditor', name: 'claude-s1-auth', surface: 'S1' };
const fixtureScript = `
import fs from 'node:fs';
import readline from 'node:readline';
const mode = process.argv[2];
const counter = 'starts.json';
const attempt = fs.existsSync(counter) ? JSON.parse(fs.readFileSync(counter)) : 0;
fs.writeFileSync(counter, JSON.stringify(attempt + 1));
const send = msg => process.stdout.write(JSON.stringify({jsonrpc:'2.0',...msg})+'\\n');
const reply = (id,result) => send({id,result});
const sid = 'saved-review-1';
let prompt;
readline.createInterface({input:process.stdin}).on('line', line => {
 const msg=JSON.parse(line);
 fs.appendFileSync('methods.txt',msg.method+'\\n');
 if(msg.method==='initialize') reply(msg.id,{protocolVersion:1,agentCapabilities:{loadSession:mode!=='no-load'}});
 else if(msg.method==='session/new') reply(msg.id,{sessionId:sid,configOptions:[{id:'model',category:'model',currentValue:'fixture-model'}]});
 else if(msg.method==='session/load') { if(msg.params.sessionId!==sid)process.exit(9); reply(msg.id,{}); }
 else if(msg.method==='session/cancel') { if(prompt)reply(prompt.id,{stopReason:'cancelled'}); }
 else if(msg.method==='session/prompt') {
   prompt=msg;
   if(mode==='disconnect' && attempt===0) {process.exit(3);return;}
   if(mode==='policy') {send({id:msg.id,error:{code:-32000,message:'This content was flagged for possible cybersecurity risk. DO_NOT_ECHO_PAYLOAD'}});return;}
   if(mode==='quota') {send({id:msg.id,error:{code:-32000,message:'RESOURCE_EXHAUSTED DO_NOT_ECHO_PAYLOAD'}});return;}
   if(mode==='malformed') {process.stdout.write('not json\\n');return;}
   if(mode==='changed-model') {send({method:'session/update',params:{sessionId:sid,update:{sessionUpdate:'config_option_update',configOptions:[{id:'model',category:'model',currentValue:'other-model'}]}}});return;}
   if(mode==='permission') {
     send({id:1000,method:'fs/read_text_file',params:{path:'/private/host-file'}});
     send({id:1001,method:'session/request_permission',params:{sessionId:sid,toolCall:{title:'mcp__audit_docker__read_file',kind:'execute',rawInput:{command:'host command'}},options:[{kind:'allow_once',optionId:'allow'},{kind:'reject_once',optionId:'reject'}]}});
     return;
   }
   if(mode==='refusal'||mode==='refusal-loop') {
     fs.appendFileSync('prompts.txt',JSON.stringify(msg.params.prompt[0].text)+'\\n');
     if(mode==='refusal-loop'||!fs.existsSync('refused.json')) {
       send({id:1002,method:'session/request_permission',params:{sessionId:sid,toolCall:{title:'audit_docker__use_tool',_meta:{'x.ai/tool':{version:1,name:'use_tool',kind:'use_tool'}},rawInput:{variant:'UseTool',tool_name:'audit_docker__use_tool',tool_input:{tool_name:'audit_docker__run_existing_tests',tool_input:{}}}},options:[{kind:'allow_once',optionId:'allow'},{kind:'reject_once',optionId:'reject'}]}});
       return;
     }
   }
   if(mode==='silent')return;
   send({method:'session/update',params:{sessionId:sid,update:{sessionUpdate:'agent_message_chunk',content:{type:'text',text:mode==='quoted-quota'?'Historical incident: You have hit your session limit; RESOURCE_EXHAUSTED. Remediation is documented.':'Acknowledged'}}}});
   reply(msg.id,{stopReason:'end_turn'});
   if(mode==='exit-error')process.exitCode=7;
 } else if(msg.id===1000)fs.writeFileSync('filesystem-denied.json',JSON.stringify(msg));
 else if(msg.id===1002){fs.writeFileSync('refused.json',JSON.stringify(msg));reply(prompt.id,{stopReason:'cancelled'});}
 else if(msg.id===1001){fs.writeFileSync('permission.json',JSON.stringify(msg));reply(prompt.id,{stopReason:'end_turn'});}
});
`;

function fixture(t, mode = 'success') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-session-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const executable = path.join(root, 'fixture.mjs');
  fs.writeFileSync(executable, fixtureScript);
  const options = { directory: path.join(root, 'session'), identity, bridgeArgs: [], prompt: 'Inert session fixture' };
  const support = {
    heartbeatMs: 30,
    preflight: async () => ({ state: 'ready', tools: ['read_file', 'submit_audit_report'] }),
    launch: ({ workDir }) => ({ invocation: { executable: process.execPath, args: [executable, mode], cwd: workDir, env: process.env }, mcpServers: [{}], transport: 'inert_acp_fixture' }),
  };
  const state = () => JSON.parse(fs.readFileSync(path.join(options.directory, 'state.json')));
  return { root, options, support, state, workspace: path.join(options.directory, 'workspace') };
}

test('ACP session records completion and can load the exact saved conversation', async t => {
  const f = fixture(t);
  const first = await runReviewSession(f.options, f.support);
  assert.equal(first.code, 0);
  assert.equal(first.sessionId, 'saved-review-1');
  assert.equal(first.observedExitCode, 0);
  assert.equal(f.state().phase, 'completed');
  const second = await runReviewSession({ ...f.options, resume: true }, f.support);
  assert.equal(second.code, 0);
  assert.match(fs.readFileSync(path.join(f.workspace, 'methods.txt'), 'utf8'), /session\/load/);
});

test('successful turns cannot be reclassified by quoted historical quota or refusal text', async t => {
  const f = fixture(t, 'quoted-quota');
  const first = await runReviewSession(f.options, f.support);
  assert.equal(first.code, 0);
  const second = await runReviewSession({ ...f.options, resume: true }, f.support);
  assert.equal(second.code, 0);
  assert.equal(f.state().phase, 'completed');
});

test('silent reasoning survives repeated heartbeats and explicit cancellation retains the session', async t => {
  const f = fixture(t, 'silent');
  const controller = new AbortController();
  const heartbeats = [];
  const result = await runReviewSession({ ...f.options, signal: controller.signal, onProgress: event => {
    heartbeats.push(event);
    if (heartbeats.filter(e => e.phase === 'running').length >= 4) controller.abort();
  } }, f.support);
  assert.equal(result.code, 130);
  assert.equal(result.failureReason, 'cancelled');
  assert.ok(heartbeats.length >= 4);
  assert.ok(heartbeats.every(beat => beat.timeLimitMs === null));
  assert.equal(f.state().sessionId, 'saved-review-1');
  assert.equal(f.state().phase, 'cancelled');
});

test('a lost transport resumes once using the same identity without provider substitution', async t => {
  const f = fixture(t, 'disconnect');
  const result = await runReviewSession(f.options, f.support);
  assert.equal(result.code, 0);
  assert.equal(result.recoveryAttempts, 1);
  assert.equal(f.state().recoveryAttempts, 1);
  assert.equal(JSON.parse(fs.readFileSync(path.join(f.workspace, 'starts.json'))), 2);
  assert.match(fs.readFileSync(path.join(f.workspace, 'methods.txt'), 'utf8'), /session\/load/);
});

test('provider policy and quota failures never trigger retries or expose raw error payloads', async t => {
  for (const [mode, reason] of [['policy', 'provider_policy'], ['quota', 'usage_limit']]) {
    const f = fixture(t, mode);
    const result = await runReviewSession(f.options, f.support);
    assert.equal(result.code, 1);
    assert.equal(result.failureReason, reason);
    assert.equal(JSON.parse(fs.readFileSync(path.join(f.workspace, 'starts.json'))), 1);
    assert.ok(!JSON.stringify(result).includes('DO_NOT_ECHO'));
    assert.ok(!JSON.stringify(f.state()).includes('DO_NOT_ECHO'));
  }
});

test('wrong source, model or assignment cannot start a saved conversation', async t => {
  const f = fixture(t);
  await runReviewSession(f.options, f.support);
  for (const patch of [{ sourceDigest: 'c'.repeat(64) }, { model: 'different-model' }, { assignmentDigest: 'd'.repeat(64) }, { agent: 'grok' }]) {
    await assert.rejects(runReviewSession({ ...f.options, identity: { ...identity, ...patch } }, f.support), /session_identity_rejected/);
  }
  assert.equal(JSON.parse(fs.readFileSync(path.join(f.workspace, 'starts.json'))), 1);
});

test('missing resume capability, malformed frames, changed models and nonzero exits remain failures', async t => {
  for (const [mode, reason] of [['malformed', 'protocol_error'], ['changed-model', 'model_changed'], ['exit-error', 'process_error']]) {
    const f = fixture(t, mode);
    const result = await runReviewSession(f.options, f.support);
    assert.equal(result.code, 1, mode);
    assert.equal(result.failureReason, reason, mode);
  }
  const f = fixture(t, 'no-load');
  const store = openSessionStore(f.options.directory, identity);
  store.save('interrupted', { sessionId: 'saved-review-1' });
  const result = await runReviewSession(f.options, f.support);
  assert.equal(result.failureReason, 'resume_unsupported');
  assert.ok(!fs.readFileSync(path.join(f.workspace, 'methods.txt'), 'utf8').includes('session/prompt'));
});

test('ACP client denies host filesystem requests and permission-title spoofing', async t => {
  const f = fixture(t, 'permission');
  const result = await runReviewSession(f.options, f.support);
  assert.equal(result.code, 0);
  assert.equal(JSON.parse(fs.readFileSync(path.join(f.workspace, 'filesystem-denied.json'))).error.code, -32601);
  assert.equal(JSON.parse(fs.readFileSync(path.join(f.workspace, 'permission.json'))).result.outcome.optionId, 'reject');
  const options = [{ kind: 'allow_once', optionId: 'allow' }, { kind: 'reject_once', optionId: 'reject' }];
  assert.equal(permissionDecision({ sessionId: 'own', options, toolCall: { _meta: { is_mcp_tool_call: true }, rawInput: { server: 'audit_docker', tool: 'read_file' } } }, 'own').outcome.optionId, 'allow');
  const grokCall = { _meta: { 'x.ai/tool': { version: 1, name: 'use_tool', kind: 'use_tool' } }, rawInput: { variant: 'UseTool', tool_name: 'audit_docker__read_file' } };
  assert.equal(permissionDecision({ sessionId: 'own', options, toolCall: grokCall }, 'own').outcome.optionId, 'allow');
  assert.equal(permissionDecision({ sessionId: 'own', options, toolCall: { ...grokCall, rawInput: { variant: 'UseTool', tool_name: 'other__read_file' } } }, 'own').outcome.optionId, 'reject');
  assert.equal(permissionDecision({ sessionId: 'other', options, toolCall: { _meta: { claudeCode: { toolName: 'mcp__audit_docker__read_file' } } } }, 'own').outcome.outcome, 'cancelled');
});

test('a turn the agent cancels after a refused tool call continues in the same session', async t => {
  const f = fixture(t, 'refusal');
  const result = await runReviewSession(f.options, f.support);
  assert.equal(result.code, 0);
  assert.equal(JSON.parse(fs.readFileSync(path.join(f.workspace, 'refused.json'))).result.outcome.optionId, 'reject');
  const prompts = fs.readFileSync(path.join(f.workspace, 'prompts.txt'), 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.equal(prompts.length, 2);
  assert.match(prompts[1], /refused your tool call audit_docker__use_tool/);
  assert.equal(JSON.parse(fs.readFileSync(path.join(f.workspace, 'starts.json'))), 1);
  assert.ok(f.state().events.some(event => event.event === 'refusal_corrected'));
});

test('repeated refusal-induced cancellation fails as a permission error, not a user cancel', async t => {
  const f = fixture(t, 'refusal-loop');
  const result = await runReviewSession(f.options, f.support);
  assert.equal(result.code, 1);
  assert.equal(result.failureReason, 'permission_denied');
  assert.equal(fs.readFileSync(path.join(f.workspace, 'prompts.txt'), 'utf8').trim().split('\n').length, 4);
});

test('subscription environments omit credential and routing overrides', () => {
  const env = sessionEnvironment({ HOME: '/home/inert', PATH: '/bin', OPENAI_API_KEY: 'secret', ANTHROPIC_API_KEY: 'secret', NODE_OPTIONS: '--require bad.js', HTTPS_PROXY: 'https://untrusted', MODEL_PROVIDER: 'unapproved' });
  assert.deepEqual(env, { HOME: '/home/inert', PATH: '/bin' });
});

test('bridge preflight verifies real MCP inventory without inference or target execution', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-mcp-preflight-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const server = { command: process.execPath, args: [new URL('./docker-mcp-bridge.mjs', import.meta.url).pathname, '--report-dir', root, '--role', 'auditor', '--auditor', 'claude-s1-auth', '--agent', 'claude'] };
  const result = await preflightBridge(server, { cwd: root, env: process.env, expectedRole: 'auditor' });
  assert.equal(result.state, 'ready');
  assert.ok(result.tools.includes('submit_audit_report'));
  await assert.rejects(preflightBridge(server, { cwd: root, env: process.env, expectedRole: 'crosscheck' }), /mcp_unavailable/);
  assert.equal(fs.existsSync(path.join(root, 'auditors')), false);
});

test('session directories reject symlinks and unsafe permissions before launching an agent', t => {
  const f = fixture(t);
  const real = path.join(f.root, 'real'); fs.mkdirSync(real, { mode: 0o700 });
  fs.symlinkSync(real, f.options.directory);
  assert.throws(() => openSessionStore(f.options.directory, identity), /session_directory_rejected/);
});
