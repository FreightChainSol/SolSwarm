import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { nativeFixture } from './codex-native-fixtures.mjs';
import { createCodexNativeAdapter } from './model-cli-codex-native.mjs';

test('native adapter preflights once, strips overrides and validates a single bounded result', async (t) => {
  const f = nativeFixture(t);
  const result = await f.nativeAdapter.withSession(async (session) => {
    assert.equal(session.provider, 'codex');
    assert.equal(session.authMethod, 'chatgpt');
    return session.review(f.request, 'fixture-requested-model');
  });
  assert.equal(result.cliReportedModel, 'fixture-served-model');
  assert.match(result.review.summary, /FAKE NATIVE/);
  const calls = fs.readFileSync(f.nativeLog,'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(calls.length, 1);
  assert.ok(!calls[0].keys.some((key) => ['OPENAI_API_KEY','CODEX_ACCESS_TOKEN','NODE_OPTIONS','HTTPS_PROXY'].includes(key)));
  assert.equal(fs.existsSync(calls[0].cwd), false);
  assert.equal(calls[0].cwd, calls[0].tmp);
});
test('native adapter refuses advertised tools before releasing a session', async (t) => {
  const f = nativeFixture(t,{tools:['exec_command']});
  await assert.rejects(f.nativeAdapter.withSession(() => assert.fail('must not admit tool-bearing native session')),/native_protocol_rejected/);
});
test('native adapter refuses invalid citations, duplicate frames and nonzero cleanup exit', async (t) => {
  for (const options of [{invalid:true},{duplicate:true},{failureExit:true}]) {
    const f = nativeFixture(t,options);
    await assert.rejects(f.nativeAdapter.withSession((session) => session.review(f.request,'fixture-requested-model')),/native_protocol_rejected|native_result_missing/);
  }
});
test('native cancellation reaps the owned process and private runtime tree', async (t) => {
  const f = nativeFixture(t,{hang:true});
  const controller = new AbortController();
  await assert.rejects(f.nativeAdapter.withSession(async (session) => {
    const pending = session.review(f.request,'fixture-requested-model');
    setTimeout(() => controller.abort(),100);
    return pending;
  },{signal:controller.signal}),/connector_cancelled/);
  const call = JSON.parse(fs.readFileSync(f.nativeLog,'utf8').trim());
  assert.equal(fs.existsSync(call.cwd), false);
});
test('native adapter rejects model changes and pre-cancelled startup', async (t) => {
  const f = nativeFixture(t);
  await assert.rejects(f.nativeAdapter.withSession((session) => session.review(f.request,'different-model')),/native_request_rejected/);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(createCodexNativeAdapter().withSession(() => assert.fail('must not start'),{signal:controller.signal}),/connector_cancelled/);
});
test('native clean exit before review is not an undefined successful result', async (t) => {
  const f = nativeFixture(t,{earlyExit:true});
  await assert.rejects(f.nativeAdapter.withSession(async (session) => {
    await new Promise((resolve) => setTimeout(resolve,100));
    return session.review(f.request,'fixture-requested-model');
  }),/native_request_rejected|native_result_missing/);
});
test('native check waits for clean exit without sending source', async (t) => {
  const f = nativeFixture(t);
  const adapter = createCodexNativeAdapter({executable:f.nativeExecutable,checkOnly:true});
  const status = await adapter.withSession((session) => ({provider:session.provider}));
  assert.equal(status.provider,'codex');
  assert.equal(fs.readFileSync(f.nativeLog,'utf8').trim().split('\n').length,1);
});
test('native cancellation kills a remaining owned descendant after its leader exits', async (t) => {
  const f = nativeFixture(t,{hang:true,descendant:true});
  const controller = new AbortController();
  await assert.rejects(f.nativeAdapter.withSession(async (session) => {
    const pending = session.review(f.request,'fixture-requested-model');
    controller.abort();
    return pending;
  },{signal:controller.signal}),/connector_cancelled/);
  const pid = Number(fs.readFileSync(f.descendant,'utf8'));
  let alive = true;
  for (let i=0;i<100 && alive;i++) {
    try { process.kill(pid,0); await new Promise((resolve) => setTimeout(resolve,10)); }
    catch (error) { if(error.code !== 'ESRCH') throw error; alive=false; }
  }
  assert.equal(alive,false);
  const call = JSON.parse(fs.readFileSync(f.nativeLog,'utf8').trim());
  assert.equal(fs.existsSync(call.cwd),false);
});
