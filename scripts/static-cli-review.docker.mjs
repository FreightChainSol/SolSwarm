import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { connectorFixture } from './connector-fixtures.mjs';
import { nativeFixture } from './codex-native-fixtures.mjs';
import { grokFixture } from './grok-native-fixtures.mjs';
import { staticCliReview } from './static-cli-review.mjs';
import { REVIEW_IMAGE, backendStatus } from './worker-isolation.mjs';

assert.equal(spawnSync('docker', ['info'], { stdio: 'ignore', timeout: 10_000 }).status, 0);
assert.equal(spawnSync('docker', ['image', 'inspect', REVIEW_IMAGE], { stdio: 'ignore', timeout: 10_000 }).status, 0);
test('single-command CLI automatically collects a fake CLI review through Docker', (t) => {
  const f = connectorFixture(t, { requiredUser: 'fixture-operator' });
  const bin = path.join(f.root, 'bin');
  fs.mkdirSync(bin);
  fs.copyFileSync(path.join(f.root, 'fake-claude'), path.join(bin, 'claude'));
  fs.chmodSync(path.join(bin, 'claude'), 0o755);
  const out = path.join(f.root, 'review');
  const run = spawnSync('bash', [fileURLToPath(new URL('../bin/audit', import.meta.url)), 'review-with-cli', '--repo', f.root, '--file', 'src/label.mjs', '--provider', 'claude', '--model', 'fixture-requested', '--out', out], {
    env: { HOME: f.root, USER: 'fixture-operator', PATH: `${bin}${path.delimiter}${process.env.PATH}` }, encoding: 'utf8', timeout: 30_000,
  });
  assert.equal(run.status, 0, run.stderr);
  assert.equal(JSON.parse(run.stdout).state, 'collected');
  const status = JSON.parse(fs.readFileSync(path.join(out, 'connector-state.json')));
  assert.equal(status.requestedModel, 'fixture-requested');
  assert.equal(status.cliReportedModel, 'fixture-model-not-live');
  assert.equal(status.modelIdentity, 'unverified');
  const report = JSON.parse(fs.readFileSync(path.join(out, 'report.json')));
  assert.match(report.result.summary, /FAKE CLI/);
  const cleanup = JSON.parse(fs.readFileSync(path.join(out, 'relay-state.json')));
  assert.equal(cleanup.socketRemoved, true);
  assert.equal(cleanup.sourceRemoved, true);
  const ledger = JSON.parse(fs.readFileSync(path.join(out, 'journal/ledger.json')));
  assert.equal(ledger.cleanup.state, 'removed');
  assert.equal(ledger.boundary.network, 'none');
  assert.equal(ledger.boundary.user, '10001:10001');
  assert.equal(fs.readFileSync(f.log, 'utf8').trim().split('\n').length, 4);
  for (const provider of ['claude', 'codex', 'grok', 'agy']) assert.equal(backendStatus(provider).state, 'blocked');
});
test('rejected live-shaped output cancels Docker and leaves only incomplete evidence', async (t) => {
  const f = connectorFixture(t, { toolCall: true });
  const out = path.join(f.root, 'review');
  await assert.rejects(staticCliReview({ repo: f.root, out, files: ['src/label.mjs'], provider: 'claude', model: 'fixture-requested' }, { adapter: f.adapter, deadlineMs: 20_000 }), /cli_tool_or_content_rejected/);
  assert.equal(fs.existsSync(path.join(out, 'report.json')), false);
  const state = JSON.parse(fs.readFileSync(path.join(out, 'relay-state.json')));
  assert.equal(state.socketRemoved, true);
  assert.equal(state.sourceRemoved, true);
  const ledger = JSON.parse(fs.readFileSync(path.join(out, 'journal/ledger.json')));
  assert.equal(ledger.cleanup.state, 'removed');
  assert.equal(JSON.parse(fs.readFileSync(path.join(out, 'connector-state.json'))).state, 'blocked_or_incomplete');
});
test('Codex-native profile collects one fake native review through real Docker', async (t) => {
  const f = nativeFixture(t);
  const out = path.join(f.root,'native-review');
  const result = await staticCliReview({repo:f.root,out,files:['src/label.mjs'],provider:'codex-native',model:'fixture-requested-model'}, {adapter:f.nativeAdapter,deadlineMs:20_000});
  assert.equal(result.state,'collected');
  assert.equal(result.profile,'codex-native');
  assert.equal(result.provider,'codex');
  assert.equal(result.cliReportedModel,'fixture-served-model');
  assert.equal(result.modelIdentity,'unverified');
  assert.match(JSON.parse(fs.readFileSync(path.join(out,'report.json'))).result.summary,/FAKE NATIVE/);
  const state = JSON.parse(fs.readFileSync(path.join(out,'relay-state.json')));
  assert.equal(state.socketRemoved,true);
  assert.equal(state.sourceRemoved,true);
  assert.equal(JSON.parse(fs.readFileSync(path.join(out,'journal/ledger.json'))).cleanup.state,'removed');
  const calls = fs.readFileSync(f.nativeLog,'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(calls.length,1);
  assert.equal(fs.existsSync(calls[0].cwd),false);
});
test('native invalid result cancels Docker without publishing a report', async (t) => {
  const f = nativeFixture(t,{invalid:true});
  const out = path.join(f.root,'native-review');
  await assert.rejects(staticCliReview({repo:f.root,out,files:['src/label.mjs'],provider:'codex-native',model:'fixture-requested-model'}, {adapter:f.nativeAdapter,deadlineMs:20_000}),/native_protocol_rejected/);
  assert.equal(fs.existsSync(path.join(out,'report.json')),false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(out,'journal/ledger.json'))).cleanup.state,'removed');
  assert.equal(JSON.parse(fs.readFileSync(path.join(out,'relay-state.json'))).socketRemoved,true);
});
test('Grok-native profile collects one fake Grok review through real Docker',async(t)=>{
  const f=grokFixture(t);
  const out=path.join(f.root,'grok-review');
  const result=await staticCliReview({repo:f.root,out,files:['src/label.mjs'],provider:'grok-native',model:'fixture-requested-model'},{adapter:f.grokAdapter,deadlineMs:20_000});
  assert.equal(result.provider,'grok');
  assert.equal(result.profile,'grok-native');
  assert.equal(result.cliReportedModel,'fixture-grok-model');
  assert.match(JSON.parse(fs.readFileSync(path.join(out,'report.json'))).result.summary,/FAKE GROK NATIVE/);
  assert.equal(JSON.parse(fs.readFileSync(path.join(out,'journal/ledger.json'))).cleanup.state,'removed');
  const state=JSON.parse(fs.readFileSync(path.join(out,'relay-state.json')));
  assert.ok(state.socketRemoved&&state.sourceRemoved);
  assert.equal(fs.readFileSync(f.grokLog,'utf8').trim().split('\n').length,1);
});
test('Grok-native invalid output cancels Docker without publishing a report',async(t)=>{
  const f=grokFixture(t,{invalid:true});
  const out=path.join(f.root,'grok-review');
  await assert.rejects(staticCliReview({repo:f.root,out,files:['src/label.mjs'],provider:'grok-native',model:'fixture-requested-model'},{adapter:f.grokAdapter,deadlineMs:20_000}),/native_protocol_rejected/);
  assert.equal(fs.existsSync(path.join(out,'report.json')),false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(out,'journal/ledger.json'))).cleanup.state,'removed');
});
test('Grok-native provider diagnostics survive private coordinator cleanup without raw payloads',async(t)=>{
  const diagnostic={category:'invalid_parameter',parameter:'tool_choice'};
  const f=grokFixture(t,{failureReason:'grok_provider_http_400',diagnostic});
  const out=path.join(f.root,'grok-refusal');
  await assert.rejects(staticCliReview({repo:f.root,out,files:['src/label.mjs'],provider:'grok-native',model:'fixture-requested-model'},{adapter:f.grokAdapter,deadlineMs:20_000}),(error)=>{
    assert.equal(error.code,'grok_provider_http_400');
    assert.deepEqual(error.diagnostic,diagnostic);return true;
  });
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(out,'connector-state.json'))).diagnostic,diagnostic);
  assert.equal(fs.existsSync(path.join(out,'report.json')),false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(out,'journal/ledger.json'))).cleanup.state,'removed');
});
