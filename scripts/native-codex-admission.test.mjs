import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { PIN, nativeIdentity, runGate } from '../native/codex-review/build.mjs';
import { ADMISSION_GATES, matchesAdmission, gateWasExecuted } from '../native/codex-review/admit.mjs';
import { parseStaticReview, staticCliReview } from './static-cli-review.mjs';
import { parseConnectorArgs } from './terminal-model-connector.mjs';
import { nativeFixture } from './codex-native-fixtures.mjs';

test('runtime admission requires every gate and current package/recipe/binary identity', () => {
  const identity = nativeIdentity();
  const receipt = {version:1,admission:true,sourceCommit:PIN,...identity,binarySha256:'a'.repeat(64),gates:ADMISSION_GATES.map((name) => ({name,passed:true}))};
  assert.equal(matchesAdmission(receipt,identity),true);
  for (const patch of [{admission:false},{version:2},{sourceCommit:'b'.repeat(40)},{packageDigest:'changed'},{recipeDigest:'changed'},{binarySha256:null},{gates:[]},{gates:receipt.gates.map((gate) => ({...gate,passed:false}))}]) {
    assert.equal(matchesAdmission({...receipt,...patch},identity),false);
  }
});
test('explicit native profile is distinct from the unmodified installed Codex CLI', () => {
  assert.equal(parseConnectorArgs(['check','--provider','codex-native']).provider,'codex-native');
  const args = ['--repo','/inert','--out','/unused','--file','sample.mjs','--provider','codex-native','--model','fixture'];
  assert.equal(parseStaticReview(args).provider,'codex-native');
  assert.throws(() => parseStaticReview(args.map((value) => value === 'codex-native' ? 'codex' : value)),/provider_tool_free_mode_unverified/);
  assert.throws(() => parseStaticReview([...args,'--executable','/unapproved']),/static_review_usage/);
});
test('native failed preflight cannot start the selected-source job', async (t) => {
  const f = nativeFixture(t,{tools:['exec_command']});
  await assert.rejects(staticCliReview({repo:f.root,out:`${f.root}/review`,files:['src/label.mjs'],provider:'codex-native',model:'fixture-requested-model'}, {
    adapter:f.nativeAdapter,runLocal:() => assert.fail('must not capture source'),
  }),/native_protocol_rejected/);
});
test('zero-test Cargo selectors and skipped Node suites cannot authorize admission', () => {
  assert.equal(gateWasExecuted('router','test result: ok. 0 passed; 0 failed;'),false);
  assert.equal(gateWasExecuted('router','test result: ok. 1 passed; 0 failed;'),true);
  assert.equal(gateWasExecuted('native','test result: ok. 1 passed; 0 failed;'),false);
  assert.equal(gateWasExecuted('docker','# pass 0\n# fail 0\n# skipped 1'),false);
  assert.equal(gateWasExecuted('docker','# pass 17\n# fail 0\n# skipped 0'),true);
});
test('gate runner preserves nonzero failure and terminates a stalled fixture', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(),'native-gate-fixture-'));
  t.after(() => fs.rmSync(root,{recursive:true,force:true}));
  const failed = await runGate([process.execPath,'-e','process.exitCode=2'],{},root,path.join(root,'failed.log'),5000);
  assert.equal(failed.passed,false);
  assert.equal(failed.observedExitCode,2);
  const timeout = await runGate([process.execPath,'-e','setInterval(()=>{},1000)'],{},root,path.join(root,'timeout.log'),100);
  assert.equal(timeout.passed,false);
  assert.equal(timeout.reason,'native_build_deadline');
});
