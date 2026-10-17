import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { grokFixture } from './grok-native-fixtures.mjs';
import { createGrokNativeAdapter } from './model-cli-grok-native.mjs';
import { PIN,SOURCE_REVISION,nativeIdentity } from '../native/grok-review/build.mjs';
import { GATES,matchesAdmission } from '../native/grok-review/admit.mjs';
import { parseStaticReview } from './static-cli-review.mjs';

test('Grok native transport preserves its provider, filters overrides and cleans one session',async(t)=>{
  const f=grokFixture(t);
  const answer=await f.grokAdapter.withSession(async(session)=>{
    assert.equal(session.provider,'grok');
    assert.equal(session.authMethod,'oidc_cached');
    return session.review(f.request,'fixture-requested-model');
  });
  assert.match(answer.review.summary,/FAKE GROK NATIVE/);
  assert.equal(answer.cliReportedModel,'fixture-grok-model');
  const calls=fs.readFileSync(f.grokLog,'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(calls.length,1);
  assert.equal(fs.existsSync(f.log),false);
  assert.equal(fs.existsSync(calls[0].cwd),false);
  assert.ok(!calls[0].keys.some((key)=>['XAI_API_KEY','GROK_AUTH','GROK_AUTH_PROVIDER_COMMAND','GROK_CLI_CHAT_PROXY_BASE_URL','CODEX_HOME','NODE_OPTIONS'].includes(key)));
});
test('Grok diagnostics carry only validated parameter names and reject extra payload fields',async(t)=>{
  const diagnostic={category:'invalid_parameter',parameter:'tool_choice'};
  const known=grokFixture(t,{failureReason:'grok_provider_http_400',diagnostic});
  await assert.rejects(known.grokAdapter.withSession((session)=>session.review(known.request,'fixture-requested-model')),(error)=>{
    assert.equal(error.code,'grok_provider_http_400');
    assert.deepEqual(error.diagnostic,diagnostic);
    return true;
  });
  for(const diagnostic of [
    {category:'invalid_parameter',parameter:'dummy-private-value'},
    {category:'unclassified',parameter:null,message:'dummy-private-value'},
    {category:'dummy-private-value',parameter:null},
  ]){
    const f=grokFixture(t,{failureReason:'grok_provider_http_400',diagnostic});
    await assert.rejects(f.grokAdapter.withSession((session)=>session.review(f.request,'fixture-requested-model')),(error)=>{
      assert.equal(error.code,'native_protocol_rejected');
      assert.ok(!error.message.includes('dummy-private-value'));
      return true;
    });
  }
});
test('Grok preflight refuses local/hosted tools and a mismatching source revision',async(t)=>{
  for(const options of [{tools:['run_terminal_cmd']},{hostedTools:['web_search']},{wrongRevision:true}]){
    const f=grokFixture(t,options);
    await assert.rejects(f.grokAdapter.withSession(()=>assert.fail('source must not be claimed')),/native_protocol_rejected/);
  }
});
test('Grok malformed/duplicate/nonzero results fail and unavailable model identity stays unknown',async(t)=>{
  for(const options of [{invalid:true},{duplicate:true},{failureExit:true}]){
    const f=grokFixture(t,options);
    await assert.rejects(f.grokAdapter.withSession((session)=>session.review(f.request,'fixture-requested-model')),/native_protocol_rejected|native_result_missing/);
  }
  const f=grokFixture(t,{unknownModel:true});
  const result=await f.grokAdapter.withSession((session)=>session.review(f.request,'fixture-requested-model'));
  assert.equal(result.cliReportedModel,null);
});
test('Grok cancellation and early exit cannot leave a successful partial review',async(t)=>{
  const f=grokFixture(t,{hang:true});
  const controller=new AbortController();
  await assert.rejects(f.grokAdapter.withSession(async(session)=>{
    const result=session.review(f.request,'fixture-requested-model');
    setTimeout(()=>controller.abort(),100);
    return result;
  },{signal:controller.signal}),/connector_cancelled/);
  assert.equal(fs.existsSync(JSON.parse(fs.readFileSync(f.grokLog,'utf8').trim()).cwd),false);
  const early=grokFixture(t,{earlyExit:true});
  await assert.rejects(early.grokAdapter.withSession(async(session)=>{
    await new Promise((resolve)=>setTimeout(resolve,100));
    return session.review(early.request,'fixture-requested-model');
  }),/native_request_rejected|native_result_missing/);
});
test('Grok receipt binds source/revision/current recipe and every gate; no installed-CLI substitution',()=>{
  const identity=nativeIdentity();
  const receipt={version:1,admission:true,sourceCommit:PIN,sourceRevision:SOURCE_REVISION,...identity,binarySha256:'a'.repeat(64),gates:GATES.map((name)=>({name,passed:true}))};
  assert.equal(matchesAdmission(receipt,identity),true);
  for(const patch of [{sourceRevision:'installed-1.0.52'},{recipeDigest:'stale'},{admission:false},{gates:[]}]){
    assert.equal(matchesAdmission({...receipt,...patch},identity),false);
  }
  assert.doesNotThrow(()=>createGrokNativeAdapter({model:undefined,checkOnly:true}));
  const args=['--repo','/inert','--out','/unused','--file','sample.mjs','--provider','grok-native','--model','fixture'];
  assert.equal(parseStaticReview(args).provider,'grok-native');
  assert.throws(()=>parseStaticReview(args.map((value)=>value==='grok-native'?'grok':value)),/provider_tool_free_mode_unverified/);
  assert.throws(()=>parseStaticReview([...args,'--executable','/unapproved']),/static_review_usage/);
});
test('Grok native diagnostics retain only fixed provider categories, not arbitrary payloads',async(t)=>{
  const known=grokFixture(t,{failureReason:'grok_provider_http_400'});
  await assert.rejects(known.grokAdapter.withSession((session)=>session.review(known.request,'fixture-requested-model')),/grok_provider_http_400/);
  const unknown=grokFixture(t,{failureReason:'dummy-provider-payload-must-not-appear'});
  await assert.rejects(unknown.grokAdapter.withSession((session)=>session.review(unknown.request,'fixture-requested-model')),(error)=>{
    assert.equal(error.code,'native_runtime_failed');
    assert.ok(!error.message.includes('dummy-provider-payload'));
    return true;
  });
});
