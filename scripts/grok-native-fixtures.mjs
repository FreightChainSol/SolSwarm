// Fixture only: no native login store or model service is accessed.
import fs from 'node:fs';
import path from 'node:path';
import { connectorFixture } from './connector-fixtures.mjs';
import { createGrokNativeAdapter, GROK_SOURCE, GROK_SOURCE_REVISION } from './model-cli-grok-native.mjs';

export function grokFixture(t,options={}){
  const f=connectorFixture(t);
  const executable=path.join(f.root,'fake-grok-native');
  const log=path.join(f.root,'grok-calls.jsonl');
  fs.writeFileSync(executable,`#!${process.execPath}
import fs from 'node:fs';
import readline from 'node:readline';
const options=${JSON.stringify(options)};
fs.appendFileSync(${JSON.stringify(log)},JSON.stringify({args:process.argv.slice(2),cwd:process.cwd(),tmp:process.env.TMPDIR,keys:Object.keys(process.env)})+'\\n');
console.log(JSON.stringify({version:1,state:'preflight_ready',provider:'grok',authMethod:'oidc_cached',
 sourceCommit:${JSON.stringify(GROK_SOURCE)},sourceRevision:options.wrongRevision?'invalid':${JSON.stringify(GROK_SOURCE_REVISION)},
 tools:options.tools||[],hostedTools:options.hostedTools||[],mcpServers:[],clientReportedModel:'fixture-requested-model'}));
if(!process.argv.includes('--check')&&!options.earlyExit){
 const input=readline.createInterface({input:process.stdin});
 input.once('line',line=>{
  const request=JSON.parse(line);
  if(Object.keys(request).sort().join(',')!=='files,instruction,version')throw new Error('binding/override leaked');
  if(options.hang)return;
  if(options.failureReason){
   console.log(JSON.stringify({version:1,state:'blocked_or_incomplete',reason:options.failureReason,...(Object.hasOwn(options,'diagnostic')?{diagnostic:options.diagnostic}:{})}));
   input.close();process.stdin.destroy();process.exitCode=2;return;
  }
  const result={summary:'FAKE GROK NATIVE: inert fixture, not inference.',notes:[]};
  if(options.invalid)result.notes=[{path:'outside.mjs',line:1,kind:'hardening',message:'inert',recommendation:'inert'}];
  const frame={version:1,state:'result',provider:'grok',clientReportedModel:options.unknownModel?null:'fixture-grok-model',result};
  console.log(JSON.stringify(frame));
  if(options.duplicate)console.log(JSON.stringify(frame));
  input.close();process.stdin.destroy();process.exitCode=options.failureExit?2:0;
 });
}
`,{mode:0o755});
  const nativeAdapter=createGrokNativeAdapter({model:'fixture-requested-model',executable,environment:{
    HOME:f.root,USER:'fixture-operator',PATH:process.env.PATH,
    XAI_API_KEY:'dummy-fixture-only',GROK_AUTH:'dummy-fixture-only',GROK_AUTH_PROVIDER_COMMAND:'must-not-run',
    GROK_CLI_CHAT_PROXY_BASE_URL:'https://invalid.test',CODEX_HOME:'/must-not-forward',NODE_OPTIONS:'--invalid-fixture-option',
  }});
  return {...f,grokLog:log,grokExecutable:executable,grokAdapter:nativeAdapter};
}
