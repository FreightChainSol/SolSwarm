// Test-only executable double; never accesses accounts or a model service.
import fs from 'node:fs';
import path from 'node:path';
import { connectorFixture } from './connector-fixtures.mjs';
import { CODEX_SOURCE, createCodexNativeAdapter } from './model-cli-codex-native.mjs';

export function nativeFixture(t, options = {}) {
  const f = connectorFixture(t);
  const executable = path.join(f.root, 'fake-codex-native');
  const log = path.join(f.root, 'native-calls.jsonl');
  const descendant = path.join(f.root, 'native-descendant.pid');
  fs.writeFileSync(executable, `#!${process.execPath}
import fs from 'node:fs';
import readline from 'node:readline';
import {spawn} from 'node:child_process';
const options=${JSON.stringify(options)};
fs.appendFileSync(${JSON.stringify(log)},JSON.stringify({args:process.argv.slice(2),cwd:process.cwd(),tmp:process.env.TMPDIR,keys:Object.keys(process.env)})+'\\n');
if(options.descendant) {
 const file=${JSON.stringify(descendant)};
 spawn(process.execPath,['-e','const fs=require("node:fs");process.on("SIGTERM",()=>{});fs.writeFileSync('+JSON.stringify(file)+',String(process.pid));setInterval(()=>{},1000);'],{stdio:'ignore'});
 for(let i=0;i<100 && !fs.existsSync(file);i++) await new Promise(resolve=>setTimeout(resolve,10));
 if(!fs.existsSync(file)) throw new Error('fixture child not ready');
}
const model=process.argv[process.argv.indexOf('--model')+1];
console.log(JSON.stringify({version:1,state:'preflight_ready',provider:'codex',authMethod:'chatgpt',sourceCommit:${JSON.stringify(CODEX_SOURCE)},tools:options.tools||[],mcpServers:[],clientReportedModel:model}));
if(process.argv.includes('--check') || options.earlyExit) process.exitCode=0;
else {
 const input=readline.createInterface({input:process.stdin});
 input.once('line',line=>{
  const request=JSON.parse(line);
  if('requestId' in request || 'jobId' in request || 'claimId' in request) throw new Error('binding leaked into inference');
  if(options.hang) return;
  const result={summary:'FAKE NATIVE: inert review, no inference.',notes:[]};
  if(options.invalid) result.notes=[{path:'outside.mjs',line:1,kind:'hardening',message:'inert',recommendation:'inert'}];
  const frame={version:1,state:'result',provider:'codex',clientReportedModel:'fixture-served-model',result};
  console.log(JSON.stringify(frame));
  if(options.duplicate) console.log(JSON.stringify(frame));
  process.stdin.destroy();
  input.close();
  process.exitCode=options.failureExit?2:0;
 });
}
`, { mode: 0o755 });
  return { ...f, descendant, nativeLog: log, nativeExecutable: executable, nativeAdapter: createCodexNativeAdapter({
    model: 'fixture-requested-model', executable, environment: {
      HOME: f.root, USER: 'fixture-operator', PATH: process.env.PATH,
      OPENAI_API_KEY: 'dummy-not-a-secret', CODEX_ACCESS_TOKEN: 'dummy-not-a-secret',
      NODE_OPTIONS: '--invalid-fixture-option', HTTPS_PROXY: 'https://invalid.test',
    },
  }) };
}
