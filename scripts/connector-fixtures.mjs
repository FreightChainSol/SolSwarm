// Test-only local CLI double. No model, authentication-store or network access.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createSnapshot, disposeSnapshot } from './worker-isolation.mjs';
import { buildReviewRequest } from './terminal-review-contract.mjs';
import { createClaudeAdapter } from './model-cli-claude.mjs';

export function connectorFixture(t, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'connector-fixture-'));
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(root, 'src/label.mjs'), 'export const label = (value) => String(value).trim();\n');
  const snapshot = createSnapshot(root, { only: ['src/label.mjs'] });
  t.after(() => { disposeSnapshot(snapshot); fs.rmSync(root, { recursive: true, force: true }); });
  const executable = path.join(root, 'fake-claude');
  const log = path.join(root, 'calls.jsonl');
  const flags = ['--restricted', '--tools', '--strict-mcp-config', '--mcp-config', '--disable-slash-commands', '--no-session-persistence', '--setting-sources', '--settings', '--output-format', '--system-prompt', '--permission-mode'];
  const source = `#!${process.execPath}
import fs from 'node:fs';
const opts = ${JSON.stringify(options)};
const args = process.argv.slice(2);
const log = ${JSON.stringify(log)};
fs.appendFileSync(log, JSON.stringify({args,cwd:process.cwd(),environmentKeys:Object.keys(process.env)})+'\\n');
if(args.includes('--version')) console.log((opts.version || '2.1.300')+' (Claude Code)');
else if(args.includes('--help')) console.log(${JSON.stringify(flags.join(' '))});
else if(args[0]==='auth') {
 const loggedIn=!opts.noAuth && (!opts.requiredUser || process.env.USER===opts.requiredUser);
 console.log(JSON.stringify({loggedIn,authMethod:opts.authMethod || (loggedIn?'claude.ai':'none')}));
 if(!loggedIn) process.exitCode=1;
} else {
 let input='';
 for await(const chunk of process.stdin) input+=chunk;
 const payload=JSON.parse(input);
 if(!args.includes('--restricted') || args[args.indexOf('--tools')+1]!=='' || !args.includes('--strict-mcp-config') || args[args.indexOf('--mcp-config')+1]!=='{"mcpServers":{}}' || args[args.indexOf('--setting-sources')+1]!=='' || !args.includes('--disable-slash-commands') || !args.includes('--no-session-persistence')) throw new Error('required isolation flags missing');
 if(JSON.parse(args[args.indexOf('--settings')+1]).forceLoginMethod!=='claudeai') throw new Error('subscription login policy missing');
 if('jobId' in payload || 'claimId' in payload || 'requestId' in payload) throw new Error('correlation data reached inference');
 if(opts.large) process.stdout.write('x'.repeat(2*1024*1024+1));
 else {
  console.log(JSON.stringify({type:'system',subtype:'init',tools:opts.tools || [],mcp_servers:[],model:'fixture-model-not-live',session_id:'fixture-session'}));
  if(opts.telemetry!==false) console.log(JSON.stringify({type:'system',subtype:'thinking_tokens',estimated_tokens:8,estimated_tokens_delta:8,session_id:'fixture-session',uuid:'fixture-event',...opts.telemetry}));
  if(opts.hang) setInterval(()=>{},1000);
  else {
   const review={summary:'FAKE CLI: simulated source review; no inference occurred.',notes:[{path:payload.files[0].path,line:1,kind:'maintainability',message:'The conversion is explicit.',recommendation:'Document expected input types.'}]};
   console.log(JSON.stringify({type:'assistant',message:{content:[{type:opts.toolCall?'tool_use':'text',text:JSON.stringify(review)}]}}));
   console.log(JSON.stringify({type:'result',subtype:'success',is_error:false,result:JSON.stringify(review)}));
  }
 }
}
`;
  fs.writeFileSync(executable, source, { mode: 0o755 });
  return {
    root, snapshot, request: buildReviewRequest(snapshot, ['src/label.mjs']), log,
    adapter: createClaudeAdapter({ executable, inferenceTimeoutMs: options.inferenceTimeoutMs || 60_000, environment: { HOME: root, USER: 'fixture-operator', PATH: process.env.PATH, ANTHROPIC_API_KEY: 'dummy-not-a-secret', CLAUDE_CODE_OAUTH_TOKEN: 'dummy-not-a-secret', NODE_OPTIONS: '--invalid-test-option', HTTPS_PROXY: 'https://invalid.test' } }),
  };
}
