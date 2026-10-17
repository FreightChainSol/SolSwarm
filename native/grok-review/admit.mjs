import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { PIN, SOURCE_REVISION, prepare, nativeIdentity } from './build.mjs';
import { openPrivateOutput, runGate } from '../codex-review/build.mjs';

const HERE=path.dirname(fileURLToPath(import.meta.url));
const ROOT=path.resolve(HERE,'../../..');
const BUILD=path.resolve(HERE,'../.cache/grok-build');
const SOURCE=path.resolve(HERE,`../.cache/grok-${PIN}`);
const BINARY=path.join(BUILD,'target/debug/freightchain-grok-review');
export const GATES=Object.freeze(['native','binary','node','docker']);
export function matchesAdmission(receipt,identity){
  return receipt?.version===1&&receipt.admission===true&&receipt.sourceCommit===PIN&&receipt.sourceRevision===SOURCE_REVISION
    && receipt.packageDigest===identity.packageDigest&&receipt.recipeDigest===identity.recipeDigest
    && typeof receipt.binarySha256==='string'&&/^[a-f0-9]{64}$/.test(receipt.binarySha256)
    && Array.isArray(receipt.gates)&&receipt.gates.length===GATES.length
    && GATES.every((name,index)=>receipt.gates[index]?.name===name&&receipt.gates[index]?.passed===true);
}
const write=(receipt)=>{
  const fd=openPrivateOutput(path.join(BUILD,'runtime-admission.json'));
  try{fs.writeFileSync(fd,JSON.stringify(receipt,null,2));}finally{fs.closeSync(fd);}
};
async function hashFile(file){
  const hash=crypto.createHash('sha256');
  for await(const chunk of fs.createReadStream(file))hash.update(chunk);
  return hash.digest('hex');
}
export async function admit(){
  write({version:1,admission:false,sourceCommit:PIN,reason:'grok_admission_in_progress'});
  const {env,metadata}=prepare();
  const identity=nativeIdentity();
  const scripts=path.join(ROOT,'audit/scripts');
  const testEnv={};
  for(const key of ['HOME','USER','PATH','LANG','LC_ALL','TMPDIR','DOCKER_CONTEXT','DOCKER_HOST','DOCKER_CONFIG','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])if(typeof process.env[key]==='string')testEnv[key]=process.env[key];
  const node=[process.execPath,'--test','--test-concurrency=1','--test-reporter=tap'];
  const gates=[
    ['native',['rustup','run','stable','cargo','test','--locked','-p','freightchain-grok-review'],SOURCE,env],
    ['binary',['rustup','run','stable','cargo','build','--locked','-p','freightchain-grok-review','--bin','freightchain-grok-review'],SOURCE,env],
    ['node',[...node,...fs.readdirSync(scripts).filter((name)=>name.endsWith('.test.mjs')).sort().map((name)=>path.join(scripts,name))],ROOT,testEnv],
    ['docker',[...node,...['worker-isolation','terminal-relay','terminal-model-connector','static-cli-review','grok-docker'].map((name)=>path.join(scripts,`${name}.docker.mjs`))],ROOT,testEnv],
  ];
  const results=[];
  for(const [name,argv,cwd,environment]of gates){
    const log=path.join(BUILD,`admission-${name}.log`);
    const result=await runGate(argv,environment,cwd,log);
    const text=fs.readFileSync(log,'utf8');
    if(name==='native'&&![
      'actual_sampler_sends_no_local_or_hosted_tools_and_refuses_reuse',
      'native_cached_auth_preflight_and_resolver_never_modify_the_store',
      'native_cli_check_reads_only_the_dummy_store_and_emits_no_diagnostics',
      'unavailable_native_credential_sends_no_anonymous_request',
      'structured_parameters_are_allowlisted_and_provider_payloads_are_never_reflected',
      'provider_error_body_is_classified_without_reflecting_message_text',
      'stalled_provider_error_body_has_an_independent_read_deadline',
    ].every((test)=>text.includes(`${test} ... ok`)))result.passed=false;
    if(['node','docker'].includes(name)&&!(/# pass [1-9][0-9]*\b/.test(text)&&/# fail 0\b/.test(text)&&/# skipped 0\b/.test(text)))result.passed=false;
    if(name==='docker'&&!/ok [0-9]+ - Grok-native profile collects one fake Grok review through real Docker/.test(text))result.passed=false;
    results.push({name,...result,logSha256:await hashFile(log)});
    if(!result.passed){
      const receipt={...metadata,...identity,version:1,admission:false,gates:results,reason:`grok_${name}_gate_failed`};
      write(receipt);
      return receipt;
    }
  }
  const current=nativeIdentity();
  const prepared=prepare().metadata;
  if(current.packageDigest!==identity.packageDigest||current.recipeDigest!==identity.recipeDigest||prepared.overlayDigest!==metadata.overlayDigest||prepared.lockDigest!==metadata.lockDigest)throw new Error('grok_inputs_changed_during_gates');
  const stat=fs.lstatSync(BINARY);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||stat.uid!==process.getuid())throw new Error('grok_binary_rejected');
  const receipt={...metadata,...identity,version:1,admission:true,binarySha256:await hashFile(BINARY),gates:results};
  write(receipt);
  return receipt;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{
    if(process.argv.length!==3||process.argv[2]!=='--admit')throw new Error('grok_admission_usage');
    const receipt=await admit();
    process.stdout.write(`${JSON.stringify(receipt,null,2)}\n`);
    if(!receipt.admission)process.exitCode=2;
  }catch(error){
    const reason=/^grok_[a-z_]+$/.test(error.message)?error.message:'grok_admission_failed';
    process.stderr.write(`${JSON.stringify({admission:false,reason})}\n`);
    process.exitCode=2;
  }
}
