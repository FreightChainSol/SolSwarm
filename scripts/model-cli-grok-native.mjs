import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createNativeReviewAdapter } from './model-cli-codex-native.mjs';
import { PIN, SOURCE_REVISION, nativeIdentity } from '../native/grok-review/build.mjs';
import { matchesAdmission } from '../native/grok-review/admit.mjs';

export const GROK_SOURCE = PIN;
export const GROK_SOURCE_REVISION = SOURCE_REVISION;
export const DEFAULT_GROK_MODEL = 'grok-4.7';
const CACHE=fileURLToPath(new URL('../native/.cache/grok-build/',import.meta.url));
const BINARY=path.join(CACHE,'target/debug/freightchain-grok-review');
const REASONS=new Set([
  'grok_input_contract_rejected','grok_output_contract_rejected','grok_configuration_rejected',
  'grok_subscription_auth_required','grok_runtime_failed','grok_execution_event_rejected','grok_deadline_exceeded',
  'grok_provider_http_400','grok_provider_http_401','grok_provider_http_403','grok_provider_http_404',
  'grok_provider_http_409','grok_provider_http_413','grok_provider_http_422','grok_provider_http_429',
  'grok_provider_unavailable','grok_provider_http_rejected','grok_provider_transport_failed',
  'grok_provider_protocol_rejected','grok_provider_stream_rejected',
]);
async function admittedBinary(){
  const parent=fs.lstatSync(CACHE);
  if(!parent.isDirectory()||parent.isSymbolicLink()||parent.uid!==process.getuid()||(parent.mode&0o077))throw new Error('grok_cache_rejected');
  const fd=fs.openSync(path.join(CACHE,'runtime-admission.json'),fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  let receipt;
  try{
    const stat=fs.fstatSync(fd);
    if(!stat.isFile()||stat.nlink!==1||stat.uid!==process.getuid()||(stat.mode&0o077)||stat.size>16_384)throw new Error('grok_receipt_rejected');
    receipt=JSON.parse(fs.readFileSync(fd,'utf8'));
  }finally{fs.closeSync(fd);}
  if(!matchesAdmission(receipt,nativeIdentity()))throw new Error('grok_receipt_stale');
  const stat=fs.lstatSync(BINARY);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||stat.uid!==process.getuid()||stat.size>4*1024**3)throw new Error('grok_binary_rejected');
  fs.accessSync(BINARY,fs.constants.X_OK);
  const hash=crypto.createHash('sha256');
  for await(const bytes of fs.createReadStream(BINARY))hash.update(bytes);
  if(hash.digest('hex')!==receipt.binarySha256)throw new Error('grok_binary_changed');
  return {executable:BINARY,identity:{
    sourceCommit:PIN,sourceRevision:SOURCE_REVISION,packageDigest:receipt.packageDigest,
    recipeDigest:receipt.recipeDigest,overlayDigest:receipt.overlayDigest,binarySha256:receipt.binarySha256,
  }};
}
const PROFILE=Object.freeze({
  provider:'grok',sourceCommit:PIN,sourceRevision:SOURCE_REVISION,authMethod:'oidc_cached',
  version:'public-source-native',tempPrefix:'fc-grok-session-',
  environmentKeys:['GROK_HOME','GROK_FORCE_LOGIN_TEAM_ID','GROK_DISABLE_API_KEY_AUTH'],
  inventories:['tools','hostedTools','mcpServers'],allowUnknownModel:true,
  diagnostics:true,
  admissionError:'grok_broker_not_admitted',resolveBinary:admittedBinary,reasons:REASONS,
});
// Executable injection remains internal test support, never a CLI/RPC flag.
export function createGrokNativeAdapter(options={}){
  return createNativeReviewAdapter({...options,model:options.model===undefined?DEFAULT_GROK_MODEL:options.model},PROFILE);
}
