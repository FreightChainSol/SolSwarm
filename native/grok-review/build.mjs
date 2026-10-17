import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { openPrivateOutput, runGate } from '../codex-review/build.mjs';
import { overlaySource, LOGIN_MANAGER, LOGIN_RESOLVER, SAMPLER_CLIENT, ROUTING, AUTH_MODULE, LOGIN_CONFIG, CONFIG_LIB, MDM, ERROR_MODULE } from './overlays.mjs';

export const PIN = '2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8';
export const SOURCE_REVISION = '559751fdcec02d413e4c57c8832ab275e4f44980';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const CACHE = path.resolve(HERE,'../.cache');
const SOURCE = path.join(CACHE,`grok-${PIN}`);
const BUILD = path.join(CACHE,'grok-build');
const MEMBER = 'freightchain-review';
const PACKAGE = 'freightchain-grok-review';
const INPUTS = {
  'Cargo.toml':'Cargo.toml',
  'NOTICE':'NOTICE',
  'src/lib.rs':'src/lib.rs',
  'src/main.rs':'src/main.rs',
  'src/config.rs':'src/config.rs',
  'src/runtime.rs':'src/runtime.rs',
  'src/routing.rs':'src/routing.rs',
  'tests/sampler_gate.rs':'tests/sampler_gate.rs',
  'tests/auth_gate.rs':'tests/auth_gate.rs',
  'tests/entry_gate.rs':'tests/entry_gate.rs',
  'tests/error_classifier_gate.rs':'tests/error_classifier_gate.rs',
  'src/contract.rs':'../codex-review/src/contract.rs',
  'review-instruction.txt':'../codex-review/review-instruction.txt',
};
export const NATIVE_DEPENDENCIES = ['chrono','futures-util','indexmap','libc','serde','serde_json','sha2','tempfile','tokio','toml','tracing','wiremock','xai-dirs','xai-grok-config','xai-grok-http','xai-grok-login','xai-grok-sampler','xai-grok-sampling-types','xai-grok-shell-base','xai-grok-version'];
const OVERLAY_PATHS = [LOGIN_MANAGER, LOGIN_RESOLVER, SAMPLER_CLIENT, ROUTING, LOGIN_CONFIG, CONFIG_LIB, MDM];
const PROTOC_SHA256 = 'bdc43e54153911f625a50baf7d4f6bc05008712964141baedd5a61122f93a016';
const hash = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
export function routingModule(source) {
  const start=source.indexOf('pub(crate) fn inject_url_derived_headers(');
  const end=source.indexOf('\nfn resolve_hidden_default_web_search_sampling_config(',start);
  if(start<0||end<0)throw new Error('grok_native_routing_shape_changed');
  const body=source.slice(start,end).replace('pub(crate) fn','fn')
    .replaceAll('crate::util::','xai_grok_shell_base::util::').replaceAll('crate::http::','xai_grok_http::');
  return '// Derived from the pinned native inject_url_derived_headers implementation.\n// Build preparation verifies this body against upstream before compilation.\nuse indexmap::IndexMap;\n\n'+body+'\n\npub fn fixed_route_headers() -> IndexMap<String, String> {\n    let mut headers = IndexMap::new();\n    inject_url_derived_headers(&mut headers, None, xai_grok_login::CLI_CHAT_PROXY_BASE_URL_DEFAULT);\n    headers\n}\n';
}
export function nativeIdentity() {
  const packageInputs=Object.entries(INPUTS).map(([name,input])=>[name,hash(fs.readFileSync(path.resolve(HERE,input)))]);
  const scripts=path.resolve(HERE,'../../scripts');
  const recipeInputs=[
    ...packageInputs,
    ...['build.mjs','Dockerfile','Dockerfile.dockerignore','docker.mjs','overlays.mjs','overlays/text_review.rs','overlays/error_classifier.rs','source-pin.json','admit.mjs','../codex-review/build.mjs','../codex-review/admit.mjs'].map((name)=>[name,hash(fs.readFileSync(path.join(HERE,name)))]),
    ...fs.readdirSync(scripts).filter((name)=>name.endsWith('.mjs')).sort().map((name)=>[`scripts/${name}`,hash(fs.readFileSync(path.join(scripts,name)))]),
    ['bin/audit',hash(fs.readFileSync(path.resolve(HERE,'../../bin/audit')))],
  ];
  return {packageDigest:hash(JSON.stringify(packageInputs)),recipeDigest:hash(JSON.stringify(recipeInputs))};
}
function privateDirectory(dir) {
  if(!fs.existsSync(dir))fs.mkdirSync(dir,{recursive:true,mode:0o700});
  const stat=fs.lstatSync(dir);
  if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid()||(stat.mode&0o077))throw new Error('grok_cache_not_private');
}
function write(file,bytes) {
  // Preserve mtimes for identical inputs so preparation does not rebuild the
  // entire native dependency graph after a transport-only change.
  if(fs.existsSync(file)){
    const current=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
    try{
      const stat=fs.fstatSync(current);
      if(!stat.isFile()||stat.nlink!==1||stat.uid!==process.getuid()||(stat.mode&0o077))throw new Error('grok_output_file_rejected');
      const expected=Buffer.from(bytes);
      if(stat.size===expected.length&&fs.readFileSync(current).equals(expected))return;
    }finally{fs.closeSync(current);}
  }
  const fd=openPrivateOutput(file);
  try{fs.writeFileSync(fd,bytes);}finally{fs.closeSync(fd);}
}
export function withoutPackage(lock) {
  const blocks=lock.split(/\n(?=\[\[package\]\])/);
  return blocks.filter((block)=>!block.startsWith(`[[package]]\nname = "${PACKAGE}"\n`)).join('\n');
}
export function overlayManifest(manifest) {
  if(!manifest.startsWith('# Auto-generated workspace root.')||manifest.split('members = [\n').length!==2||manifest.includes(`"${MEMBER}"`))throw new Error('grok_workspace_shape_changed');
  return manifest.replace('members = [\n',`members = [\n "${MEMBER}",\n`);
}
export function overlayLock(lock) {
  if(lock.includes(`name = "${PACKAGE}"`))throw new Error('grok_lock_already_overlaid');
  const blocks=lock.split(/\n(?=\[\[package\]\])/);
  const labels=NATIVE_DEPENDENCIES.map((name)=>{
    const versions=blocks.filter((block)=>block.startsWith(`[[package]]\nname = "${name}"\n`)).map((block)=>block.match(/\nversion = "([^"]+)"/)?.[1]).filter(Boolean);
    const picked=versions.length===1?versions[0]:name==='sha2'?versions.find((version)=>version.startsWith('0.10.')):undefined;
    if(!picked)throw new Error('grok_locked_dependency_ambiguous');
    return versions.length===1?name:`${name} ${picked}`;
  });
  const added=`[[package]]\nname = "${PACKAGE}"\nversion = "0.1.0"\ndependencies = [\n${labels.map((label)=>` "${label}",`).join('\n')}\n]\n`;
  const anchor=blocks.find((block)=>block.startsWith('[[package]]')&&block.match(/\nname = "([^"]+)"/)?.[1]>PACKAGE);
  if(!anchor)throw new Error('grok_lock_anchor_missing');
  const at=lock.indexOf(anchor);
  return `${lock.slice(0,at)}${added}\n${lock.slice(at)}`;
}
function command(argv,env) {
  const result=spawnSync(argv[0],argv.slice(1),{cwd:SOURCE,env,encoding:'utf8',timeout:60_000,maxBuffer:8*1024*1024});
  if(result.error||result.status!==0)throw new Error('grok_prepare_command_failed');
  return result.stdout;
}
export function validateExtras(names) {
  const allowed=new Set([...Object.keys(INPUTS),'UPSTREAM_LICENSE','UPSTREAM_THIRD-PARTY-NOTICES'].map((name)=>`${MEMBER}/${name}`));
  allowed.add(AUTH_MODULE);
  allowed.add(ERROR_MODULE);
  if(names.some((name)=>name&&!allowed.has(name)))throw new Error('grok_untracked_source_input');
}
function validateOverlay(dir) {
  const allowed=new Set([...Object.keys(INPUTS),'UPSTREAM_LICENSE','UPSTREAM_THIRD-PARTY-NOTICES']);
  const visit=(folder,prefix='')=>{
    for(const item of fs.readdirSync(folder,{withFileTypes:true})){
      const name=prefix+item.name;
      const file=path.join(folder,item.name);
      const stat=fs.lstatSync(file);
      if(stat.isSymbolicLink()||stat.uid!==process.getuid())throw new Error('grok_overlay_input_rejected');
      if(item.isDirectory()){
        if(!['src','tests'].includes(name))throw new Error('grok_overlay_input_rejected');
        privateDirectory(file);
        visit(file,`${name}/`);
      }else if(!allowed.has(name)||!stat.isFile()||stat.nlink!==1)throw new Error('grok_overlay_input_rejected');
    }
  };
  visit(dir);
}
export function prepare() {
  privateDirectory(CACHE);
  privateDirectory(SOURCE);
  privateDirectory(BUILD);
  for(const name of ['home','cargo-home','target'])privateDirectory(path.join(BUILD,name));
  const env={};
  for(const key of ['PATH','LANG','LC_ALL','TMPDIR'])if(typeof process.env[key]==='string')env[key]=process.env[key];
  Object.assign(env,{
    HOME:path.join(BUILD,'home'),CARGO_HOME:path.join(BUILD,'cargo-home'),CARGO_TARGET_DIR:path.join(BUILD,'target'),
    RUSTUP_HOME:path.join(os.homedir(),'.rustup'),CARGO_BUILD_JOBS:'2',CARGO_PROFILE_DEV_DEBUG:'0',GIT_TERMINAL_PROMPT:'0',
    PROTOC:path.join(BUILD,'protoc-29.3/bin/protoc'),PROTOC_INCLUDE:path.join(BUILD,'protoc-29.3/include'),
  });
  const compiler=fs.lstatSync(env.PROTOC);
  if(!compiler.isFile()||compiler.isSymbolicLink()||compiler.uid!==process.getuid()||(compiler.mode&0o077)||hash(fs.readFileSync(env.PROTOC))!==PROTOC_SHA256)throw new Error('grok_private_protoc_required');
  const git=['git','--no-pager','-c','core.hooksPath=/dev/null','-c','protocol.ext.allow=never','-c','protocol.file.allow=never','-c','credential.helper=','-C',SOURCE];
  if(command([...git,'rev-parse','HEAD'],env).trim()!==PIN||fs.readFileSync(path.join(SOURCE,'SOURCE_REV'),'utf8').trim()!==SOURCE_REVISION)throw new Error('grok_source_pin_mismatch');
  const manifest=command([...git,'show','HEAD:Cargo.toml'],env);
  const lock=command([...git,'show','HEAD:Cargo.lock'],env);
  const routing=routingModule(command([...git,'show',`HEAD:${ROUTING}`],env));
  if(fs.readFileSync(path.join(HERE,'src/routing.rs'),'utf8')!==routing)throw new Error('grok_native_routing_drift');
  const overlaidManifest=overlayManifest(manifest);
  const overlaidLock=overlayLock(lock);
  const dirty=command([...git,'diff','--name-only','HEAD'],env).trim().split('\n').filter(Boolean);
  if(dirty.some((name)=>!['Cargo.toml','Cargo.lock',...OVERLAY_PATHS].includes(name)))throw new Error('grok_cached_source_changed');
  const overlays=OVERLAY_PATHS.map((name)=>{
    const original=command([...git,'show',`HEAD:${name}`],env);
    const expected=overlaySource(name,original);
    const file=path.join(SOURCE,name);
    const stat=fs.lstatSync(file);
    if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||stat.uid!==process.getuid())throw new Error('grok_overlay_input_rejected');
    const existing=fs.readFileSync(file,'utf8');
    return {name,file,expected,existing,recognized:existing===original||existing===expected};
  });
  if(overlays.some((overlay)=>!overlay.recognized)){
    const fd=fs.openSync(path.join(BUILD,'prepared.json'),fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
    let previous;
    try{
      const stat=fs.fstatSync(fd);
      if(!stat.isFile()||stat.uid!==process.getuid()||stat.nlink!==1||(stat.mode&0o077)||stat.size>16_384)throw new Error('grok_previous_overlay_receipt_rejected');
      previous=JSON.parse(fs.readFileSync(fd,'utf8'));
    }finally{fs.closeSync(fd);}
    const module=path.join(SOURCE,AUTH_MODULE);
    const stat=fs.lstatSync(module);
    if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||stat.uid!==process.getuid())throw new Error('grok_overlay_input_rejected');
    const oldPaths=previous.overlayPaths||[LOGIN_MANAGER,LOGIN_RESOLVER,SAMPLER_CLIENT,ROUTING];
    if(!Array.isArray(oldPaths)||oldPaths.some((name)=>!OVERLAY_PATHS.includes(name)))throw new Error('grok_previous_overlay_receipt_rejected');
    const classifier=path.join(SOURCE,ERROR_MODULE);
    const classifierInputs=[];
    if(previous.classifierModuleDigest){
      const stat=fs.lstatSync(classifier);
      if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||stat.uid!==process.getuid())throw new Error('grok_overlay_input_rejected');
      classifierInputs.push([ERROR_MODULE,hash(fs.readFileSync(classifier))]);
    }
    const existingDigest=hash(JSON.stringify([...overlays.filter(({name})=>oldPaths.includes(name)).map(({name,existing})=>[name,hash(existing)]),[AUTH_MODULE,hash(fs.readFileSync(module))],...classifierInputs]));
    if(previous.sourceCommit!==PIN||previous.overlayDigest!==existingDigest)throw new Error('grok_cached_source_changed');
  }
  for(const ignored of [false,true])validateExtras(command([...git,'ls-files','--others','--exclude-standard','-z',...(ignored?['--ignored']:[])],env).split('\0').filter(Boolean));
  for(const [name,original,expected] of [['Cargo.toml',manifest,overlaidManifest],['Cargo.lock',lock,overlaidLock]]){
    const file=path.join(SOURCE,name);
    const stat=fs.lstatSync(file);
    if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||stat.uid!==process.getuid())throw new Error('grok_workspace_file_rejected');
    const existing=fs.readFileSync(file,'utf8');
    if(existing!==original&&existing!==expected&&!(name==='Cargo.lock'&&withoutPackage(existing).trimEnd()===withoutPackage(expected).trimEnd()))throw new Error('grok_cached_workspace_changed');
  }
  const crate=path.join(SOURCE,MEMBER);
  privateDirectory(crate);
  validateOverlay(crate);
  for(const overlay of overlays)if(overlay.existing!==overlay.expected)fs.writeFileSync(overlay.file,overlay.expected);
  const authModule=fs.readFileSync(path.join(HERE,'overlays/text_review.rs'));
  const authOutput=path.join(SOURCE,AUTH_MODULE);
  const authParent=fs.lstatSync(path.dirname(authOutput));
  if(!authParent.isDirectory()||authParent.isSymbolicLink()||authParent.uid!==process.getuid())throw new Error('grok_overlay_input_rejected');
  if(fs.existsSync(authOutput)){
    const stat=fs.lstatSync(authOutput);
    if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||stat.uid!==process.getuid())throw new Error('grok_overlay_input_rejected');
  }
  if(!fs.existsSync(authOutput)||!fs.readFileSync(authOutput).equals(authModule))fs.writeFileSync(authOutput,authModule,{mode:0o600});
  const classifierModule=fs.readFileSync(path.join(HERE,'overlays/error_classifier.rs'));
  const classifierOutput=path.join(SOURCE,ERROR_MODULE);
  const classifierParent=fs.lstatSync(path.dirname(classifierOutput));
  if(!classifierParent.isDirectory()||classifierParent.isSymbolicLink()||classifierParent.uid!==process.getuid())throw new Error('grok_overlay_input_rejected');
  if(fs.existsSync(classifierOutput)){
    const stat=fs.lstatSync(classifierOutput);
    if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||stat.uid!==process.getuid())throw new Error('grok_overlay_input_rejected');
  }
  if(!fs.existsSync(classifierOutput)||!fs.readFileSync(classifierOutput).equals(classifierModule))fs.writeFileSync(classifierOutput,classifierModule,{mode:0o600});
  const identities=[];
  for(const [name,input] of Object.entries(INPUTS)){
    const file=path.resolve(HERE,input);
    const stat=fs.lstatSync(file);
    if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||stat.uid!==process.getuid())throw new Error('grok_package_input_rejected');
    const bytes=fs.readFileSync(file);
    const output=path.join(crate,name);
    privateDirectory(path.dirname(output));
    write(output,bytes);
    identities.push([name,hash(bytes)]);
  }
  for(const name of ['LICENSE','THIRD-PARTY-NOTICES'])write(path.join(crate,`UPSTREAM_${name}`),fs.readFileSync(path.join(SOURCE,name)));
  validateOverlay(crate);
  if(fs.readFileSync(path.join(SOURCE,'Cargo.toml'),'utf8')!==overlaidManifest)fs.writeFileSync(path.join(SOURCE,'Cargo.toml'),overlaidManifest);
  if(fs.readFileSync(path.join(SOURCE,'Cargo.lock'),'utf8')!==overlaidLock)fs.writeFileSync(path.join(SOURCE,'Cargo.lock'),overlaidLock);
  const metadata={
    sourceCommit:PIN,sourceRevision:SOURCE_REVISION,packageDigest:hash(JSON.stringify(identities)),lockDigest:hash(overlaidLock),
    protocSha256:hash(fs.readFileSync(env.PROTOC)),compiler:command(['rustup','run','stable','rustc','--version'],env).trim(),
    overlayDigest:hash(JSON.stringify([...overlays.map(({name,expected})=>[name,hash(expected)]),[AUTH_MODULE,hash(authModule)],[ERROR_MODULE,hash(classifierModule)]])),
    classifierModuleDigest:hash(classifierModule),
    overlayPaths:OVERLAY_PATHS,
    stage:'native_contract_and_sampler_gates',admission:false,
  };
  write(path.join(BUILD,'prepared.json'),JSON.stringify(metadata,null,2));
  return {env,metadata};
}
export async function testNative() {
  const {env,metadata}=prepare();
  const result=await runGate(['rustup','run','stable','cargo','test','--locked','-p',PACKAGE],env,SOURCE,path.join(BUILD,'sampler-gates.log'));
  const receipt={...metadata,nativeTests:result.passed?'passed':'failed',...result,admission:false};
  write(path.join(BUILD,'sampler-gates.json'),JSON.stringify(receipt,null,2));
  return receipt;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{
    const args=process.argv.slice(2);
    if(args.length!==1||!['--prepare','--test'].includes(args[0]))throw new Error('grok_build_usage');
    const result=args[0]==='--test'?await testNative():prepare().metadata;
    process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
    if(result.passed===false)process.exitCode=2;
  }catch(error){
    const reason=/^grok_[a-z_]+$/.test(error.message)?error.message:'grok_build_failed';
    process.stderr.write(`${JSON.stringify({admission:false,reason})}\n`);
    process.exitCode=2;
  }
}
