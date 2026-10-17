import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { grokDockerControl, prepareGrokDocker, createGrokDockerAdapter, GROK_AUTH_VOLUME, GROK_DOCKER_LABEL } from './model-cli-grok-docker.mjs';
import { GROK_SOURCE, GROK_SOURCE_REVISION } from './model-cli-grok-native.mjs';
import { REVIEW_IMAGE } from './worker-isolation.mjs';
import { staticCliReview } from './static-cli-review.mjs';

test('Grok Docker keeps the inference process and credentials inside its private boundary', { timeout: 120_000 }, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fc-grok-docker-fixture-'));
  const fixture = `fc-grok-fixture-${crypto.randomUUID()}`;
  const volume = `${fixture}-auth`;
  t.after(async () => {
    await grokDockerControl(['volume', 'rm', volume]);
    await grokDockerControl(['image', 'rm', fixture]);
    fs.rmSync(root, { recursive: true, force: true });
  });
  fs.writeFileSync(path.join(root, 'Dockerfile'), `FROM ${REVIEW_IMAGE}\nCOPY broker.mjs /trusted/broker.mjs\nLABEL freightchain.grok.source="${GROK_SOURCE}"\nENTRYPOINT ["/usr/local/bin/node","/trusted/broker.mjs"]\n`);
  fs.writeFileSync(path.join(root, 'broker.mjs'), `
import fs from 'node:fs';
import readline from 'node:readline';
import net from 'node:net';
if(process.getuid()!==10001 || fs.existsSync('/source') || fs.existsSync('/var/run/docker.sock')) throw new Error('boundary invalid');
if(fs.readFileSync('/home/reviewer/.grok/dummy-auth','utf8')!=='fixture-only')throw new Error('dummy auth missing');
try{fs.writeFileSync('/home/reviewer/.grok/attempt','must fail');throw new Error('auth writable');}catch(e){if(e.code!=='EROFS')throw e;}
for(const authority of ['github.com:443','127.0.0.1:443'])await new Promise((resolve,reject)=>{
 const socket=net.connect(3128,'grok-egress',()=>socket.write('CONNECT '+authority+' HTTP/1.1\\r\\nHost: '+authority+'\\r\\n\\r\\n'));
 let bytes=0;socket.on('data',chunk=>bytes+=chunk.length);socket.on('error',()=>{});
 socket.setTimeout(3000,()=>{socket.destroy();reject(new Error('proxy did not reject'));});
 socket.on('close',()=>bytes?reject(new Error('proxy allowed forbidden destination')):resolve());
});
const model=process.argv[process.argv.indexOf('--model')+1];
console.log(JSON.stringify({version:1,state:'preflight_ready',provider:'grok',authMethod:'oidc_cached',sourceCommit:'${GROK_SOURCE}',sourceRevision:'${GROK_SOURCE_REVISION}',tools:[],hostedTools:[],mcpServers:[],clientReportedModel:model}));
if(!process.argv.includes('--check')){
const input=readline.createInterface({input:process.stdin});
input.once('line',line=>{
 const request=JSON.parse(line);
 if(Object.keys(request).sort().join(',')!=='files,instruction,version')throw new Error('binding leaked');
 if(model==='fixture-hang')return;
 const result={summary:'INERT DOCKER GROK: no provider inference.',notes:[]};
 if(model==='fixture-invalid')result.notes=[{path:'outside.mjs',line:1,kind:'hardening',message:'inert',recommendation:'inert'}];
 console.log(JSON.stringify({version:1,state:'result',provider:'grok',clientReportedModel:model,result}));
 input.close();process.stdin.destroy();
});}
`);
  const build = spawnSync('docker', ['build', '--network', 'none', '-t', fixture, root], { encoding: 'utf8', timeout: 30_000, maxBuffer: 65536 });
  assert.equal(build.status, 0, build.stderr);
  const image = await grokDockerControl(['image', 'inspect', fixture, '--format', '{{.Id}}']);
  await grokDockerControl(['volume', 'create', '--label', `${GROK_DOCKER_LABEL}=auth-v1`, volume]);
  await grokDockerControl(['run', '--rm', '--pull=never', '--network', 'none', '--user', '0:0', '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--security-opt', 'no-new-privileges', '--read-only',
    '--mount', `type=volume,src=${volume},dst=/auth`, '--entrypoint', '/usr/local/bin/node', REVIEW_IMAGE,
    '-e', 'const fs=require("node:fs");fs.writeFileSync("/auth/dummy-auth","fixture-only",{mode:0o600});fs.chownSync("/auth/dummy-auth",10001,10001);fs.chownSync("/auth",10001,10001);']);
  // Fixture-only translation ensures the real authentication volume is never touched.
  const control = (args, options) => grokDockerControl(args.map((arg) => arg === GROK_AUTH_VOLUME ? volume : arg.replace(`src=${GROK_AUTH_VOLUME},`, `src=${volume},`)), options);
  const resources = [];
  const prepare = async (options) => {
    const runtime = await prepareGrokDocker({ ...options, control, receipt: { image } });
    resources.push(runtime.resources);
    const spec = JSON.parse(await grokDockerControl(['inspect', runtime.resources.worker, '--format', '{{json .}}']));
    assert.equal(spec.Config.User, '10001:10001');
    assert.equal(spec.HostConfig.ReadonlyRootfs, true);
    assert.equal(spec.HostConfig.Privileged, false);
    assert.deepEqual(spec.HostConfig.PortBindings, {});
    assert.deepEqual(spec.HostConfig.CapDrop, ['ALL']);
    assert.equal(spec.Mounts.length, 1);
    assert.equal(spec.Mounts[0].Name, volume);
    assert.equal(spec.Mounts[0].RW, false);
    assert.equal(await grokDockerControl(['network', 'inspect', runtime.resources.network, '--format', '{{.Internal}}']), 'true');
    return runtime;
  };
  fs.writeFileSync(path.join(root, 'sample.mjs'), 'export const inert = 1;\n');
  for (const model of ['fixture-valid', 'fixture-invalid']) {
    const out = path.join(root, model);
    const run = () => staticCliReview({ repo: root, out, files: ['sample.mjs'], provider: 'grok-docker', model }, { adapter: createGrokDockerAdapter({ model, prepare }), deadlineMs: 20_000 });
    if (model === 'fixture-invalid') {
      await assert.rejects(run(), /native_protocol_rejected/);
      assert.equal(fs.existsSync(path.join(out, 'report.json')), false);
    } else {
      const status = await run();
      assert.equal(status.state, 'collected');
      assert.equal(status.profile, 'grok-docker');
      assert.equal(status.brokerIdentity.isolation, 'docker');
      assert.equal(JSON.parse(fs.readFileSync(path.join(out, 'relay-state.json'))).socketRemoved, true);
    }
  }
  const model = 'fixture-hang', controller = new AbortController();
  const adapter = createGrokDockerAdapter({ model, prepare });
  await assert.rejects(adapter.withSession(async () => {
    controller.abort();
    throw new Error('fixture cancel');
  }, { signal: controller.signal }), /fixture cancel|connector_cancelled|native_request_rejected/);
  for (const resource of resources) {
    for (const name of [resource.worker, resource.proxy]) assert.notEqual(spawnSync('docker', ['inspect', name], { stdio: 'ignore' }).status, 0);
    for (const name of [resource.network, resource.external]) assert.notEqual(spawnSync('docker', ['network', 'inspect', name], { stdio: 'ignore' }).status, 0);
  }
});
