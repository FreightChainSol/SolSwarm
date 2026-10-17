import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { MODEL_CLIS, checkModelCli, checkAllModelClis } from './model-cli-status.mjs';
import { connectorFixture } from './connector-fixtures.mjs';

test('all-provider diagnostics separate absence, profile support and authenticated readiness', async (t) => {
  const f = connectorFixture(t, { requiredUser: 'fixture-operator' });
  const bin = path.join(f.root, 'bin');
  fs.mkdirSync(bin);
  const calls = path.join(f.root, 'version-calls.jsonl');
  for (const name of ['claude', 'codex', 'grok', 'agy']) fs.writeFileSync(path.join(bin, name), `#!${process.execPath}\nimport fs from 'node:fs';\nfs.appendFileSync(${JSON.stringify(calls)},JSON.stringify({args:process.argv.slice(2),cwd:process.cwd(),keys:Object.keys(process.env)})+'\\n');\nif(process.argv.slice(2).join(' ')!=='--version') throw new Error('unsupported diagnostic operation');\nconsole.log('fixture-cli 1.2.3');\n`, { mode: 0o755 });
  const result = await checkAllModelClis({ environment: { HOME: f.root, USER: 'fixture-operator', PATH: bin, ANTHROPIC_API_KEY: 'dummy', NODE_OPTIONS: '--invalid' }, adapter: f.adapter });
  assert.equal(result.state, 'diagnostics');
  assert.deepEqual(result.providers.map((p) => p.provider), MODEL_CLIS);
  assert.equal(result.providers[0].state, 'ready');
  assert.equal(result.providers[0].supported, true);
  for (const status of result.providers.slice(1, 4)) {
    assert.equal(status.state, 'blocked');
    assert.equal(status.supported, false);
    assert.equal(status.reason, 'provider_tool_free_mode_unverified');
    assert.equal(status.authStatus, 'not_checked');
    assert.equal(status.cliVersion, '1.2.3');
  }
  for (const status of result.providers.slice(4)) assert.equal(status.state, 'unavailable');
  const probes = fs.readFileSync(calls, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(probes.length, 3);
  assert.ok(probes.every((p) => p.args.join(' ') === '--version' && !p.keys.includes('NODE_OPTIONS') && !p.keys.includes('ANTHROPIC_API_KEY') && !fs.existsSync(p.cwd)));
  assert.ok(!fs.readFileSync(f.log, 'utf8').includes('--print'));
});
test('unknown providers and pre-aborted diagnostics are rejected', async () => {
  await assert.rejects(checkModelCli('../arbitrary'), /provider_unknown/);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(checkModelCli('claude', { signal: controller.signal }), /connector_cancelled/);
});
test('missing CLIs report unavailable without any authentication attempt', async (t) => {
  const f = connectorFixture(t);
  const result = await checkModelCli('claude', { environment: { PATH: f.root }, adapter: { withSession: () => assert.fail('must not authenticate') } });
  assert.equal(result.state, 'unavailable');
  assert.equal(result.supported, true);
  assert.equal(result.available, false);
});
test('cancelled version probes reap their process and remove the private cwd', async (t) => {
  const f = connectorFixture(t);
  const cwdFile = path.join(f.root, 'probe-cwd.txt');
  fs.writeFileSync(path.join(f.root, 'grok'), `#!${process.execPath}\nimport fs from 'node:fs';\nfs.writeFileSync(${JSON.stringify(cwdFile)},process.cwd());\nsetInterval(()=>{},1000);\n`, { mode: 0o755 });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 250);
  try { await assert.rejects(checkModelCli('grok', { environment: { PATH: f.root }, signal: controller.signal }), /connector_cancelled/); } finally { clearTimeout(timer); }
  if (fs.existsSync(cwdFile)) assert.equal(fs.existsSync(fs.readFileSync(cwdFile, 'utf8')), false);
});
test('oversized version output is bounded and never treated as a verified version', async (t) => {
  const f = connectorFixture(t);
  fs.writeFileSync(path.join(f.root, 'grok'), `#!${process.execPath}\nprocess.stdout.write('1.2.3 '+'x'.repeat(65536));\n`, { mode: 0o755 });
  const result = await checkModelCli('grok', { environment: { PATH: f.root } });
  assert.equal(result.state, 'blocked');
  assert.equal(result.cliVersion, null);
  assert.equal(result.authStatus, 'not_checked');
});
