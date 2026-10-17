import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { allowedGrokDestination, publicV4 } from './grok-docker-egress.mjs';
import { grokContainerArgs, prepareGrokDocker, createGrokDockerAdapter, readGrokDockerReceipt, GROK_AUTH_VOLUME } from './model-cli-grok-docker.mjs';
import { GROK_SOURCE, GROK_SOURCE_REVISION } from './model-cli-grok-native.mjs';
import { grokFixture } from './grok-native-fixtures.mjs';
import { REVIEW_PROFILES } from './model-cli-profile.mjs';
import { parseStaticReview } from './static-cli-review.mjs';

const image = `sha256:${'a'.repeat(64)}`;
test('Grok Docker egress permits only fixed provider HTTPS hosts and public IPv4', () => {
  for (const host of ['cli-chat-proxy.grok.com:443', 'auth.x.ai:443']) assert.equal(allowedGrokDestination(host), true);
  for (const host of ['api.x.ai:443', 'github.com:443', 'auth.x.ai:80', 'auth.x.ai.evil.test:443', '127.0.0.1:443', 'auth.x.ai:443@evil', 'AUTH.X.AI:443']) assert.equal(allowedGrokDestination(host), false);
  for (const ip of ['127.0.0.1', '10.1.2.3', '169.254.169.254', '172.16.1.1', '192.168.1.1', '100.64.0.1', '198.18.0.1', '0.0.0.0', '::1', 'fe80::1', 'not-an-ip']) assert.equal(publicV4(ip), false);
  assert.equal(publicV4('1.1.1.1'), true);
});
test('Grok Docker container has no host credentials, source, socket, privilege or published port', () => {
  const args = grokContainerArgs({ image, name: 'fixture-client', label: 'fixture', network: 'fixture-internal' });
  assert.ok(args.includes('--read-only'));
  assert.ok(args.includes('10001:10001'));
  assert.ok(args.includes('no-new-privileges'));
  assert.ok(args.includes(`type=volume,src=${GROK_AUTH_VOLUME},dst=/home/reviewer/.grok,readonly`));
  assert.ok(!args.some((arg) => /type=bind|docker.sock|privileged|--publish|host.docker.internal/.test(arg)));
  const login = grokContainerArgs({ image, name: 'fixture-login', label: 'fixture', network: 'fixture-internal', login: true });
  assert.ok(login.includes(`type=volume,src=${GROK_AUTH_VOLUME},dst=/home/reviewer/.grok`));
  assert.throws(() => grokContainerArgs({ image: 'mutable:tag', name: 'fixture', label: 'fixture', network: 'fixture' }));
  assert.throws(() => grokContainerArgs({ image, name: 'fixture', label: 'fixture', network: 'fixture', volume: '/host/home' }));
});
test('Grok Docker image receipts reject stale inputs, untested images and linked files', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fc-grok-docker-receipt-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'runtime.json');
  const identity = { packageDigest: 'package', recipeDigest: 'recipe' };
  const good = { version: 1, sourceCommit: GROK_SOURCE, sourceRevision: GROK_SOURCE_REVISION, ...identity, image, nativeTests: 'passed' };
  const write = (value) => fs.writeFileSync(file, JSON.stringify(value), { mode: 0o600 });
  write(good);
  assert.deepEqual(readGrokDockerReceipt(file, identity), good);
  for (const patch of [{ recipeDigest: 'stale' }, { nativeTests: 'skipped' }, { image: 'mutable:tag' }, { sourceRevision: 'installed-cli' }]) {
    write({ ...good, ...patch }); assert.throws(() => readGrokDockerReceipt(file, identity));
  }
  write(good);
  const link = path.join(dir, 'link.json'); fs.symlinkSync(file, link);
  assert.throws(() => readGrokDockerReceipt(link, identity));
});
test('Grok Docker provisions private networks, fixed proxy, read-only auth and labelled cleanup', async () => {
  const calls = [];
  const control = async (args) => {
    calls.push(args);
    if (args[0] === 'image') return JSON.stringify({ Id: image, Config: { Labels: { 'freightchain.grok.source': GROK_SOURCE } } });
    if (args[0] === 'volume') return 'auth-v1';
    if (args.includes('inspect')) return calls.find((call) => call[0] === 'network' && call[1] === 'create').find((arg) => arg.startsWith('freightchain.grok.isolated=')).split('=')[1];
    return '';
  };
  const runtime = await prepareGrokDocker({ model: 'grok-4.7', control, receipt: { image } });
  assert.equal(runtime.executable, 'docker');
  assert.deepEqual(runtime.args.slice(0, 3), ['start', '--attach', '--interactive']);
  const network = calls.find((args) => args[0] === 'network' && args[1] === 'create');
  assert.ok(network.includes('--internal'));
  const create = calls.find((args) => args[0] === 'create');
  assert.ok(create.includes(`type=volume,src=${GROK_AUTH_VOLUME},dst=/home/reviewer/.grok,readonly`));
  assert.ok(!create.some((arg) => arg.startsWith('type=bind')));
  const proxy = calls.find((args) => args[0] === 'run');
  const mount = proxy.find((arg) => arg.startsWith('type=bind'));
  const staged = mount.slice('type=bind,src='.length).split(',dst=')[0];
  assert.ok(fs.existsSync(staged));
  await runtime.cleanup();
  assert.equal(JSON.parse(fs.readFileSync(runtime.identity.journal)).cleanup.state, 'removed');
  assert.equal(fs.existsSync(staged), false);
  assert.equal(calls.filter((args) => args[0] === 'rm').length, 2);
  assert.equal(calls.filter((args) => args[0] === 'network' && args[1] === 'rm').length, 2);
});
test('Grok Docker refuses unprepared or foreign auth before provisioning a job', async () => {
  let calls = 0;
  await assert.rejects(prepareGrokDocker({ model: '--invalid', control: () => { calls++; } }), /requested_model_rejected/);
  assert.equal(calls, 0);
  const control = async (args) => args[0] === 'image' ? JSON.stringify({ Id: image, Config: { Labels: { 'freightchain.grok.source': GROK_SOURCE } } }) : 'foreign';
  await assert.rejects(prepareGrokDocker({ control, receipt: { image } }), /grok_docker_auth_volume_rejected/);
});
test('Grok Docker retains cleanup failures and a journal write failure cannot prevent teardown', async (t) => {
  for (const failJournal of [false, true]) {
    let label;
    const removed = [];
    const control = async (args) => {
      if (args[0] === 'image') return JSON.stringify({ Id: image, Config: { Labels: { 'freightchain.grok.source': GROK_SOURCE } } });
      if (args[0] === 'volume') return 'auth-v1';
      if (args[0] === 'network' && args[1] === 'create') label = args.find((arg) => arg.startsWith('freightchain.grok.isolated=')).split('=')[1];
      if (args.includes('inspect')) return label;
      if (args[0] === 'rm' || args[0] === 'network' && args[1] === 'rm') {
        removed.push(args.at(-1));
        if (!failJournal && removed.length === 1) throw new Error('fixture daemon failure');
      }
      return '';
    };
    const runtime = await prepareGrokDocker({ control, receipt: { image } });
    let protectedFile;
    if (failJournal) {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fc-grok-journal-fault-'));
      t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
      protectedFile = path.join(dir, 'dummy.txt'); fs.writeFileSync(protectedFile, 'untouched');
      fs.unlinkSync(runtime.identity.journal); fs.symlinkSync(protectedFile, runtime.identity.journal);
      t.after(() => fs.unlinkSync(runtime.identity.journal));
    }
    await assert.rejects(runtime.cleanup(), failJournal ? /grok_docker_journal_unverified/ : /grok_docker_cleanup_unverified/);
    assert.equal(removed.length, 4);
    if (failJournal) assert.equal(fs.readFileSync(protectedFile, 'utf8'), 'untouched');
    else {
      const ledger = JSON.parse(fs.readFileSync(runtime.identity.journal));
      assert.equal(ledger.cleanup.state, 'failed');
      assert.deepEqual(ledger.cleanup.resources, [runtime.resources.worker]);
    }
  }
});
test('Grok Docker uses the same strict native protocol and cleans its runtime on success or refusal', async (t) => {
  for (const invalid of [false, true]) {
    const f = grokFixture(t, { invalid });
    let cleaned = 0;
    const adapter = createGrokDockerAdapter({ model: 'fixture-requested-model', prepare: async () => ({ executable: f.grokExecutable, identity: { isolation: 'docker' }, cleanup: async () => { cleaned++; } }) });
    const review = () => adapter.withSession((session) => session.review(f.request, 'fixture-requested-model'));
    if (invalid) await assert.rejects(review(), /native_protocol_rejected/);
    else assert.match((await review()).review.summary, /FAKE GROK/);
    assert.equal(cleaned, 1);
  }
  assert.ok(REVIEW_PROFILES.includes('grok-docker'));
  assert.equal(parseStaticReview(['--repo', '/fixture', '--out', '/unused', '--file', 'sample.mjs', '--provider', 'grok-docker', '--model', 'grok-4.7']).provider, 'grok-docker');
});
