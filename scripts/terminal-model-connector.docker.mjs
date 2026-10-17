import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import test from 'node:test';
import { localTerminalReview } from './terminal-local-review.mjs';
import { connectorFixture } from './connector-fixtures.mjs';
import { REVIEW_IMAGE, backendStatus } from './worker-isolation.mjs';

const connector = fileURLToPath(new URL('./terminal-model-connector.mjs', import.meta.url));
assert.equal(spawnSync('docker', ['info', '--format', '{{.ServerVersion}}'], { stdio: 'ignore', timeout: 10_000 }).status, 0);
assert.equal(spawnSync('docker', ['image', 'inspect', REVIEW_IMAGE], { stdio: 'ignore', timeout: 10_000 }).status, 0);

test('automatic connector completes Docker → fake tool-free CLI → Docker collection without manual copying', async (t) => {
  const f = connectorFixture(t);
  const bin = path.join(f.root, 'bin');
  fs.mkdirSync(bin);
  fs.copyFileSync(path.join(f.root, 'fake-claude'), path.join(bin, 'claude'));
  fs.chmodSync(path.join(bin, 'claude'), 0o755);
  const out = path.join(f.root, 'review');
  const controller = new AbortController();
  let connected;
  let socket;
  const outcome = await localTerminalReview({ repo: f.root, files: ['src/label.mjs'], out }, {
    signal: controller.signal, deadlineMs: 20_000,
    onReady: ({ socketPath }) => {
      socket = socketPath;
      connected = new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [connector, 'connect', '--provider', 'claude', '--model', 'fake-requested-model', '--socket', socketPath], {
          env: { HOME: f.root, PATH: `${bin}${path.delimiter}${process.env.PATH}` },
          stdio: ['ignore', 'pipe', 'pipe'],
        });
        let stdout = '';
        let stderr = '';
        const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('mock connector deadline')); }, 10_000);
        child.stdout.on('data', (chunk) => { stdout += chunk; });
        child.stderr.on('data', (chunk) => { stderr += chunk; });
        child.on('error', reject);
        child.on('close', (code) => {
          clearTimeout(timer);
          if (code !== 0) { reject(new Error(`mock connector failed: ${stderr}`)); return; }
          try { resolve(JSON.parse(stdout)); } catch (err) { reject(err); }
        });
      });
      connected.catch(() => controller.abort());
    },
  });
  const status = await connected;
  assert.equal(status.state, 'submitted');
  assert.equal(status.cliReportedModel, 'fixture-model-not-live');
  assert.equal(status.requestedModel, 'fake-requested-model');
  const report = JSON.parse(fs.readFileSync(path.join(out, 'report.json')));
  assert.match(report.result.summary, /FAKE CLI/);
  assert.equal(report.origin, 'terminal_supplied_unverified');
  assert.equal(report.modelIdentity, 'unverified');
  assert.equal(report.executionEvidence, 'not_collected');
  assert.equal(outcome.ledger.boundary.network, 'none');
  assert.equal(outcome.ledger.boundary.user, '10001:10001');
  assert.equal(outcome.ledger.cleanup.state, 'removed');
  assert.equal(fs.existsSync(socket), false);
  for (const name of [outcome.ledger.resources.worker, outcome.ledger.resources.collector]) assert.notEqual(spawnSync('docker', ['inspect', name], { stdio: 'ignore' }).status, 0);
  assert.notEqual(spawnSync('docker', ['volume', 'inspect', outcome.ledger.resources.volume], { stdio: 'ignore' }).status, 0);
  for (const provider of ['claude', 'codex', 'grok', 'agy']) assert.equal(backendStatus(provider).state, 'blocked');
});
