import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import test from 'node:test';
import { localTerminalReview } from './terminal-local-review.mjs';
import { backendStatus, REVIEW_IMAGE } from './worker-isolation.mjs';

const client = fileURLToPath(new URL('./terminal-review-client.mjs', import.meta.url));
assert.equal(spawnSync('docker', ['info', '--format', '{{.ServerVersion}}'], { stdio: 'ignore', timeout: 10_000 }).status, 0, 'Docker is required for this explicit inert test');
assert.equal(spawnSync('docker', ['image', 'inspect', REVIEW_IMAGE], { stdio: 'ignore', timeout: 10_000 }).status, 0, 'the pinned runtime must be cached; no pull is performed');
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'terminal-relay-e2e-'));
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(root, 'src/label.mjs'), 'export function label(value) {\n  return String(value).trim();\n}\n');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { repo: root, files: ['src/label.mjs'], out: path.join(root, 'review') };
}
async function terminal(operation, socketPath, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [client, operation, '--socket', socketPath], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('terminal client deadline')); }, 10_000);
    child.stdout.on('data', (chunk) => { stdout += chunk; if (stdout.length > 512 * 1024) child.kill('SIGKILL'); });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) { reject(new Error(`terminal client failed (${code}): ${stderr}`)); return; }
      try { resolve(JSON.parse(stdout)); } catch (err) { reject(err); }
    });
    child.stdin.end(input ? JSON.stringify(input) : '');
  });
}
function cleaned(journal) {
  assert.equal(journal.cleanup.state, 'removed');
  assert.equal(spawnSync('docker', ['inspect', journal.resources.worker], { stdio: 'ignore' }).status, 1);
  assert.equal(spawnSync('docker', ['inspect', journal.resources.collector], { stdio: 'ignore' }).status, 1);
  assert.equal(spawnSync('docker', ['volume', 'inspect', journal.resources.volume], { stdio: 'ignore' }).status, 1);
}

test('inert source travels Docker → real terminal client → private Docker output → parent collection', async (t) => {
  const options = fixture(t);
  const controller = new AbortController();
  let terminalRun;
  let socketPath;
  let seen;
  const outcome = await localTerminalReview(options, {
    signal: controller.signal, deadlineMs: 15_000,
    onReady: (info) => {
      socketPath = info.socketPath;
      terminalRun = (async () => {
        const claimed = await terminal('claim', socketPath);
        seen = claimed.request;
        assert.equal(seen.files[0].path, 'src/label.mjs');
        assert.match(seen.files[0].code, /String\(value\)\.trim/);
        const result = { summary: 'SIMULATED TERMINAL RESPONDER: inert transport test, no model inference.', notes: [{ path: 'src/label.mjs', line: 2, kind: 'maintainability', message: 'String conversion and trimming are explicit.', recommendation: 'Document how null and undefined are represented.' }] };
        await terminal('submit', socketPath, { version: 1, method: 'review.submit', requestId: seen.requestId, jobId: seen.jobId, sourceDigest: seen.sourceDigest, claimId: claimed.claimId, result });
      })();
      terminalRun.catch(() => controller.abort());
    },
  });
  await terminalRun;
  assert.equal(outcome.ledger.job.state, 'collected');
  assert.equal(outcome.ledger.boundary.network, 'none');
  assert.equal(outcome.ledger.boundary.user, '10001:10001');
  assert.ok(!outcome.ledger.boundary.mounts.some((m) => m.destination.includes('socket') || m.destination.includes('parent')));
  const report = JSON.parse(fs.readFileSync(path.join(options.out, 'report.json')));
  assert.equal(report.sourceDigest, seen.sourceDigest);
  assert.equal(report.origin, 'terminal_supplied_unverified');
  assert.equal(report.modelIdentity, 'unverified');
  assert.equal(report.toolsDisabled, 'unverified');
  assert.match(report.result.summary, /SIMULATED TERMINAL RESPONDER/);
  assert.equal(backendStatus('codex').state, 'blocked');
  assert.equal(backendStatus('claude').state, 'blocked');
  assert.equal(fs.existsSync(socketPath), false);
  const relayState = JSON.parse(fs.readFileSync(path.join(options.out, 'relay-state.json')));
  assert.equal(relayState.socketRemoved, true);
  assert.equal(relayState.sourceRemoved, true);
  cleaned(outcome.ledger);
});

test('cancelling an awaiting user-terminal job removes the socket and owned resources', async (t) => {
  const options = fixture(t);
  const controller = new AbortController();
  let socketPath;
  await assert.rejects(localTerminalReview(options, { signal: controller.signal, deadlineMs: 10_000, onReady: (info) => { socketPath = info.socketPath; controller.abort(); } }));
  assert.equal(fs.existsSync(socketPath), false);
  assert.equal(fs.existsSync(path.join(options.out, 'report.json')), false);
  const journal = JSON.parse(fs.readFileSync(path.join(options.out, 'journal/ledger.json')));
  assert.equal(journal.job.state, 'cancelled');
  cleaned(journal);
});

test('no terminal response produces a bounded incomplete result, never a fabricated review', async (t) => {
  const options = fixture(t);
  let socketPath;
  await assert.rejects(localTerminalReview(options, { deadlineMs: 2000, onReady: (info) => { socketPath = info.socketPath; } }));
  assert.equal(fs.existsSync(path.join(options.out, 'report.json')), false);
  if (socketPath) assert.equal(fs.existsSync(socketPath), false);
  const journal = JSON.parse(fs.readFileSync(path.join(options.out, 'journal/ledger.json')));
  assert.equal(journal.job.state, 'timed_out');
  cleaned(journal);
});
