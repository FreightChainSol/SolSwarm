import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { REVIEW_IMAGE, createSnapshot, disposeSnapshot } from './worker-isolation.mjs';
import { buildExistingTestCatalog } from './review-workflow.mjs';
import { callBridgeTool, resolveDockerBin } from './docker-mcp-bridge.mjs';
import { holdSandbox, probeSandbox } from './sandbox-lifecycle.mjs';
const scripts = path.dirname(fileURLToPath(import.meta.url));
const dockerBin = resolveDockerBin();
const docker = args => {
  const result = spawnSync(dockerBin, args, { encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, `Docker control ${args[0]}: ${result.stderr}`);
  return result.stdout.trim();
};

test('real Docker enforces offline existing tests, manifest binding and unlimited review hold', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'source-review-docker-'));
  const source = path.join(root, 'source');
  fs.mkdirSync(source, { mode: 0o755 });
  fs.writeFileSync(path.join(source, 'package.json'), JSON.stringify({ scripts: { test: 'node --test existing.test.cjs' } }));
  fs.writeFileSync(path.join(source, 'existing.test.cjs'), "const fs=require('node:fs'),test=require('node:test');test('inert existing test',async()=>{fs.mkdirSync('/tmp/test-active');try{await new Promise(r=>setTimeout(r,300));fs.appendFileSync('/tmp/test-runs','ran\\n')}finally{fs.rmdirSync('/tmp/test-active')}});\n");
  fs.writeFileSync(path.join(source, 'test.sh'), '#!/bin/sh\ntouch /out/target-script-ran\n');
  const snapshot = createSnapshot(source);
  const catalog = buildExistingTestCatalog(snapshot.snapshot, snapshot.manifest);
  disposeSnapshot(snapshot);
  fs.mkdirSync(path.join(root, 'harness'));
  fs.writeFileSync(path.join(root, 'harness/existing-tests.json'), JSON.stringify(catalog));
  const containers = [];
  const label = crypto.randomUUID();
  t.after(() => {
    for (const container of containers) {
      const owner = docker(['inspect', '--format', '{{index .Config.Labels "freightchain.review.fixture"}}', container]);
      assert.equal(owner, label);
      docker(['rm', '--force', container]);
    }
    fs.rmSync(root, { recursive: true, force: true });
  });
  const start = network => {
    const container = `source-review-${crypto.randomUUID()}`;
    const args = ['run', '--detach', '--pull=never', '--name', container, '--label', `freightchain.review.fixture=${label}`, '--network', network, '--user', '10001:10001', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '128', '--memory', '256m', '--tmpfs', '/tmp:mode=1777', '--tmpfs', '/work:mode=1777', '--tmpfs', '/out:mode=1777', '--mount', `type=bind,src=${source},dst=/src,readonly`, '--env', 'SANDBOX_REVIEW_ONLY=1', '--env', 'SANDBOX_BUDGET_MS=1000', '--env', 'SANDBOX_HOLD=1'];
    for (const file of ['sandbox-inside.mjs', 'sandbox-lib.mjs']) args.push('--mount', `type=bind,src=${path.join(scripts, file)},dst=/opt/audit/${file},readonly`);
    docker([...args, REVIEW_IMAGE, 'node', '/opt/audit/sandbox-inside.mjs']);
    containers.push(container);
    return container;
  };
  const offline = start('none');
  let ready = false;
  for (let i = 0; i < 100; i++) {
    const state = docker(['exec', offline, 'node', '-e', "const fs=require('node:fs');process.stdout.write(fs.existsSync('/out/checks.done')?'ready':'pending')"]);
    if (state === 'ready') { ready = true; break; }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.equal(ready, true);
  const rows = JSON.parse(docker(['exec', offline, 'node', '-e', "process.stdout.write(require('node:fs').readFileSync('/out/results.json','utf8'))"]));
  assert.ok(rows.checks.some(row => row.id === 'test-sh' && row.result === 'impossible' && row.detail.includes('Source security review')));
  await new Promise(resolve => setTimeout(resolve, 1300));
  assert.equal(docker(['inspect', '--format', '{{.State.Running}}', offline]), 'true', 'preparation budget must not terminate a held review');
  assert.equal(docker(['exec', offline, 'node', '-e', "process.stdout.write(String(require('node:fs').existsSync('/out/target-script-ran')))"]), 'false');
  const entry = catalog.tests.find(row => row.kind === 'npm');
  const ctx = { dockerBin, container: offline, reportDir: root, role: 'auditor', auditor: 'claude-s1-auth' };
  const results = await Promise.all([
    callBridgeTool(ctx, 'run_existing_tests', { test_id: entry.id }),
    callBridgeTool({ ...ctx, auditor: 'grok-s2-input' }, 'run_existing_tests', { test_id: entry.id }),
  ]);
  assert.ok(results.every(result => /exit code: 0/.test(result)), results.join('\n'));
  assert.equal(docker(['exec', offline, 'cat', '/tmp/test-runs']), 'ran\nran');
  docker(['exec', offline, 'node', '-e', "require('node:fs').appendFileSync('/work/src/package.json',' ')"]);
  assert.match(await callBridgeTool(ctx, 'run_existing_tests', { test_id: entry.id }), /Existing test manifest changed/);
  assert.equal(docker(['exec', offline, 'cat', '/tmp/test-runs']), 'ran\nran');
  const connected = start('bridge');
  await assert.rejects(callBridgeTool({ ...ctx, container: connected }, 'run_existing_tests', { test_id: entry.id }), /network-disconnected/);
  const lifecycle = [];
  let probes = 0;
  const released = await holdSandbox({
    held: () => probes < 5,
    probe: async () => ++probes === 1 ? { state: 'unavailable' } : probeSandbox(dockerBin, offline),
    record: status => lifecycle.push(status),
    wait: async () => { if (probes === 2) docker(['stop', offline]); },
  });
  assert.equal(released, false);
  assert.deepEqual(lifecycle.map(row => row.state), ['unavailable', 'running', 'stopped', 'lost']);
  assert.equal(lifecycle.at(-1).reason, 'container_stopped');
});
