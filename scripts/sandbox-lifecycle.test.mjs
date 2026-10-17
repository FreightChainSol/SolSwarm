import assert from 'node:assert/strict';
import test from 'node:test';
import { holdSandbox } from './sandbox-lifecycle.mjs';

test('transient Docker failures do not release an active review', async () => {
  const statuses = ['running', 'unavailable', 'missing', 'unavailable', 'running'];
  const records = [];
  let held = true;
  const result = await holdSandbox({ held: () => held, probe: async () => ({ state: statuses.shift() }), record: value => records.push(value), wait: async () => { if (!statuses.length) held = false; } });
  assert.equal(result, true);
  assert.ok(!records.some(row => row.state === 'lost'));
  assert.deepEqual(records.at(-1), { state: 'released', reason: 'owner_released' });
});

test('confirmed missing and stopped containers retain the infrastructure failure', async () => {
  for (const state of ['missing', 'stopped']) {
    const records = [];
    let probes = 0;
    const result = await holdSandbox({ held: () => true, probe: async () => { probes++; return { state, exitCode: 137, oomKilled: true }; }, record: value => records.push(value), wait: async () => {} });
    assert.equal(result, false);
    assert.equal(probes, state === 'missing' ? 3 : 1);
    assert.equal(records.at(-1).reason, state === 'missing' ? 'container_missing' : 'container_stopped');
    assert.equal(records.at(-1).oomKilled, true);
  }
});

test('owner release during a slow Docker probe does not become a sandbox failure', async () => {
  let held = true;
  const records = [];
  assert.equal(await holdSandbox({ held: () => held, probe: async () => { held = false; return { state: 'stopped' }; }, record: value => records.push(value) }), true);
  assert.deepEqual(records, [{ state: 'released', reason: 'owner_released' }]);
});
