import assert from 'node:assert/strict';
import test from 'node:test';
import { loginGrokDocker } from '../native/grok-review/docker.mjs';

test('Grok Docker device login timeout cannot be reported as success even if attachment exits zero', async () => {
  let cleaned = 0;
  await assert.rejects(loginGrokDocker({ timeoutMs: 200, prepareRuntime: async () => ({
    executable: process.execPath, args: ['-e', 'process.on("SIGTERM",()=>process.exit(0));setInterval(()=>{},1000);'],
    cleanup: async () => { cleaned++; },
  }) }), /grok_docker_login_deadline/);
  assert.equal(cleaned, 1);
});
test('Grok Docker device login cancellation reaps its runtime and never claims completion', async () => {
  let cleaned = 0;
  const controller = new AbortController();
  const run = loginGrokDocker({ signal: controller.signal, prepareRuntime: async () => ({
    executable: process.execPath, args: ['-e', 'process.on("SIGTERM",()=>process.exit(0));setInterval(()=>{},1000);'],
    cleanup: async () => { cleaned++; },
  }) });
  setTimeout(() => controller.abort(), 150);
  await assert.rejects(run, /connector_cancelled/);
  assert.equal(cleaned, 1);
});
test('Grok Docker official login exit is collected only after successful cleanup', async () => {
  let cleaned = 0;
  const result = await loginGrokDocker({ prepareRuntime: async () => ({
    executable: process.execPath, args: ['-e', 'process.exit(0)'], cleanup: async () => { cleaned++; },
  }) });
  assert.equal(result.state, 'login_completed');
  assert.equal(cleaned, 1);
  await assert.rejects(loginGrokDocker({ prepareRuntime: async () => ({
    executable: process.execPath, args: ['-e', 'process.exit(0)'], cleanup: async () => { throw new Error('fixture cleanup failed'); },
  }) }), /fixture cleanup failed/);
});
