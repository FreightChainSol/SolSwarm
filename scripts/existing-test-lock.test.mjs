import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { withExistingTestLock } from './existing-test-lock.mjs';

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-test-lock-'));
  fs.mkdirSync(path.join(root, 'harness'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

test('separate bridge processes cannot run existing tests concurrently', { timeout: 5000 }, async t => {
  const root = fixture(t);
  const script = `
    import fs from 'node:fs';
    import { withExistingTestLock } from ${JSON.stringify(new URL('./existing-test-lock.mjs', import.meta.url).href)};
    const root = process.argv[1], marker = root + '/active';
    process.send('ready');
    process.once('message', async () => {
      try {
        await withExistingTestLock(root, async () => {
          const fd = fs.openSync(marker, 'wx');
          process.send('running');
          await new Promise(resolve => process.once('message', resolve));
          fs.closeSync(fd); fs.unlinkSync(marker);
        });
        process.disconnect();
      } catch (error) { console.error(error); process.exit(1); }
    });`;
  const children = [0, 1, 2].map(() => spawn(process.execPath, ['--input-type=module', '-e', script, root], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] }));
  t.after(() => children.forEach(child => { if (child.exitCode == null) child.kill('SIGKILL'); }));
  const exits = children.map(child => once(child, 'exit'));
  let active = 0, peak = 0, runs = 0;
  for (const child of children) child.on('message', message => {
    if (message === 'running') {
      active++; peak = Math.max(peak, active); runs++;
      setTimeout(() => { active--; child.send('finish'); }, 50);
    }
  });
  await Promise.all(children.map(child => once(child, 'message')));
  for (const child of children) child.send('start');
  assert.ok((await Promise.all(exits)).every(([code]) => code === 0));
  assert.equal(runs, 3);
  assert.equal(peak, 1);
  assert.equal(fs.existsSync(path.join(root, 'harness/existing-tests.lock')), false);
});

test('failed tests release the lock, while abandoned or invalid locks refuse execution', async t => {
  const root = fixture(t);
  await assert.rejects(withExistingTestLock(root, async () => { throw new Error('test failed'); }), /test failed/);
  assert.equal(await withExistingTestLock(root, async () => 'next test'), 'next test');
  const lock = path.join(root, 'harness/existing-tests.lock');
  fs.mkdirSync(lock);
  await assert.rejects(withExistingTestLock(root, () => assert.fail('must not run'), { waitMs: 0 }), /Existing tests are busy/);
  assert.equal(fs.existsSync(lock), true, 'never remove another bridge lock');
  fs.rmdirSync(lock);
  fs.symlinkSync(root, lock);
  await assert.rejects(withExistingTestLock(root, () => assert.fail('must not run')), /Invalid existing test lock/);
});
