import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

export async function withExistingTestLock(reportDir, run, { waitMs = 300_000 } = {}) {
  if (!Number.isSafeInteger(waitMs) || waitMs < 0) throw new Error('Invalid existing test lock wait');
  const directory = path.join(fs.realpathSync(path.join(reportDir, 'harness')), 'existing-tests.lock');
  const started = performance.now();
  for (;;) {
    try { fs.mkdirSync(directory, { mode: 0o700 }); break; }
    catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const stat = fs.lstatSync(directory, { throwIfNoEntry: false });
      if (stat && (!stat.isDirectory() || stat.isSymbolicLink())) throw new Error('Invalid existing test lock');
      // Never remove another bridge's lock: its Docker test may still be running.
      if (performance.now() - started >= waitMs) throw new Error('Existing tests are busy or a previous bridge lost its test lock; start a new review or resume into a new output directory');
      await delay(100);
    }
  }
  try { return await run(); }
  finally { fs.rmdirSync(directory); }
}
