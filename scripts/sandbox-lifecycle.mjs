import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// An unavailable Docker daemon is not evidence that its container stopped.
export function probeSandbox(dockerBin, container) {
  return new Promise(resolve => {
    const child = spawn(dockerBin, ['inspect', '--format', '{{json .State}}', container], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '', finished = false;
    const finish = value => { if (!finished) { finished = true; clearTimeout(timer); resolve(value); } };
    const timer = setTimeout(() => { child.kill('SIGKILL'); finish({ state: 'unavailable' }); }, 8000);
    child.stdout.on('data', data => { stdout = (stdout + data).slice(-65536); });
    child.stderr.on('data', data => { stderr = (stderr + data).slice(-65536); });
    child.once('error', () => finish({ state: 'unavailable' }));
    child.once('close', code => {
      if (code !== 0) { finish({ state: /No such (?:object|container):/i.test(stderr) ? 'missing' : 'unavailable' }); return; }
      try {
        const value = JSON.parse(stdout);
        if (value.Running === true) finish({ state: 'running' });
        else if (value.Running === false) finish({ state: 'stopped', exitCode: Number.isInteger(value.ExitCode) ? value.ExitCode : null, oomKilled: value.OOMKilled === true });
        else finish({ state: 'unavailable' });
      } catch { finish({ state: 'unavailable' }); }
    });
  });
}

export async function holdSandbox({ probe, held, record, wait = () => new Promise(resolve => setTimeout(resolve, 1000)) }) {
  let missing = 0, previous;
  while (held()) {
    const status = await probe();
    // A release during a slow status request is still an intentional release.
    if (!held()) break;
    const encoded = JSON.stringify(status);
    if (encoded !== previous) { record(status); previous = encoded; }
    missing = status.state === 'missing' ? missing + 1 : 0;
    if (status.state === 'stopped' || missing >= 3) {
      record({ ...status, state: 'lost', reason: status.state === 'stopped' ? 'container_stopped' : 'container_missing' });
      return false;
    }
    await wait();
  }
  record({ state: 'released', reason: 'owner_released' });
  return true;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [container, holdFile, recordFile] = process.argv.slice(2);
  if (!container || !holdFile || !recordFile) throw new Error('Expected container, hold file and lifecycle record');
  const record = status => {
    const temporary = `${recordFile}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify({ ...status, at: new Date().toISOString() }) + '\n', { mode: 0o600 });
    fs.renameSync(temporary, recordFile);
  };
  await holdSandbox({ probe: () => probeSandbox('docker', container), held: () => fs.existsSync(holdFile), record });
}
