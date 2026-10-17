import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { prepare, nativeIdentity, PIN, SOURCE_REVISION } from './build.mjs';
import { openPrivateOutput, runGate } from '../codex-review/build.mjs';
import { REVIEW_IMAGE } from '../../scripts/worker-isolation.mjs';
import { grokDockerControl, GROK_AUTH_VOLUME, GROK_DOCKER_IMAGE, GROK_DOCKER_LABEL, prepareGrokDocker } from '../../scripts/model-cli-grok-docker.mjs';
import { ConnectorError } from '../../scripts/model-cli-claude.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CACHE = path.resolve(HERE, '../.cache/grok-docker');
const SOURCE = path.resolve(HERE, `../.cache/grok-${PIN}`);
const RECEIPT = path.join(CACHE, 'runtime.json');
function privateDirectory(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(dir);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || stat.mode & 0o077) throw new ConnectorError('grok_docker_cache_rejected');
}
export async function setupGrokDocker() {
  privateDirectory(CACHE);
  // Invalidate an old image receipt before preparing changed inputs.
  const invalid = openPrivateOutput(RECEIPT);
  fs.writeFileSync(invalid, '{}'); fs.closeSync(invalid);
  prepare();
  const identity = nativeIdentity();
  // prepare() verifies every tracked change and extra file in this public checkout.
  // Never send the operator's home, login store or target repository to the build.
  const buildRecord = fs.mkdtempSync(path.join(CACHE, 'build-id-'));
  const iidFile = path.join(buildRecord, 'image.txt');
  try {
    const result = await runGate(['docker', 'build', '--progress=plain', '--iidfile', iidFile, '-t', GROK_DOCKER_IMAGE, '-f', path.join(HERE, 'Dockerfile'), SOURCE], process.env, HERE, path.join(CACHE, 'build.log'));
    if (!result.passed) throw new ConnectorError('grok_docker_build_failed');
    if (JSON.stringify(nativeIdentity()) !== JSON.stringify(identity)) throw new ConnectorError('grok_docker_inputs_changed');
    // Bind this exact build result; a concurrent build may move the display tag.
    const fdImage = fs.openSync(iidFile, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    let image;
    try {
      const stat = fs.fstatSync(fdImage);
      if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== process.getuid() || stat.size > 128) throw new ConnectorError('grok_docker_image_rejected');
      image = fs.readFileSync(fdImage, 'utf8').trim();
    } finally { fs.closeSync(fdImage); }
    if (!/^sha256:[a-f0-9]{64}$/.test(image)) throw new ConnectorError('grok_docker_image_rejected');
    const receipt = { version: 1, sourceCommit: PIN, sourceRevision: SOURCE_REVISION, ...identity, image, nativeTests: 'passed' };
    const fd = openPrivateOutput(RECEIPT);
    try { fs.writeFileSync(fd, JSON.stringify(receipt, null, 2)); } finally { fs.closeSync(fd); }
    let volume;
    try { volume = await grokDockerControl(['volume', 'inspect', GROK_AUTH_VOLUME, '--format', '{{index .Labels "freightchain.grok.isolated"}}']); }
    catch {
      await grokDockerControl(['volume', 'create', '--label', `${GROK_DOCKER_LABEL}=auth-v1`, GROK_AUTH_VOLUME]);
      volume = await grokDockerControl(['volume', 'inspect', GROK_AUTH_VOLUME, '--format', '{{index .Labels "freightchain.grok.isolated"}}']);
    }
    if (volume !== 'auth-v1') throw new ConnectorError('grok_docker_auth_volume_rejected');
    await grokDockerControl(['run', '--rm', '--pull=never', '--network', 'none', '--user', '0:0', '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--cap-add', 'FOWNER', '--security-opt', 'no-new-privileges', '--read-only',
      '--mount', `type=volume,src=${GROK_AUTH_VOLUME},dst=/auth`, '--entrypoint', '/usr/local/bin/node', REVIEW_IMAGE,
      '-e', 'const fs=require("node:fs");fs.chownSync("/auth",10001,10001);fs.chmodSync("/auth",0o700);']);
    return { state: 'prepared', profile: 'grok-docker', image, next: './bin/audit grok-docker login' };
  } finally { fs.rmSync(buildRecord, { recursive: true, force: true }); }
}
// Dependency/deadline injection is internal test support, never a CLI option.
export async function loginGrokDocker({ signal, prepareRuntime = prepareGrokDocker, timeoutMs = 5 * 60_000 } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 10 || timeoutMs > 5 * 60_000) throw new ConnectorError('grok_docker_usage');
  if (signal?.aborted) throw new ConnectorError('connector_cancelled');
  const runtime = await prepareRuntime({ login: true, signal });
  try {
    // The official login UI prints only its normal device-flow instructions.
    // No host credential is read, copied, extracted, mounted or passed over stdin.
    await new Promise((resolve, reject) => {
      const child = spawn(runtime.executable, runtime.args, { stdio: 'inherit' });
      let stopped;
      let escalation;
      const stop = () => {
        stopped ||= signal?.aborted ? 'connector_cancelled' : 'grok_docker_login_deadline';
        child.kill('SIGTERM');
        escalation ||= setTimeout(() => child.kill('SIGKILL'), 300);
      };
      const timer = setTimeout(stop, timeoutMs);
      signal?.addEventListener('abort', stop, { once: true });
      child.once('error', () => reject(new ConnectorError('grok_docker_login_failed')));
      child.once('close', (code) => {
        clearTimeout(timer);
        clearTimeout(escalation);
        signal?.removeEventListener('abort', stop);
        if (stopped || signal?.aborted) reject(new ConnectorError(stopped || 'connector_cancelled'));
        else code === 0 ? resolve() : reject(new ConnectorError('grok_docker_login_failed'));
      });
      if (signal?.aborted) stop();
    });
    return { state: 'login_completed', profile: 'grok-docker' };
  } finally { await runtime.cleanup(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const controller = new AbortController();
  const stop = () => { controller.abort(); process.exitCode = 130; };
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  try {
    if (process.argv.length !== 3 || !['setup', 'login'].includes(process.argv[2])) throw new ConnectorError('grok_docker_usage');
    const result = process.argv[2] === 'setup' ? await setupGrokDocker() : await loginGrokDocker({ signal: controller.signal });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (err) {
    process.stderr.write(`${JSON.stringify({ state: 'blocked_or_incomplete', reason: err instanceof ConnectorError ? err.code : 'grok_docker_failed', buildLog: path.join(CACHE, 'build.log') })}\n`);
    if (!process.exitCode) process.exitCode = 2;
  } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
