import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ConnectorError } from './model-cli-claude.mjs';
import { createNativeReviewAdapter } from './model-cli-codex-native.mjs';
import { GROK_SOURCE, GROK_SOURCE_REVISION, DEFAULT_GROK_MODEL } from './model-cli-grok-native.mjs';
import { nativeIdentity } from '../native/grok-review/build.mjs';
import { REVIEW_IMAGE, createSnapshot, disposeSnapshot } from './worker-isolation.mjs';
import { openPrivateOutput } from '../native/codex-review/build.mjs';

export const GROK_AUTH_VOLUME = 'freightchain-grok-isolated-auth-v1';
export const GROK_DOCKER_IMAGE = 'freightchain-grok-review:isolated';
export const GROK_DOCKER_LABEL = 'freightchain.grok.isolated';
const RECEIPT = fileURLToPath(new URL('../native/.cache/grok-docker/runtime.json', import.meta.url));
const HERE = path.dirname(fileURLToPath(import.meta.url));
const SESSIONS = fileURLToPath(new URL('../native/.cache/grok-docker/sessions/', import.meta.url));
const REASONS = new Set(['grok_input_contract_rejected', 'grok_output_contract_rejected', 'grok_configuration_rejected', 'grok_subscription_auth_required', 'grok_runtime_failed', 'grok_execution_event_rejected', 'grok_deadline_exceeded', 'grok_provider_http_400', 'grok_provider_http_401', 'grok_provider_http_403', 'grok_provider_http_404', 'grok_provider_http_409', 'grok_provider_http_413', 'grok_provider_http_422', 'grok_provider_http_429', 'grok_provider_unavailable', 'grok_provider_http_rejected', 'grok_provider_transport_failed', 'grok_provider_protocol_rejected', 'grok_provider_stream_rejected']);

// Docker control configuration belongs to the trusted operator, never to source/model input.
export async function grokDockerControl(args, { signal, timeoutMs = 15_000 } = {}) {
  if (signal?.aborted) throw new ConnectorError('connector_cancelled');
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '', bytes = 0, failed = false;
    const stop = () => { failed = true; child.kill('SIGKILL'); };
    const timer = setTimeout(stop, timeoutMs);
    signal?.addEventListener('abort', stop, { once: true });
    child.stdout.on('data', (chunk) => { bytes += chunk.length; if (bytes > 1024 * 1024) stop(); else output += chunk.toString('utf8'); });
    child.stderr.on('data', (chunk) => { bytes += chunk.length; if (bytes > 1024 * 1024) stop(); });
    child.on('error', () => { failed = true; });
    child.on('close', (code) => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', stop);
      if (failed || code !== 0) reject(new ConnectorError(signal?.aborted ? 'connector_cancelled' : 'grok_docker_control_failed'));
      else resolve(output.trim());
    });
    if (signal?.aborted) stop();
  });
}
export function grokContainerArgs({ image, name, label, network, volume = GROK_AUTH_VOLUME, login = false }) {
  if (!/^sha256:[a-f0-9]{64}$/.test(image) || !/^[a-zA-Z0-9-]+$/.test(name) || !/^[a-zA-Z0-9-]+$/.test(network) || !/^[a-zA-Z0-9-]+$/.test(label) || volume !== GROK_AUTH_VOLUME) throw new ConnectorError('grok_docker_spec_rejected');
  return ['--pull=never', '--name', name, '--label', `${GROK_DOCKER_LABEL}=${label}`, '--network', network,
    '--user', '10001:10001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only',
    '--pids-limit', '64', '--memory', '512m', '--cpus', '1', '--ipc', 'private',
    '--log-driver', 'none', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777',
    '--tmpfs', '/session:rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=700',
    '--workdir', '/session', '--env', 'HOME=/home/reviewer', '--env', 'GROK_HOME=/home/reviewer/.grok',
    '--env', 'HTTPS_PROXY=http://grok-egress:3128', '--env', 'HTTP_PROXY=http://grok-egress:3128',
    '--mount', `type=volume,src=${volume},dst=/home/reviewer/.grok${login ? '' : ',readonly'}`,
  ];
}
export function readGrokDockerReceipt(file = RECEIPT, identity = nativeIdentity()) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== process.getuid() || stat.mode & 0o077 || stat.size > 16384) throw new Error('receipt rejected');
    const receipt = JSON.parse(fs.readFileSync(fd, 'utf8'));
    if (receipt.version !== 1 || receipt.sourceCommit !== GROK_SOURCE || receipt.sourceRevision !== GROK_SOURCE_REVISION
      || receipt.packageDigest !== identity.packageDigest || receipt.recipeDigest !== identity.recipeDigest
      || !/^sha256:[a-f0-9]{64}$/.test(receipt.image) || receipt.nativeTests !== 'passed') throw new Error('receipt stale');
    return receipt;
  } finally { fs.closeSync(fd); }
}
export async function prepareGrokDocker({ model = DEFAULT_GROK_MODEL, checkOnly = false, login = false, signal, control = grokDockerControl, receipt: injectedReceipt } = {}) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(model)) throw new ConnectorError('requested_model_rejected');
  let receipt;
  try { receipt = injectedReceipt || readGrokDockerReceipt(); } catch { throw new ConnectorError('grok_docker_not_prepared'); }
  const label = crypto.randomUUID(), prefix = `fc-grok-${label}`;
  const names = { worker: `${prefix}-client`, proxy: `${prefix}-proxy`, network: `${prefix}-internal`, external: `${prefix}-external` };
  fs.mkdirSync(SESSIONS, { recursive: true, mode: 0o700 });
  const journal = path.join(SESSIONS, `${label}.json`);
  const ledger = { version: 1, profile: 'grok-docker', image: receipt.image, label, resources: names, authVolume: GROK_AUTH_VOLUME, state: 'preparing', cleanup: { state: 'pending' } };
  const save = () => {
    const fd = openPrivateOutput(journal);
    try { fs.writeFileSync(fd, JSON.stringify(ledger, null, 2)); } finally { fs.closeSync(fd); }
  };
  save();
  let snapshot;
  const owned = [];
  const cleanup = async () => {
    const errors = [];
    for (const [type, name] of [...owned].reverse()) {
      try {
        const format = type === 'network' ? '{{index .Labels "freightchain.grok.isolated"}}' : '{{index .Config.Labels "freightchain.grok.isolated"}}';
        const owner = await control([...(type === 'network' ? ['network'] : []), 'inspect', name, '--format', format]);
        if (owner !== label) throw new Error('owner changed');
        await control(type === 'network' ? ['network', 'rm', name] : ['rm', '--force', name]);
      } catch { errors.push(name); }
    }
    owned.length = 0;
    if (snapshot) { try { disposeSnapshot(snapshot); snapshot = null; } catch { errors.push('staged_proxy'); } }
    ledger.cleanup = errors.length ? { state: 'failed', resources: errors } : { state: 'removed' };
    try { save(); } catch { throw new ConnectorError('grok_docker_journal_unverified'); }
    if (errors.length) throw new ConnectorError('grok_docker_cleanup_unverified');
  };
  try {
    const image = JSON.parse(await control(['image', 'inspect', receipt.image, '--format', '{{json .}}'], { signal }));
    if (image.Id !== receipt.image || image.Config?.Labels?.['freightchain.grok.source'] !== GROK_SOURCE) throw new ConnectorError('grok_docker_image_rejected');
    // Never create an anonymous empty volume during inference: require explicit setup/login.
    if (await control(['volume', 'inspect', GROK_AUTH_VOLUME, '--format', '{{index .Labels "freightchain.grok.isolated"}}'], { signal }) !== 'auth-v1') throw new ConnectorError('grok_docker_auth_volume_rejected');
    snapshot = createSnapshot(HERE, { only: ['grok-docker-egress.mjs'] });
    for (const [name, internal] of [[names.network, true], [names.external, false]]) {
      owned.push(['network', name]);
      await control(['network', 'create', ...(internal ? ['--internal'] : []), '--label', `${GROK_DOCKER_LABEL}=${label}`, name], { signal });
    }
    owned.push(['container', names.proxy]);
    await control(['run', '--detach', '--pull=never', '--name', names.proxy, '--label', `${GROK_DOCKER_LABEL}=${label}`, '--network', names.external,
      '--user', '10001:10001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only', '--memory', '128m', '--pids-limit', '32', '--cpus', '0.5', '--log-driver', 'none',
      '--mount', `type=bind,src=${path.join(snapshot.snapshot, 'grok-docker-egress.mjs')},dst=/trusted/proxy.mjs,readonly`,
      '--entrypoint', '/usr/local/bin/node', REVIEW_IMAGE, '/trusted/proxy.mjs'], { signal });
    await control(['network', 'connect', '--alias', 'grok-egress', names.network, names.proxy], { signal });
    owned.push(['container', names.worker]);
    await control(['create', '--interactive', ...grokContainerArgs({ image: receipt.image, name: names.worker, label, network: names.network, login }),
      ...(login ? ['--entrypoint', '/usr/local/bin/grok'] : []), receipt.image,
      ...(login ? ['login', '--device-auth'] : [checkOnly ? '--check' : '--review', '--model', model])], { signal });
    ledger.state = 'provisioned';
    save();
    return { executable: 'docker', args: ['start', '--attach', '--interactive', names.worker], cleanup, resources: names,
      identity: { sourceCommit: GROK_SOURCE, sourceRevision: GROK_SOURCE_REVISION, image: receipt.image, isolation: 'docker', credentials: 'dedicated_docker_volume', egress: 'grok_https_only', journal } };
  } catch (err) {
    try { await cleanup(); } catch (cleanupError) { throw cleanupError; }
    throw err;
  }
}
export function createGrokDockerAdapter({ model = DEFAULT_GROK_MODEL, checkOnly = false, prepare = prepareGrokDocker } = {}) {
  return { async withSession(callback, { signal } = {}) {
    const runtime = await prepare({ model, checkOnly, signal });
    try {
      const adapter = createNativeReviewAdapter({ model, checkOnly }, {
        provider: 'grok', sourceCommit: GROK_SOURCE, sourceRevision: GROK_SOURCE_REVISION, authMethod: 'oidc_cached',
        version: 'public-source-docker', tempPrefix: 'fc-grok-docker-', environmentKeys: [],
        inventories: ['tools', 'hostedTools', 'mcpServers'], allowUnknownModel: true, diagnostics: true,
        admissionError: 'grok_docker_not_prepared', resolveBinary: async () => runtime, reasons: REASONS,
      });
      return await adapter.withSession(callback, { signal });
    } finally { await runtime.cleanup(); }
  } };
}
