import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawnSync, spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const PIN = '092d3acd6bec3e3a14bdc7e7a2810ab628ab759d';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const CACHE = path.join(HERE, '../.cache');
const SOURCE = path.join(CACHE, `codex-${PIN}`);
const WORKSPACE = path.join(SOURCE, 'codex-rs');
const PACKAGE = 'freightchain-codex-review';
const UPSTREAM_VERSION = '0.162.1';
const MEMBER = 'freightchain-review';
const FILES = ['Cargo.toml', 'NOTICE', 'review-instruction.txt', 'src/lib.rs', 'src/main.rs', 'src/contract.rs', 'src/policy.rs', 'src/runtime.rs', 'src/runtime_config.rs', 'tests/startup_gate.rs', 'tests/runtime_gate.rs'];
export const NATIVE_DEPENDENCIES = ['anyhow', 'codex-config', 'codex-core', 'codex-exec-server', 'codex-extension-api', 'codex-features', 'codex-login', 'codex-protocol', 'codex-state', 'codex-utils-absolute-path', 'core_test_support', 'serde', 'serde_json', 'sha2', 'tempfile', 'tokio', 'toml', 'wiremock'];
const hash = (value) => crypto.createHash('sha256').update(value).digest('hex');

function privateDirectory(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(dir);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077)) throw new Error('native_cache_not_private');
}
export function nativeIdentity() {
  const scripts = path.resolve(HERE, '../../scripts');
  const inputs = [
    ...FILES.map((name) => [name, path.join(HERE, name)]),
    ...['build.mjs', 'admit.mjs', 'source-pin.json'].map((name) => [name, path.join(HERE, name)]),
    ...fs.readdirSync(scripts).filter((name) => name.endsWith('.mjs')).sort().map((name) => [`scripts/${name}`, path.join(scripts, name)]),
    ['bin/audit', path.resolve(HERE, '../../bin/audit')],
  ];
  const digests = inputs.map(([name, file]) => {
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== process.getuid()) throw new Error('native_recipe_input_rejected');
    return [name, hash(fs.readFileSync(file))];
  });
  return { packageDigest: hash(JSON.stringify(digests.slice(0, FILES.length))), recipeDigest: hash(JSON.stringify(digests)) };
}
export function withoutNativeEntry(lock) {
  const marker = `[[package]]\nname = "${PACKAGE}"\n`;
  const at = lock.indexOf(marker);
  if (at < 0) return lock;
  const next = lock.indexOf('\n[[package]]\n', at + marker.length);
  return `${lock.slice(0, at)}${next < 0 ? '' : lock.slice(next + 1)}`;
}
export function openPrivateOutput(file) {
  privateDirectory(path.dirname(file));
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o600);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== process.getuid() || (stat.mode & 0o077)) throw new Error('native_output_file_rejected');
    fs.ftruncateSync(fd, 0);
    return fd;
  } catch (err) { fs.closeSync(fd); throw err; }
}
function writePrivateOutput(file, bytes) {
  const fd = openPrivateOutput(file);
  try { fs.writeFileSync(fd, bytes); } finally { fs.closeSync(fd); }
}
export function validateSourceExtras(names) {
  const allowed = new Set([...FILES, 'UPSTREAM_LICENSE', 'UPSTREAM_NOTICE'].map((name) => `codex-rs/${MEMBER}/${name}`));
  if (names.some((name) => name && !allowed.has(name))) throw new Error('native_cached_untracked_input');
}
export function validateOverlayFiles(dir) {
  const allowed = new Set([...FILES, 'UPSTREAM_LICENSE', 'UPSTREAM_NOTICE']);
  const visit = (folder, prefix = '') => {
    for (const entry of fs.readdirSync(folder, { withFileTypes: true })) {
      const name = prefix + entry.name;
      if (entry.isSymbolicLink()) throw new Error('native_overlay_link_rejected');
      if (entry.isDirectory()) {
        if (!['src', 'tests'].includes(name)) throw new Error('native_overlay_extra_input');
        privateDirectory(path.join(folder, entry.name));
        visit(path.join(folder, entry.name), `${name}/`);
      } else {
        const stat = fs.lstatSync(path.join(folder, entry.name));
        if (!allowed.has(name) || !stat.isFile() || stat.nlink !== 1 || stat.uid !== process.getuid()) throw new Error('native_overlay_extra_input');
      }
    }
  };
  visit(dir);
}
function command(args, env, cwd) {
  const result = spawnSync(args[0], args.slice(1), { env, cwd, encoding: 'utf8', timeout: 120_000, maxBuffer: 8 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error('native_prepare_command_failed');
  return result.stdout;
}
export function overlayManifest(original) {
  if (!original.startsWith('[workspace]\nmembers = [\n') || original.includes(`"${MEMBER}"`)) throw new Error('native_workspace_shape_changed');
  return original.replace('members = [\n', `members = [\n    "${MEMBER}",\n`);
}
export function overlayLock(original) {
  if (original.includes(`name = "${PACKAGE}"`)) throw new Error('native_lock_already_overlaid');
  // Release tagging updates local manifests but leaves their old lock labels.
  // Never change the source/version/checksum of a registry or Git dependency.
  const blocks = original.split(/\n(?=\[\[package\]\])/).map((block) =>
    block.startsWith('[[package]]') && !/\nsource = /.test(block)
      ? block.replace('\nversion = "0.0.0"', `\nversion = "${UPSTREAM_VERSION}"`)
      : block);
  const normalized = blocks.join('\n');
  const labels = NATIVE_DEPENDENCIES.map((name) => {
    const versions = blocks.filter((block) => block.includes(`\nname = "${name}"\n`)).map((block) => block.match(/\nversion = "([^"]+)"/)?.[1]).filter(Boolean);
    const prefix = name === 'sha2' ? '0.10.' : name === 'toml' ? '0.9.' : null;
    const picked = prefix && versions.length > 1 ? versions.find((version) => version.startsWith(prefix)) : versions.length === 1 ? versions[0] : null;
    if (!picked) throw new Error('native_locked_dependency_ambiguous');
    return versions.length === 1 ? name : `${name} ${picked}`;
  });
  const added = `[[package]]\nname = "${PACKAGE}"\nversion = "0.1.0"\ndependencies = [\n${labels.map((label) => ` "${label}",`).join('\n')}\n]\n`;
  const anchor = blocks.find((block) => block.startsWith('[[package]]') && block.match(/\nname = "([^"]+)"/)?.[1] > PACKAGE);
  if (!anchor) return `${normalized.trimEnd()}\n\n${added}`;
  const at = normalized.indexOf(anchor);
  return `${normalized.slice(0, at)}${added}\n${normalized.slice(at)}`;
}
function preparationEnvironment() {
  privateDirectory(CACHE);
  for (const name of ['build-home', 'cargo-home', 'target']) privateDirectory(path.join(CACHE, name));
  const env = {};
  for (const key of ['PATH', 'LANG', 'LC_ALL', 'TMPDIR']) if (typeof process.env[key] === 'string') env[key] = process.env[key];
  Object.assign(env, {
    HOME: path.join(CACHE, 'build-home'),
    CARGO_HOME: path.join(CACHE, 'cargo-home'),
    CARGO_TARGET_DIR: path.join(CACHE, 'target'),
    RUSTUP_HOME: path.join(os.homedir(), '.rustup'),
    GIT_TERMINAL_PROMPT: '0',
    CARGO_BUILD_JOBS: '2',
  });
  return env;
}
export function prepareNativeSource() {
  const env = preparationEnvironment();
  const git = ['git', '--no-pager', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.ext.allow=never', '-c', 'protocol.file.allow=never', '-c', 'credential.helper='];
  if (!fs.existsSync(SOURCE)) {
    privateDirectory(SOURCE);
    command([...git, 'init', '--quiet', SOURCE], env);
    command([...git, '-C', SOURCE, 'fetch', '--quiet', '--depth', '1', '--no-tags', 'https://github.com/openai/codex.git', PIN], env);
    command([...git, '-C', SOURCE, 'checkout', '--quiet', '--detach', 'FETCH_HEAD'], env);
  }
  privateDirectory(SOURCE);
  if (!fs.lstatSync(path.join(SOURCE, '.git')).isDirectory() || fs.lstatSync(path.join(SOURCE, '.git')).isSymbolicLink()) throw new Error('native_source_git_directory_rejected');
  if (command([...git, '-C', SOURCE, 'rev-parse', 'HEAD'], env).trim() !== PIN) throw new Error('native_source_pin_mismatch');
  const rootManifest = command([...git, '-C', SOURCE, 'show', 'HEAD:codex-rs/Cargo.toml'], env);
  const rootLock = command([...git, '-C', SOURCE, 'show', 'HEAD:codex-rs/Cargo.lock'], env);
  const manifest = overlayManifest(rootManifest);
  const lock = overlayLock(rootLock);
  for (const [name, expected, base] of [['Cargo.toml', manifest, rootManifest], ['Cargo.lock', lock, rootLock]]) {
    const file = path.join(WORKSPACE, name);
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== process.getuid()) throw new Error('native_workspace_file_rejected');
    const existing = fs.readFileSync(file, 'utf8');
    const packageOnly = name === 'Cargo.lock' && withoutNativeEntry(existing).trimEnd() === withoutNativeEntry(expected).trimEnd();
    if (existing !== base && existing !== expected && !packageOnly) throw new Error('native_cached_workspace_changed');
  }
  const dirty = command([...git, '-C', SOURCE, 'diff', '--name-only', 'HEAD'], env).trim().split('\n').filter(Boolean);
  if (dirty.some((name) => !['codex-rs/Cargo.toml', 'codex-rs/Cargo.lock'].includes(name))) throw new Error('native_cached_source_changed');
  for (const ignored of [false, true]) {
    const args = [...git, '-C', SOURCE, 'ls-files', '--others', '--exclude-standard', '-z', ...(ignored ? ['--ignored'] : [])];
    validateSourceExtras(command(args, env).split('\0').filter(Boolean));
  }
  const crate = path.join(WORKSPACE, MEMBER);
  privateDirectory(crate);
  validateOverlayFiles(crate);
  for (const name of FILES) {
    const input = path.join(HERE, name);
    if (!fs.lstatSync(input).isFile() || fs.lstatSync(input).isSymbolicLink()) throw new Error('native_package_file_rejected');
    const output = path.join(crate, name);
    if (fs.existsSync(output) && fs.lstatSync(output).isSymbolicLink()) throw new Error('native_overlay_link_rejected');
    privateDirectory(path.dirname(output));
    fs.writeFileSync(output, fs.readFileSync(input), { mode: 0o600 });
  }
  for (const name of ['LICENSE', 'NOTICE']) fs.writeFileSync(path.join(crate, `UPSTREAM_${name}`), fs.readFileSync(path.join(SOURCE, name)), { mode: 0o600 });
  validateOverlayFiles(crate);
  fs.writeFileSync(path.join(WORKSPACE, 'Cargo.toml'), manifest);
  fs.writeFileSync(path.join(WORKSPACE, 'Cargo.lock'), lock);
  const compiler = command(['rustup', 'run', 'stable', 'rustc', '--version'], env).trim();
  const version = compiler.match(/^rustc 1\.(\d+)\.(\d+)/);
  if (!version || Number(version[1]) < 95) throw new Error('native_existing_toolchain_incompatible');
  const metadata = { stage: 'policy_and_contract_gates', sourceCommit: PIN, ...nativeIdentity(), lockDigest: hash(lock), compiler, admission: false };
  writePrivateOutput(path.join(CACHE, 'prepared.json'), JSON.stringify(metadata, null, 2));
  return { env, metadata };
}
export async function runGate(argv, env, cwd, log, durationMs = 30 * 60_000) {
  const fd = openPrivateOutput(log);
  let bytes = 0;
  let failure = null;
  const result = await new Promise((resolve) => {
    const child = spawn(argv[0], argv.slice(1), { env, cwd, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const stop = (reason) => {
      failure ||= reason;
      if (child.pid) { try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); } }
    };
    const timer = setTimeout(() => stop('native_build_deadline'), durationMs);
    const receive = (chunk) => {
      bytes += chunk.length;
      if (bytes > 16 * 1024 * 1024) stop('native_build_log_limit');
      else fs.writeSync(fd, chunk);
    };
    const cancel = () => stop('native_build_cancelled');
    process.on('SIGINT', cancel);
    process.on('SIGTERM', cancel);
    child.stdout.on('data', receive);
    child.stderr.on('data', receive);
    child.on('error', () => { failure = 'native_build_unavailable'; });
    child.on('close', (code) => {
      clearTimeout(timer);
      process.removeListener('SIGINT', cancel);
      process.removeListener('SIGTERM', cancel);
      resolve(code);
    });
  });
  fs.closeSync(fd);
  return { passed: result === 0 && !failure, reason: failure || (result === 0 ? null : 'native_gate_failed'), observedExitCode: result, logBytes: bytes };
}
async function testNative() {
  const { env, metadata } = prepareNativeSource();
  const gate = await runGate(['rustup', 'run', 'stable', 'cargo', 'test', '--locked', '-p', PACKAGE], env, WORKSPACE, path.join(CACHE, 'policy-gates.log'));
  const receipt = { ...metadata, policyContractTests: gate.passed ? 'passed' : 'failed', reason: gate.reason, observedExitCode: gate.observedExitCode, logBytes: gate.logBytes, admission: false };
  writePrivateOutput(path.join(CACHE, 'policy-gates.json'), JSON.stringify(receipt, null, 2));
  return receipt;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 1 || !['--prepare', '--test'].includes(args[0])) throw new Error('native_build_usage');
    const result = args[0] === '--prepare' ? prepareNativeSource().metadata : await testNative();
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (result.policyContractTests === 'failed') process.exitCode = 2;
  } catch (err) {
    const reason = typeof err.message === 'string' && /^native_[a-z_]+$/.test(err.message) ? err.message : 'native_build_failed';
    process.stderr.write(`${JSON.stringify({ stage: 'blocked', reason, admission: false })}\n`);
    process.exitCode = 2;
  }
}
