// Runs inside the disposable container. Writes /out/results.json as it goes.
// Host-owned rows (solana-verify, and ZAP once a server is listening) stay pending.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { assess, osvOfflineMiss, plan, safeRel } from './sandbox-lib.mjs';

const outDir = process.env.SANDBOX_OUT || '/out';
const budgetMs = Number(process.env.SANDBOX_BUDGET_MS || 45 * 60 * 1000);
const deadline = Date.now() + budgetMs;
const checks = [];
const reviewOnly = process.env.SANDBOX_REVIEW_ONLY === '1';

function save(note) {
  fs.mkdirSync(outDir, { recursive: true });
  const file = path.join(outDir, 'results.json');
  fs.writeFileSync(file, `${JSON.stringify({ checks, note: note || '' }, null, 2)}\n`);
  try { fs.chmodSync(file, 0o644); } catch { /* the report dir is already writable by the host */ }
}

function put(id, result, detail) {
  const idx = checks.findIndex((row) => row.id === id);
  const row = { id, result, detail: String(detail || '').replace(/\s+/g, ' ').slice(0, 700) };
  if (idx >= 0) checks[idx] = row;
  else checks.push(row);
  save();
}

function timeLeft() {
  return deadline - Date.now();
}

let spillSeq = 0;
const spills = new Set();
const LOG_CAP = 32 * 1024 * 1024;

function run(cmd, args, { cwd, timeoutMs, env } = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      cwd: cwd || '/work/src',
      env: { ...process.env, PATH: `/work/bin:${process.env.PATH || ''}`, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    const spill = path.join(outDir, `.spill-${process.pid}-${spillSeq++}`);
    let spillFd = null;
    let spilled = 0;
    let capped = false;
    try {
      spillFd = fs.openSync(spill, 'w');
      spills.add(spill);
    } catch { spillFd = null; }
    const take = (buf) => {
      out = (out + buf.toString()).slice(-16_000);
      if (spillFd == null || capped) return;
      if (spilled + buf.length > LOG_CAP) {
        const room = LOG_CAP - spilled;
        if (room > 0) {
          fs.writeSync(spillFd, buf.subarray(0, room));
          spilled += room;
        }
        fs.writeSync(spillFd, '\n[truncated at 32MB]\n');
        capped = true;
        return;
      }
      fs.writeSync(spillFd, buf);
      spilled += buf.length;
    };
    child.stdout.on('data', take);
    child.stderr.on('data', take);
    const limit = Math.max(1000, Math.min(timeoutMs || timeLeft(), timeLeft()));
    const timer = setTimeout(() => { child.kill('SIGKILL'); }, limit);
    const finishRun = (code) => {
      if (spillFd != null) { try { fs.closeSync(spillFd); } catch { /* already closed */ } }
      resolve({ code, out, spill: spillFd != null ? spill : null });
    };
    child.on('error', (err) => {
      clearTimeout(timer);
      out = err.message;
      finishRun(127);
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      finishRun(signal === 'SIGKILL' ? 124 : (code ?? 1));
    });
  });
}

function brief(res) {
  const tail = res.out.trim().split('\n').slice(-2).join(' ').slice(0, 220);
  const why = res.code === 124 ? 'timed out' : `exit ${res.code}`;
  return tail ? `${why}: ${tail}` : why;
}

function publish(name, obj) {
  const file = path.join(outDir, name);
  fs.writeFileSync(file, `${JSON.stringify(obj)}\n`);
  try { fs.chmodSync(file, 0o644); } catch { /* the report dir is already writable by the host */ }
}

function sweepSpills() {
  for (const file of spills) fs.rmSync(file, { force: true });
  spills.clear();
}

function log(id, res) {
  const file = path.join(outDir, `${id}.log`);
  fs.appendFileSync(file, `\n--- ${id}\n`);
  if (res.spill && spills.has(res.spill)) {
    const inFd = fs.openSync(res.spill, 'r');
    const outFd = fs.openSync(file, 'a');
    const buf = Buffer.alloc(256 * 1024);
    let n;
    while ((n = fs.readSync(inFd, buf, 0, buf.length, null)) > 0) fs.writeSync(outFd, buf, 0, n);
    fs.closeSync(inFd);
    fs.closeSync(outFd);
    fs.rmSync(res.spill, { force: true });
    spills.delete(res.spill);
  } else if (res.out) {
    fs.appendFileSync(file, res.out);
  }
  try { fs.chmodSync(file, 0o644); } catch { /* the report dir is already writable by the host */ }
}

const CARGO_ENV = {
  CARGO_TARGET_DIR: '/work/target',
  CARGO_HOME: '/work/cargo',
  OPENSSL_NO_VENDOR: '1',
};
const OPENSSL_NOTE = 'OpenSSL build scripts used the image library. The upstream tarball was not fetched.';

function buildResult(res) {
  return res.code === 0 ? 'ran' : 'failed';
}

function scanResult(res) {
  if (osvOfflineMiss(res.out) && res.code !== 0 && res.code !== 1) return 'impossible';
  return res.code === 0 || res.code === 1 ? 'ran' : 'failed';
}

// Yarn classic uses exit 0–31 as a severity bitmask. A transport error is also exit 1,
// and that JSON is {"type":"error"} rather than an advisory report.
function yarnAuditResult(res) {
  if (/"type"\s*:\s*"error"/.test(String(res.out || ''))) return 'failed';
  if (res.code >= 0 && res.code <= 31) return 'ran';
  return scanResult(res);
}

function dirOf(rel) {
  const safe = safeRel(rel);
  if (!safe) return null;
  return safe === '.' ? '/work/src' : path.join('/work/src', safe);
}

async function cargoLocked(id, args, rels) {
  const bits = [];
  let worst = 'ran';
  for (const rel of rels) {
    if (timeLeft() < 20_000) { worst = 'impossible'; bits.push(`${rel} skipped at the time limit`); break; }
    const cwd = dirOf(path.posix.dirname(rel));
    if (!cwd) { worst = 'failed'; bits.push(`${rel} path refused`); continue; }
    const res = await run('cargo', args, { cwd, timeoutMs: 15 * 60 * 1000, env: CARGO_ENV });
    log(id, res);
    if (res.code !== 0) worst = 'failed';
    bits.push(`${rel} ${brief(res)}`);
  }
  if (worst === 'ran') bits.push(OPENSSL_NOTE);
  put(id, worst === 'ran' ? 'ran' : worst, bits.join('; '));
}

async function scripts(id, rels) {
  const bits = [];
  let worst = 'ran';
  for (const rel of rels) {
    if (timeLeft() < 20_000) { worst = 'impossible'; bits.push(`${rel} skipped at the time limit`); break; }
    const cwd = dirOf(path.posix.dirname(rel));
    const file = path.join('/work/src', rel);
    if (!cwd || !safeRel(rel)) { worst = 'failed'; bits.push(`${rel} path refused`); continue; }
    const res = await run('bash', [file], { cwd, timeoutMs: 15 * 60 * 1000, env: CARGO_ENV });
    log(id, res);
    if (res.code !== 0) worst = 'failed';
    bits.push(`${rel} ${brief(res)}`);
  }
  put(id, worst, bits.join('; '));
}

async function installAnchor(version) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) return { code: 1, out: 'version refused' };
  const arch = process.arch === 'arm64' ? 'aarch64' : 'x86_64';
  const tag = `v${version}`;
  const base = `https://github.com/coral-xyz/anchor/releases/download/${tag}`;
  fs.mkdirSync('/work/bin', { recursive: true });
  const unpackDir = `/tmp/anchor-unpack-${version}`;
  fs.mkdirSync(unpackDir, { recursive: true });
  const tar = `${unpackDir}.tar.gz`;
  const tarUrl = `${base}/anchor-${version}-${arch}-unknown-linux-gnu.tar.gz`;
  let res = await run('curl', ['-fsSL', '--retry', '2', '-o', tar, tarUrl], { cwd: '/tmp', timeoutMs: 180_000 });
  if (res.code === 0) {
    const unpacked = await run('tar', ['-xzf', tar, '-C', unpackDir], { cwd: '/tmp', timeoutMs: 60_000 });
    if (unpacked.code !== 0) return unpacked;
    const bin = findBin(unpackDir, 'anchor');
    if (!bin) return { code: 1, out: 'tarball had no anchor binary' };
    fs.copyFileSync(bin, '/work/bin/anchor');
    fs.chmodSync('/work/bin/anchor', 0o755);
    return { code: 0, out: `installed ${version}` };
  }
  const raw = `${base}/anchor-${version}-${arch}-unknown-linux-gnu`;
  const dest = '/work/bin/anchor';
  res = await run('curl', ['-fsSL', '--retry', '2', '-o', dest, raw], { cwd: '/tmp', timeoutMs: 180_000 });
  if (res.code === 0) fs.chmodSync(dest, 0o755);
  return res;
}

function findBin(dir, name, depth = 0) {
  if (depth > 3) return null;
  let ents = [];
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return null; }
  for (const ent of ents) {
    if (ent.isSymbolicLink()) continue;
    const p = path.join(dir, ent.name);
    if (ent.isFile() && ent.name === name) return p;
    if (ent.isDirectory()) {
      const hit = findBin(p, name, depth + 1);
      if (hit) return hit;
    }
  }
  return null;
}

async function anchorBuild(tree) {
  const bits = [];
  let worst = 'ran';
  const seen = new Set();
  for (const item of tree.anchors) {
    if (!item.anchorVersion || seen.has(item.anchorVersion)) continue;
    seen.add(item.anchorVersion);
    const installed = await installAnchor(item.anchorVersion);
    log('anchor-build', installed);
    if (installed.code !== 0) {
      put('anchor-build', 'failed', `${item.rel} @ ${item.anchorVersion} ${brief(installed)}`);
      return;
    }
  }
  for (const item of tree.anchors.filter((a) => a.anchorVersion)) {
    if (timeLeft() < 20_000) { worst = 'impossible'; bits.push('time limit'); break; }
    const cwd = dirOf(item.rel);
    if (!cwd) { worst = 'failed'; bits.push(`${item.rel} path refused`); continue; }
    const tools = fs.existsSync('/opt/platform-tools') ? { SOLANA_PLATFORM_TOOLS_DIR: '/opt/platform-tools' } : {};
    const res = await run('anchor', ['build'], { cwd, timeoutMs: 20 * 60 * 1000, env: { ...CARGO_ENV, ...tools } });
    log('anchor-build', res);
    if (res.code !== 0) worst = 'failed';
    bits.push(`${item.rel} @ ${item.anchorVersion} ${brief(res)}`);
  }
  if (worst === 'ran') bits.push(OPENSSL_NOTE);
  put('anchor-build', worst, bits.join('; ') || 'no versioned Anchor.toml');
}

async function npmInstall(rels) {
  const bits = [];
  let worst = 'ran';
  for (const rel of rels) {
    const cwd = dirOf(path.posix.dirname(rel));
    if (!cwd) { worst = 'failed'; bits.push(`${rel} path refused`); continue; }
    const res = await run('npm', ['ci', '--no-audit', '--no-fund'], { cwd, timeoutMs: 10 * 60 * 1000 });
    log('npm-install', res);
    if (res.code !== 0) worst = 'failed';
    else installed.add(path.posix.dirname(rel));
    bits.push(`${rel} ${brief(res)}`);
  }
  put('npm-install', worst, bits.join('; '));
}

async function pnpmInstall(rels) {
  const bits = [];
  let worst = 'ran';
  for (const rel of rels) {
    const cwd = dirOf(path.posix.dirname(rel));
    if (!cwd) { worst = 'failed'; bits.push(`${rel} path refused`); continue; }
    const res = await run('pnpm', ['install', '--frozen-lockfile'], { cwd, timeoutMs: 10 * 60 * 1000 });
    log('pnpm-install', res);
    if (res.code !== 0) worst = 'failed';
    else installed.add(path.posix.dirname(rel));
    bits.push(`${rel} ${brief(res)}`);
  }
  put('pnpm-install', worst, bits.join('; '));
}

function yarnBerry(cwd) {
  try {
    return /__metadata|yarn lockfile v[2-9]/i.test(fs.readFileSync(path.join(cwd, 'yarn.lock'), 'utf8').slice(0, 400));
  } catch { return false; }
}

async function yarnInstall(rels) {
  const bits = [];
  let worst = 'ran';
  for (const rel of rels) {
    const cwd = dirOf(path.posix.dirname(rel));
    if (!cwd) { worst = 'failed'; bits.push(`${rel} path refused`); continue; }
    const berry = yarnBerry(cwd);
    if (berry) {
      const prepared = await run('corepack', ['prepare', 'yarn@4.9.2', '--activate'], { cwd, timeoutMs: 180_000 });
      log('yarn-install', prepared);
      if (prepared.code !== 0) { worst = 'failed'; bits.push(`${rel} ${brief(prepared)}`); continue; }
    }
    const args = berry ? ['install', '--immutable'] : ['install', '--frozen-lockfile', '--registry', 'https://registry.npmjs.org'];
    const res = await run('yarn', args, { cwd, timeoutMs: 10 * 60 * 1000 });
    log('yarn-install', res);
    if (res.code !== 0) worst = 'failed';
    else installed.add(path.posix.dirname(rel));
    bits.push(`${rel} ${brief(res)}`);
  }
  put('yarn-install', worst, bits.join('; '));
}

async function audits(tree) {
  const bits = [];
  let worst = 'ran';
  const jobs = [
    ...tree.npmLocks.items.map((rel) => ['npm', ['audit', '--json', '--registry', 'https://registry.npmjs.org'], rel]),
    ...tree.pnpmLocks.items.map((rel) => ['pnpm', ['audit', '--json'], rel]),
    ...tree.yarnOnly.items.map((rel) => ['yarn', null, rel]),
  ];
  for (const [cmd, args, rel] of jobs) {
    const cwd = dirOf(path.posix.dirname(rel));
    if (!cwd) continue;
    const yarnArgs = cmd === 'yarn'
      ? (yarnBerry(cwd) ? ['npm', 'audit', '--json'] : ['audit', '--json', '--registry', 'https://registry.npmjs.org'])
      : args;
    const res = await run(cmd, yarnArgs, { cwd, timeoutMs: 5 * 60 * 1000 });
    log('npm-audit', res);
    const kind = cmd === 'yarn' ? yarnAuditResult(res) : scanResult(res);
    if (kind === 'failed') worst = 'failed';
    bits.push(`${rel} ${brief(res)}`);
  }
  put('npm-audit', worst, bits.join('; ') || 'no lockfile directory');
}

async function cargoAudit(rels) {
  const bits = [];
  let worst = 'ran';
  for (const rel of rels) {
    const file = path.join('/work/src', rel);
    const res = await run('cargo', ['audit', '--file', file], {
      cwd: '/work/src',
      timeoutMs: 5 * 60 * 1000,
      env: { CARGO_HOME: '/work/cargo', OPENSSL_NO_VENDOR: '1' },
    });
    log('cargo-audit', res);
    const kind = scanResult(res);
    if (kind === 'failed') worst = 'failed';
    if (kind === 'impossible') worst = 'impossible';
    bits.push(`${rel} ${brief(res)}`);
  }
  put('cargo-audit', worst, bits.join('; '));
}

async function osv(call) {
  const id = call ? 'osv-call' : 'osv-lock';
  const args = ['scan', 'source', '-r', '/work/src', '--offline-vulnerabilities'];
  if (call) args.push('--call-analysis=rust');
  const res = await run('osv-scanner', args, { cwd: '/work/src', timeoutMs: call ? 20 * 60 * 1000 : 5 * 60 * 1000, env: { ...CARGO_ENV, XDG_CACHE_HOME: '/opt/osv-cache' } });
  log(id, res);
  const kind = scanResult(res);
  let detail = kind === 'impossible'
    ? `An ecosystem in this tree has no offline database, so this scan was not completed. The OSV API is not contacted. ${brief(res)}`
    : brief(res);
  if (call && kind === 'ran') detail = `${detail} ${OPENSSL_NOTE}`;
  put(id, kind, detail);
}

function listen(port) {
  return new Promise((resolve) => {
    const socket = net.connect(port, '127.0.0.1');
    const done = (ok) => { socket.destroy(); resolve(ok); };
    socket.on('connect', () => done(true));
    socket.on('error', () => done(false));
    socket.setTimeout(1000, () => done(false));
  });
}

async function waitPort(port, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await listen(port)) return true;
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

const installed = new Set();

async function maybeServe(tree) {
  const web = tree.webStart;
  if (!web) return;
  const key = web.rel === '.' ? '.' : web.rel;
  if (!installed.has(key)) {
    put('zap', 'impossible', `Install in ${web.rel} did not succeed, so the local server was not started.`);
    publish('zap.json', { ready: false });
    return;
  }
  const cwd = dirOf(web.rel);
  const logFd = fs.openSync(path.join(outDir, 'web-server.log'), 'w');
  const child = spawn('npm', ['start'], {
    cwd,
    detached: true,
    stdio: ['ignore', logFd, logFd],
    env: { ...process.env, HOST: '0.0.0.0', PORT: '3000', BROWSER: 'none' },
  });
  const up = await waitPort(3000, 30_000);
  if (!up) {
    try { process.kill(-child.pid, 'SIGTERM'); } catch { child.kill('SIGTERM'); }
    put('zap', 'impossible', 'The start script did not listen on 127.0.0.1:3000. ZAP was not pointed anywhere else.');
    publish('zap.json', { ready: false });
    return;
  }
  publish('zap.json', { ready: true, port: 3000 });
  // The host may still be pulling the ZAP image, then the baseline is capped at 2 minutes.
  const until = Date.now() + 12 * 60 * 1000;
  while (Date.now() < until && !fs.existsSync(path.join(outDir, 'zap.done'))) {
    await new Promise((r) => setTimeout(r, 1000));
  }
  try { process.kill(-child.pid, 'SIGTERM'); } catch { child.kill('SIGTERM'); }
}

function listRs(dir, depth = 0, out = []) {
  if (depth > 4 || out.length >= 8) return out;
  let ents = [];
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const ent of ents) {
    if (ent.isSymbolicLink()) continue;
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) listRs(p, depth + 1, out);
    else if (ent.isFile() && ent.name.endsWith('.rs')) out.push(p);
  }
  return out;
}

function packageDir() {
  const candidates = ['/work/src'];
  try {
    for (const ent of fs.readdirSync('/work/src', { withFileTypes: true })) {
      if (ent.isDirectory() && !ent.isSymbolicLink()) candidates.push(path.join('/work/src', ent.name));
    }
  } catch { /* the copy failed */ }
  for (const dir of candidates) {
    try {
      const text = fs.readFileSync(path.join(dir, 'Cargo.toml'), 'utf8');
      if (/^\[package\]/m.test(text) && fs.existsSync(path.join(dir, 'Cargo.lock'))) return dir;
    } catch { /* not a package */ }
  }
  return null;
}

async function runPocs() {
  const pkg = packageDir();
  const files = listRs('/pocs');
  if (!pkg) {
    put('cargo-test', 'impossible', 'No Cargo package with a Cargo.lock, so the Rust PoCs were not fetched or run.');
    return;
  }
  if (!files.length) {
    put('cargo-test', 'impossible', 'No .rs PoC files.');
    return;
  }
  for (const file of files) {
    const text = fs.readFileSync(file, 'utf8');
    const base = path.basename(file, '.rs').replace(/[^A-Za-z0-9_]/g, '_').slice(0, 40) || 'poc';
    const name = `audit_${base}`;
    if (!text.includes('#[test]')) {
      put(`poc:${path.basename(file)}`, 'impossible', 'The file has no #[test], so it was not executed.');
      continue;
    }
    fs.mkdirSync(path.join(pkg, 'tests'), { recursive: true });
    fs.copyFileSync(file, path.join(pkg, 'tests', `${name}.rs`));
    const res = await run('cargo', ['test', '--locked', '--test', name], { cwd: pkg, timeoutMs: 10 * 60 * 1000, env: CARGO_ENV });
    log('cargo-test', res);
    put(`poc:${path.basename(file)}`, res.code === 0 ? 'ran' : 'failed', brief(res));
  }
}

// A Python project (dependency manifest in the directory or an ancestor) that has pytest-style tests.
function hasPythonTests(root) {
  let tests = false, projects = false;
  (function walk(dir, depth) {
    if (depth > 6 || tests && projects) return;
    let ents = [];
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const ent of ents) {
      if (ent.isSymbolicLink() || ['.git', 'node_modules', 'target', 'dist', '.venv', 'venv'].includes(ent.name)) continue;
      if (ent.isDirectory()) walk(path.join(dir, ent.name), depth + 1);
      else if (/^(?:conftest|test_.*|.*_test)\.py$/.test(ent.name)) tests = true;
      else if (/^(?:requirements[\w.-]*\.txt|pyproject\.toml)$/.test(ent.name)) projects = true;
    }
  })(root, 0);
  return tests && projects;
}

async function main() {
  try {
  fs.mkdirSync('/work/src', { recursive: true });
  fs.cpSync('/src', '/work/src', { recursive: true, force: true });
  if (reviewOnly) {
    process.env.CARGO_TARGET_DIR = '/work/target';
    process.env.CARGO_HOME = '/work/cargo';
    process.env.CARGO_NET_OFFLINE = 'true';
  }
  if (reviewOnly && process.env.SANDBOX_POCS === '1') throw new Error('Source review excludes PoCs');
  if (process.env.SANDBOX_POCS === '1') {
    await runPocs();
    save('rust pocs');
    return;
  }
  const tree = plan('/work/src');
  if (reviewOnly && tree.cargoLocks.items.length && process.env.SANDBOX_FAST !== '1') {
    // Only the trusted manifest/lockfile preparer has network access. It cannot run target code.
    const prepared = await run('python3', ['/opt/prepare-cargo-cache.py'], { cwd: '/tmp', timeoutMs: 12 * 60 * 1000 });
    log('cargo-cache', prepared);
    put('cargo-cache', prepared.code === 0 ? 'ran' : 'failed', `Manifest-only locked dependency preparation: ${brief(prepared)}`);
  }
  if (reviewOnly && process.env.SANDBOX_FAST !== '1' && hasPythonTests('/work/src')) {
    // Wheel-only install from requirements files; no target code or build backend runs while networked.
    const prepared = await run('python3', ['/opt/prepare-python-env.py'], { cwd: '/tmp', timeoutMs: 25 * 60 * 1000 });
    log('python-env', prepared);
    put('python-env', prepared.code === 0 ? 'ran' : 'failed', `Wheel-only Python test environment: ${brief(prepared)}`);
  }
  for (const row of assess(tree)) {
    if (row.result === 'impossible') put(row.id, 'impossible', row.detail);
  }
  const want = new Set(assess(tree).filter((row) => row.result === 'pending').map((row) => row.id));
  const owned = [
    ['cargo-build', () => cargoLocked('cargo-build', ['build', '--locked'], tree.cargoLocks.items)],
    ['cargo-test', () => cargoLocked('cargo-test', ['test', '--locked'], tree.cargoLocks.items)],
    ['build-sh', () => scripts('build-sh', tree.buildScripts.items)],
    ['test-sh', () => scripts('test-sh', tree.testScripts.items)],
    ['anchor-build', () => anchorBuild(tree)],
    ['npm-install', () => npmInstall(tree.npmLocks.items)],
    ['pnpm-install', () => pnpmInstall(tree.pnpmLocks.items)],
    ['yarn-install', () => yarnInstall(tree.yarnOnly.items)],
    ['npm-audit', () => audits(tree)],
    ['cargo-audit', () => cargoAudit(tree.cargoLocks.items)],
    ['osv-lock', () => osv(false)],
    ['osv-call', () => osv(true)],
  ];
  if (reviewOnly) {
    for (const id of want) put(id, 'impossible', 'Source security review: target builds, install hooks, active scans and tests are disabled during networked preparation. Existing tests may run through the fixed MCP catalog after network disconnection.');
  } else if (process.env.SANDBOX_FAST !== '1') {
    for (const [id, fn] of owned) {
      if (!want.has(id)) continue;
      if (timeLeft() < 20_000) {
        put(id, 'impossible', 'Sandbox time limit reached before this check.');
        continue;
      }
      try { await fn(); } catch (err) { put(id, 'failed', err.message || String(err)); }
    }
    if (want.has('zap')) {
      try { await maybeServe(tree); } catch (err) { put('zap', 'failed', err.message || String(err)); }
    }
  } else {
    for (const id of want) put(id, 'impossible', 'Skipped in fast mode (SANDBOX_FAST=1).');
  }
  if (fs.existsSync('/opt/audit/harness.mjs')) {
    const hArgs = ['/opt/audit/harness.mjs', '--target', '/work/src', '--out', path.join(outDir, 'harness-leads')];
    if (process.env.SANDBOX_FAST === '1') hArgs.push('--no-deps');
    const hRes = await run('node', hArgs, { cwd: '/work/src', timeoutMs: Math.min(240_000, Math.max(15_000, timeLeft())), env: CARGO_ENV });
    log('harness', hRes);
    if (reviewOnly) {
      try {
        const record = JSON.parse(fs.readFileSync(path.join(outDir, 'harness-leads/scanner-results.json'), 'utf8'));
        for (const [tool, id] of [['cargo-audit', 'cargo-audit'], ['osv-scanner', 'osv-lock'], ['semgrep', 'semgrep'], ['gitleaks', 'gitleaks']]) {
          const rows = record.checks.filter(row => row.tool === tool);
          const ran = rows.length && rows.every(row => ['passed', 'findings'].includes(row.state));
          put(id, ran ? 'ran' : rows.some(row => row.state === 'failed') ? 'failed' : 'impossible', `${tool}: ${rows.map(row => row.state).join(', ') || 'no scanner evidence'}. See scanner-results.json and scanner-output files. Static scan only; target code was not executed.`);
        }
      } catch { put('static-scanners', 'failed', 'Structured scanner evidence was not produced. See harness.log.'); }
    }
  }
  save();
  publish('checks.done', { ready: true, timestamp: new Date().toISOString() });
  if (process.env.SANDBOX_HOLD === '1') {
    fs.mkdirSync(path.join(outDir, 'auditors'), { recursive: true });
    fs.mkdirSync(path.join(outDir, 'pocs'), { recursive: true });
    fs.mkdirSync(path.join(outDir, 'crosscheck'), { recursive: true });
    // The preparation budget ends at checks.done; reviewers have no deadline.
    while (!fs.existsSync(path.join(outDir, 'sandbox.release'))) {
      await new Promise((r) => setTimeout(r, 400));
    }
  }
  } finally {
    sweepSpills();
  }
}

main().catch((err) => {
  put('cargo-build', 'failed', err.message || String(err));
  process.exit(0);
});
