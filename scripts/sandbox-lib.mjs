// Plan, copy, and summary for the disposable audit sandbox.
// The target is untrusted. This module only reads a tree and writes a report.
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const CHECKS = [
  ['cargo-build', 'cargo build (dependency build.rs)'],
  ['build-sh', 'project build.sh'],
  ['cargo-test', 'cargo test'],
  ['test-sh', 'project test.sh'],
  ['anchor-build', 'anchor build (Anchor CLI and platform-tools)'],
  ['npm-install', 'npm install'],
  ['pnpm-install', 'pnpm install'],
  ['yarn-install', 'yarn install'],
  ['npm-audit', 'npm audit'],
  ['cargo-audit', 'cargo audit'],
  ['osv-lock', 'osv-scanner lockfile scan'],
  ['osv-call', 'osv-scanner call analysis'],
  ['solana-verify', 'solana-verify reproducible build'],
  ['deployed-compare', 'deployed .so comparison'],
  ['zap', 'OWASP ZAP'],
  ['live-probe', 'production host and RPC'],
];

// These two are gaps by rule, on every run.
const FIXED = {
  'deployed-compare': 'Deployed program bytes were not compared. This pass does not contact an RPC.',
  'live-probe': 'No production host or RPC was contacted.',
};

const SKIP_DIR = new Set(['.git', 'node_modules', 'target', 'dist', '.next', 'coverage', '.cargo', '.ssh', '.aws', '.docker', '.kube', 'secrets']);
const MAX = 4;
const SEMVER = /^\d+\.\d+\.\d+$/;
const B58 = '[1-9A-HJ-NP-Za-km-z]{32,44}';
// Lockfiles whose offline OSV database is not baked into the image.
// The host downloads these. The target container never reaches the OSV API.
const OSV_NAME = new Map([
  ['requirements.txt', 'PyPI'],
  ['poetry.lock', 'PyPI'],
  ['Pipfile.lock', 'PyPI'],
  ['pdm.lock', 'PyPI'],
  ['uv.lock', 'PyPI'],
  ['go.mod', 'Go'],
  ['pom.xml', 'Maven'],
  ['gradle.lockfile', 'Maven'],
]);

export function osvOfflineMiss(text) {
  return /no offline (?:database|version of the osv database)|databases are not cached|failed to download/i.test(String(text || ''));
}

// The user typed this URL. It is never read from the repository.
export function rpcAllowed(raw) {
  let url;
  try { url = new URL(String(raw || '')); } catch { return null; }
  if (url.protocol !== 'https:') return null;
  if (url.username || url.password) return null;
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!host || host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) return null;
  if (host.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    if (!ipAllowed(host)) return null;
  }
  return url.href;
}

export function hostAllowed(host) {
  const h = String(host || '').trim().toLowerCase().replace(/\.+$/, '');
  if (!h || h.includes(':') || h.includes('/') || h.includes('@')) return false;
  if (/^\d/.test(h) || h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')) return false;
  return ALLOW.has(h);
}

const ALLOW = new Set([
  'crates.io',
  'index.crates.io',
  'static.crates.io',
  'registry.npmjs.org',
  'registry.yarnpkg.com',
  'github.com',
  'api.github.com',
  'codeload.github.com',
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com',
  'github-releases.githubusercontent.com',
]);

export function ipAllowed(ip) {
  const raw = String(ip || '').toLowerCase().split('%')[0];
  if (!raw) return false;
  if (raw.includes(':')) {
    if (raw === '::' || raw === '::1' || raw.startsWith('fe80:') || raw.startsWith('fc') || raw.startsWith('fd')) return false;
    if (raw.startsWith('::ffff:')) return ipAllowed(raw.slice(7));
    return true;
  }
  const m = raw.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  if ([a, b, Number(m[3]), Number(m[4])].some((n) => n > 255)) return false;
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a >= 224) return false;
  return true;
}

export function safeRel(rel) {
  if (rel === '.') return '.';
  if (!rel || typeof rel !== 'string') return null;
  if (rel.startsWith('/') || rel.includes('..') || rel.includes('\\') || /\s/.test(rel)) return null;
  if (!/^[A-Za-z0-9._@+/-]+$/.test(rel)) return null;
  return rel;
}

function skipFile(name) {
  if (name === '.env') return true;
  if (name.startsWith('.env.') && !name.endsWith('.example') && !name.endsWith('.sample') && !name.endsWith('.template')) return true;
  const lower = name.toLowerCase();
  if (['id.json', '.npmrc', '.netrc', '.pypirc', '.git-credentials', '.envrc'].includes(lower)) return true;
  if (/keypair.*\.json$|\.pem$|\.key$|\.p12$|\.pfx$|^id_(rsa|ed25519|ecdsa|dsa)/.test(lower)) return true;
  return false;
}

function walk(root, visit, dir = root, depth = 0) {
  if (depth > 6) return;
  let ents = [];
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const ent of ents) {
    if (ent.isSymbolicLink()) continue;
    if (ent.isDirectory()) {
      if (SKIP_DIR.has(ent.name)) continue;
      if (ent.name === 'secrets' && path.basename(dir) === 'deploy') continue;
      walk(root, visit, path.join(dir, ent.name), depth + 1);
    } else if (ent.isFile()) {
      const rel = path.relative(root, path.join(dir, ent.name)).split(path.sep).join('/');
      visit(path.join(dir, ent.name), rel);
    }
  }
}

function readText(file) {
  try {
    if (fs.statSync(file).size > 1_000_000) return '';
    return fs.readFileSync(file, 'utf8');
  } catch { return ''; }
}

function quoted(text, key) {
  const m = String(text || '').match(new RegExp(`^\\s*${key}\\s*=\\s*"(\\d+\\.\\d+\\.\\d+)"`, 'm'));
  return m && SEMVER.test(m[1]) ? m[1] : null;
}

function anchorLang(text) {
  const direct = String(text || '').match(/anchor-lang\s*=\s*"(\d+\.\d+\.\d+)"/);
  if (direct && SEMVER.test(direct[1])) return direct[1];
  const obj = String(text || '').match(/anchor-lang\s*=\s*\{[^}]*version\s*=\s*"(\d+\.\d+\.\d+)"/);
  return obj && SEMVER.test(obj[1]) ? obj[1] : null;
}

function cliSolana(text) {
  const section = String(text || '').split('[workspace.metadata.cli]')[1];
  if (!section) return null;
  return quoted(section.split(/\n\[/)[0], 'solana');
}

function shallow(rel, name) {
  return rel === name || new RegExp(`^[^/]+/${name}$`).test(rel);
}

function cap(list) {
  return { items: list.slice(0, MAX), total: list.length };
}

export function copyTree(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const ent of fs.readdirSync(src, { withFileTypes: true })) {
    if (ent.isSymbolicLink()) continue;
    const from = path.join(src, ent.name);
    const to = path.join(dst, ent.name);
    if (ent.isDirectory()) {
      if (SKIP_DIR.has(ent.name)) continue;
      if (ent.name === 'secrets' && path.basename(src) === 'deploy') continue;
      copyTree(from, to);
    } else if (ent.isFile()) {
      if (skipFile(ent.name)) continue;
      fs.copyFileSync(from, to);
    }
  }
}

export function plan(root) {
  const files = [];
  walk(root, (abs, rel) => files.push({ abs, rel }));
  const has = (rel) => files.some((f) => f.rel === rel);
  const cargoLocks = [];
  const buildScripts = [];
  const testScripts = [];
  const anchors = [];
  const npmLocks = [];
  const pnpmLocks = [];
  const packageJsonNoLock = [];
  const yarnLocks = [];
  const yarnOnly = [];
  const osvExtra = [];
  const starts = [];
  for (const f of files) {
    if (f.rel.endsWith('/Cargo.lock') || f.rel === 'Cargo.lock') cargoLocks.push(f.rel);
    if (f.rel.endsWith('/yarn.lock') || f.rel === 'yarn.lock') yarnLocks.push(f.rel);
    const eco = OSV_NAME.get(f.rel.split('/').pop());
    if (eco && osvExtra.length < 8) osvExtra.push({ rel: f.rel, ecosystem: eco });
    if (shallow(f.rel, 'build.sh')) buildScripts.push(f.rel);
    if (shallow(f.rel, 'test.sh')) testScripts.push(f.rel);
    if (f.rel.endsWith('/package-lock.json') || f.rel === 'package-lock.json') npmLocks.push(f.rel);
    if (f.rel.endsWith('/pnpm-lock.yaml') || f.rel === 'pnpm-lock.yaml') pnpmLocks.push(f.rel);
  }
  for (const f of files) {
    if (!f.rel.endsWith('/Anchor.toml') && f.rel !== 'Anchor.toml') continue;
    const dir = f.rel.includes('/') ? f.rel.slice(0, f.rel.lastIndexOf('/')) : '.';
    const cargoRel = dir === '.' ? 'Cargo.toml' : `${dir}/Cargo.toml`;
    const rootCargo = files.find((x) => x.rel === 'Cargo.toml');
    const anchorText = readText(f.abs);
    const cargoText = readText(path.join(root, cargoRel));
    const rootText = rootCargo ? readText(rootCargo.abs) : '';
    const childVersions = [...new Set(files.filter(item => item.rel.startsWith(dir === '.' ? 'programs/' : `${dir}/programs/`) && item.rel.endsWith('/Cargo.toml')).map(item => anchorLang(readText(item.abs))).filter(Boolean))];
    const rel = safeRel(dir);
    if (!rel) continue;
    anchors.push({
      rel,
      anchorVersion: quoted(anchorText, 'anchor_version') || anchorLang(cargoText) || anchorLang(rootText) || (childVersions.length === 1 ? childVersions[0] : null),
      solanaVersion: quoted(anchorText, 'solana_version') || cliSolana(cargoText) || cliSolana(rootText),
    });
  }
  for (const f of files) {
    if (!f.rel.endsWith('/package.json') && f.rel !== 'package.json') continue;
    const dir = f.rel.includes('/') ? f.rel.slice(0, f.rel.lastIndexOf('/')) : '.';
    const lock = (name) => (dir === '.' ? name : `${dir}/${name}`);
    const npm = has(lock('package-lock.json'));
    const pnpm = has(lock('pnpm-lock.yaml'));
    const yarn = has(lock('yarn.lock'));
    if (!npm && !pnpm && yarn) yarnOnly.push(f.rel);
    else if (!npm && !pnpm) packageJsonNoLock.push(f.rel);
    let scripts = null;
    try { scripts = JSON.parse(readText(f.abs) || '{}').scripts; } catch { scripts = null; }
    if (scripts && typeof scripts.start === 'string' && scripts.start.trim() && (npm || pnpm || yarn)) {
      const rel = safeRel(dir);
      if (rel) starts.push({ rel, depth: rel === '.' ? 0 : rel.split('/').length });
    }
  }
  starts.sort((a, b) => a.depth - b.depth);
  return {
    cargoLocks: cap(cargoLocks),
    buildScripts: cap(buildScripts),
    testScripts: cap(testScripts),
    anchors: anchors.slice(0, MAX),
    npmLocks: cap(npmLocks),
    pnpmLocks: cap(pnpmLocks),
    packageJsonNoLock: cap(packageJsonNoLock),
    yarnLocks: cap(yarnLocks),
    yarnOnly: cap(yarnOnly),
    osvExtra,
    webStart: starts[0] ? { rel: starts[0].rel, script: 'start' } : null,
  };
}

function pending(id, detail) {
  return { id, result: 'pending', detail };
}
function impossible(id, detail) {
  return { id, result: 'impossible', detail };
}

export function assess(tree) {
  const checks = [];
  const locks = tree.cargoLocks.items;
  checks.push(locks.length
    ? pending('cargo-build', locks.join(', '))
    : impossible('cargo-build', 'No Cargo.lock. A manifest without a lockfile is not fetched.'));
  checks.push(tree.buildScripts.items.length
    ? pending('build-sh', tree.buildScripts.items.join(', '))
    : impossible('build-sh', 'No build.sh at the repository root or one directory down.'));
  checks.push(locks.length
    ? pending('cargo-test', locks.join(', '))
    : impossible('cargo-test', 'No Cargo.lock.'));
  checks.push(tree.testScripts.items.length
    ? pending('test-sh', tree.testScripts.items.join(', '))
    : impossible('test-sh', 'No test.sh at the repository root or one directory down.'));
  const versioned = tree.anchors.filter((a) => a.anchorVersion);
  if (!tree.anchors.length) checks.push(impossible('anchor-build', 'No Anchor.toml.'));
  else if (!versioned.length) checks.push(impossible('anchor-build', 'Anchor.toml has no anchor_version and no anchor-lang version, so the Anchor CLI was not downloaded.'));
  else checks.push(pending('anchor-build', versioned.map((a) => `${a.rel} @ ${a.anchorVersion}`).join(', ')));
  checks.push(tree.npmLocks.items.length
    ? pending('npm-install', tree.npmLocks.items.join(', '))
    : impossible('npm-install', tree.packageJsonNoLock.items.length
      ? `package.json has no lockfile (${tree.packageJsonNoLock.items.join(', ')}), so npm install was not run.`
      : 'No package-lock.json.'));
  checks.push(tree.pnpmLocks.items.length
    ? pending('pnpm-install', tree.pnpmLocks.items.join(', '))
    : impossible('pnpm-install', 'No pnpm-lock.yaml.'));
  checks.push(tree.yarnOnly.items.length
    ? pending('yarn-install', `${tree.yarnOnly.items.join(', ')} (frozen install)`)
    : impossible('yarn-install', tree.yarnLocks.items.length
      ? 'An npm or pnpm lockfile is present, so yarn install was not run.'
      : 'No yarn.lock.'));
  if (tree.npmLocks.items.length || tree.pnpmLocks.items.length) checks.push(pending('npm-audit', 'lockfile present'));
  else if (tree.yarnOnly.items.length) checks.push(pending('npm-audit', 'yarn audit'));
  else checks.push(impossible('npm-audit', 'No package-lock.json, pnpm-lock.yaml, or yarn.lock. Versions of unpinned packages are outside this run.'));
  checks.push(locks.length
    ? pending('cargo-audit', locks.join(', '))
    : impossible('cargo-audit', 'No Cargo.lock.'));
  const anyLock = locks.length || tree.npmLocks.items.length || tree.pnpmLocks.items.length || tree.yarnOnly.items.length || (tree.osvExtra || []).length;
  const ecos = [...new Set((tree.osvExtra || []).map((item) => item.ecosystem))];
  checks.push(anyLock
    ? pending('osv-lock', `crates.io and npm databases are in the image.${ecos.length ? ` The host downloads ${ecos.join(', ')} and mounts it read-only.` : ''}`)
    : impossible('osv-lock', 'No lockfile for osv-scanner.'));
  checks.push(locks.length
    ? pending('osv-call', 'rust call analysis runs dependency build.rs inside the sandbox')
    : impossible('osv-call', 'No Cargo.lock. Call analysis was not run, so osv-scanner did not execute build.rs.'));
  const pinned = tree.anchors.find((a) => a.solanaVersion && safeRel(a.rel));
  checks.push(pinned
    ? pending('solana-verify', `${pinned.rel} solana ${pinned.solanaVersion}`)
    : impossible('solana-verify', 'No pinned Solana version (Anchor.toml solana_version or workspace.metadata.cli solana). The image tag is not guessed, and the Docker socket is not mounted.'));
  checks.push(impossible('deployed-compare', FIXED['deployed-compare']));
  checks.push(tree.webStart
    ? pending('zap', `local ${tree.webStart.script} in ${tree.webStart.rel}, then ZAP against 127.0.0.1 only`)
    : impossible('zap', 'No locked package.json start script. ZAP is not pointed at a host named in the repository.'));
  checks.push(impossible('live-probe', FIXED['live-probe']));
  return checks;
}

export function blocked(reason) {
  return CHECKS.map(([id]) => ({ id, result: 'impossible', detail: FIXED[id] || reason }));
}

export function settle(checks) {
  const byId = new Map((checks || []).map((c) => [c.id, c]));
  return CHECKS.map(([id]) => {
    const row = byId.get(id);
    if (!row || row.result === 'pending') {
      return { id, result: 'impossible', detail: row?.detail && row.result !== 'pending' ? row.detail : (FIXED[id] || 'Not run.') };
    }
    return { id, result: row.result, detail: row.detail || '' };
  });
}

function cell(value) {
  return String(value || '').replace(/\|/g, '/').replace(/\s+/g, ' ').slice(0, 360);
}

export function render(checks, note) {
  const rows = settle(checks);
  const lines = [
    '# Sandbox',
    '',
    'Disposable container. Host home and the Docker socket are not mounted. Named secret files are excluded, but arbitrary source files may still contain secrets. Egress is an allowlist proxy for crates.io, registry.npmjs.org, registry.yarnpkg.com, and GitHub; this limits destinations, not data leaving to allowed hosts. Target processes share writable result storage with the sandbox reporter, so rows are sandbox-reported, not authenticated evidence. OpenSSL build scripts use the image library. PyPI, Go, and Maven databases are downloaded on the host when those lockfiles exist and mounted read-only. A pinned Solana version prefetches platform-tools on the host. Deployed bytes are compared only when --rpc is passed. The container and its network are removed at the end.',
    '',
    '`ran` means the command finished (a scanner exit 1 means it reported advisories). `failed` means the command was started and exited non-zero. `impossible` means it was not started. Logs are under `harness/sandbox-run/`. Built programs are copied to `files/` before the work volume is removed.',
    '',
    '| check | result | detail |',
    '|---|---|---|',
  ];
  const labels = new Map(CHECKS);
  for (const row of rows) {
    lines.push(`| ${labels.get(row.id) || row.id} | ${row.result} | ${cell(row.detail)} |`);
  }
  if (note) lines.push('', cell(note));
  lines.push('');
  return lines.join('\n');
}

export function writeReports(results, sandboxPath, summaryPath) {
  const md = render(results.checks || [], results.note || '');
  fs.mkdirSync(path.dirname(sandboxPath), { recursive: true });
  fs.writeFileSync(sandboxPath, md);
  const prev = fs.existsSync(summaryPath) ? fs.readFileSync(summaryPath, 'utf8') : '# Harness\n';
  const stripped = prev.replace(/\n# Sandbox[\s\S]*$/, '\n');
  fs.writeFileSync(summaryPath, `${stripped.trimEnd()}\n\n${md}`);
}

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

export function seedOsv(src, tree, dest) {
  fs.mkdirSync(dest, { recursive: true });
  let n = 0;
  for (const item of tree.osvExtra || []) {
    const rel = safeRel(item.rel);
    if (!rel || rel === '.') continue;
    const from = path.join(src, rel);
    let st;
    try { st = fs.statSync(from); } catch { continue; }
    if (!st.isFile()) continue;
    const to = path.join(dest, rel);
    fs.mkdirSync(path.dirname(to), { recursive: true });
    fs.copyFileSync(from, to);
    n += 1;
  }
  return n;
}

export function programIds(root) {
  const ids = [];
  const push = (id) => { if (id && !ids.includes(id) && ids.length < 4) ids.push(id); };
  walk(root, (abs, rel) => {
    if (ids.length >= 4) return;
    const text = readText(abs);
    if (rel.endsWith('.rs')) {
      for (const match of text.matchAll(new RegExp(`declare_id!\\s*\\(\\s*"(${B58})"`, 'g'))) push(match[1]);
    }
    if (rel === 'Anchor.toml' || rel.endsWith('/Anchor.toml')) {
      for (const part of text.split(/^\[programs\.[^\]]+\]/m).slice(1)) {
        const body = part.split(/\n\[/)[0];
        for (const match of body.matchAll(new RegExp(`^[A-Za-z0-9_-]+\\s*=\\s*"(${B58})"`, 'gm'))) push(match[1]);
      }
    }
  });
  return ids;
}

function elfHash(buf) {
  const at = buf.indexOf(Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  if (at < 0) return null;
  return crypto.createHash('sha256').update(buf.subarray(at)).digest('hex');
}

function soFiles(dir, depth = 0, out = []) {
  if (depth > 4 || !dir) return out;
  let ents = [];
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const ent of ents) {
    if (ent.isSymbolicLink()) continue;
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) soFiles(p, depth + 1, out);
    else if (ent.isFile() && ent.name.endsWith('.so') && out.length < 8) out.push(p);
  }
  return out;
}

const ARTIFACT_SKIP = new Set(['node_modules', '.git', 'deps', 'incremental', '.fingerprint', 'registry', 'git', 'build', 'examples']);
const SO_MAX = 8 * 1024 * 1024;
const IDL_MAX = 2 * 1024 * 1024;
const ARTIFACT_TOTAL = 64 * 1024 * 1024;
const ARTIFACT_COUNT = 40;

function wantedArtifact(rel, size) {
  const base = path.posix.basename(rel);
  if (!base || base.includes('keypair') || base.startsWith('.env')) return false;
  const parent = path.posix.basename(path.posix.dirname(rel));
  if (base.endsWith('.so')) return size > 0 && size <= SO_MAX && parent !== 'deps';
  if (base.endsWith('.json') && parent === 'idl') return size > 0 && size <= IDL_MAX;
  return false;
}

function walkArtifacts(dir, rel, visit, depth) {
  if (depth > 8) return;
  let ents = [];
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const ent of ents) {
    if (ent.isSymbolicLink()) continue;
    const abs = path.join(dir, ent.name);
    const next = rel ? `${rel}/${ent.name}` : ent.name;
    if (ent.isDirectory()) {
      if (ARTIFACT_SKIP.has(ent.name)) continue;
      walkArtifacts(abs, next, visit, depth + 1);
    } else if (ent.isFile()) visit(abs, next);
  }
}

// A sandbox work volume keeps cargo output under target/. A solana-verify
// directory is already the target dir (deploy/ at its root). Package-local
// target/ dirs under src/ are included. The cargo registry is not walked.
function exportRoots(root) {
  const roots = [];
  const target = path.join(root, 'target');
  if (fs.existsSync(target)) roots.push({ abs: target, rel: 'target' });
  const src = path.join(root, 'src');
  if (fs.existsSync(src)) {
    const add = (dir, rel, depth) => {
      if (depth > 4) return;
      let ents = [];
      try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const ent of ents) {
        if (!ent.isDirectory() || ent.isSymbolicLink()) continue;
        if (ent.name === 'node_modules' || ent.name === '.git') continue;
        const childRel = rel ? `${rel}/${ent.name}` : ent.name;
        if (ent.name === 'target') roots.push({ abs: path.join(dir, ent.name), rel: childRel });
        else add(path.join(dir, ent.name), childRel, depth + 1);
      }
    };
    add(src, 'src', 0);
  }
  if (!roots.length) roots.push({ abs: root, rel: '' });
  return roots;
}

// Copies deploy *.so and idl/*.json into the report's files/ directory.
// Keypairs, symlinks, deps, and the cargo registry stay behind. Returns how
// many files this call added. An existing manifest is kept and extended.
export function exportArtifacts(root, dest, prefix = '') {
  fs.mkdirSync(dest, { recursive: true });
  const manifestPath = path.join(dest, 'manifest.json');
  const prev = readJson(manifestPath, []);
  const items = Array.isArray(prev) ? prev.filter((row) => row && typeof row.path === 'string') : [];
  const seen = new Set(items.map((row) => row.path));
  let total = items.reduce((sum, row) => sum + (Number(row.bytes) || 0), 0);
  let added = 0;
  const put = (abs, rel) => {
    if (items.length >= ARTIFACT_COUNT || total >= ARTIFACT_TOTAL) return;
    let st;
    try { st = fs.lstatSync(abs); } catch { return; }
    if (!st.isFile() || st.isSymbolicLink() || !wantedArtifact(rel, st.size)) return;
    const destRel = path.posix.join(prefix || '', rel).replace(/^\//, '');
    if (!destRel || destRel.split('/').includes('..') || seen.has(destRel)) return;
    if (total + st.size > ARTIFACT_TOTAL) return;
    const to = path.join(dest, destRel);
    fs.mkdirSync(path.dirname(to), { recursive: true });
    fs.copyFileSync(abs, to);
    const hash = crypto.createHash('sha256').update(fs.readFileSync(to)).digest('hex');
    items.push({ path: destRel, bytes: st.size, sha256: hash });
    seen.add(destRel);
    total += st.size;
    added += 1;
  };
  for (const start of exportRoots(root)) walkArtifacts(start.abs, start.rel, put, 0);
  fs.writeFileSync(manifestPath, `${JSON.stringify(items, null, 2)}\n`);
  return added;
}

export async function compareDeployed(rpc, src, soDir) {
  const allowed = rpcAllowed(rpc);
  if (!allowed) {
    return { result: 'impossible', detail: 'The --rpc URL was refused. It must be https, with no credentials, and not a private, link-local, or metadata address.' };
  }
  const ids = programIds(src);
  if (!ids.length) return { result: 'impossible', detail: 'No declare_id! or Anchor program id was found, so the RPC was not queried.' };
  const files = soFiles(soDir);
  if (!files.length) return { result: 'impossible', detail: 'No .so was produced, so the deployed program was not compared.' };
  const host = new URL(allowed).hostname.replace(/^\[|\]$/g, '');
  if (!host.includes(':') && !/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    let addrs = [];
    try { addrs = await dns.lookup(host, { all: true }); } catch { return { result: 'failed', detail: `The RPC host did not resolve: ${host}` }; }
    if (!addrs.length || addrs.some((item) => !ipAllowed(item.address))) {
      return { result: 'impossible', detail: 'The RPC host resolved to a private or metadata address, so it was not queried.' };
    }
  }
  const built = files.map((file) => ({ file: path.basename(file), hash: elfHash(fs.readFileSync(file)) })).filter((item) => item.hash);
  if (!built.length) return { result: 'failed', detail: 'The build produced .so files, and none of them is an ELF.' };
  const bits = [];
  let worst = 'ran';
  for (const id of ids) {
    let body;
    try {
      const res = await fetch(allowed, {
        method: 'POST',
        redirect: 'manual',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getAccountInfo', params: [id, { encoding: 'base64' }] }),
        signal: AbortSignal.timeout(20_000),
      });
      if (res.status >= 300 && res.status < 400) {
        worst = 'impossible';
        bits.push(`${id} redirect refused`);
        continue;
      }
      body = await res.json();
    } catch (err) {
      worst = 'failed';
      bits.push(`${id} ${err.message || err}`);
      continue;
    }
    const data = body && body.result && body.result.value && body.result.value.data;
    const b64 = Array.isArray(data) ? data[0] : null;
    if (!b64) {
      worst = 'failed';
      bits.push(`${id} account is empty`);
      continue;
    }
    const hash = elfHash(Buffer.from(b64, 'base64'));
    const hit = hash && built.find((item) => item.hash === hash);
    if (!hash) {
      worst = 'failed';
      bits.push(`${id} account has no ELF`);
    } else if (!hit) {
      worst = 'failed';
      bits.push(`${id} on-chain ${hash.slice(0, 12)} matches none of the built files`);
    } else {
      bits.push(`${id} matches ${hit.file} ${hash.slice(0, 12)}`);
    }
  }
  return { result: worst, detail: `Host queried the RPC you passed. The container did not. ${bits.join('; ')}` };
}

async function main() {
  const [cmd, a, b, c, d] = process.argv.slice(2);
  if (cmd === 'copy') copyTree(a, b);
  else if (cmd === 'plan') process.stdout.write(`${JSON.stringify(plan(a))}\n`);
  else if (cmd === 'assess') process.stdout.write(`${JSON.stringify(assess(readJson(a, {})))}\n`);
  else if (cmd === 'solana') {
    const tree = readJson(a, {});
    const hit = (tree.anchors || []).find((x) => x.solanaVersion && safeRel(x.rel));
    if (!hit) process.exit(2);
    process.stdout.write(`${hit.solanaVersion}\t${safeRel(hit.rel)}\n`);
  } else if (cmd === 'blocked') {
    fs.mkdirSync(path.dirname(a), { recursive: true });
    fs.writeFileSync(a, `${JSON.stringify({ checks: blocked(b), note: b }, null, 2)}\n`);
  } else if (cmd === 'merge') {
    const cur = readJson(a, { checks: [] });
    const checks = (cur.checks || []).filter((row) => row.id !== b);
    checks.push({ id: b, result: c, detail: d || '' });
    fs.writeFileSync(a, `${JSON.stringify({ ...cur, checks }, null, 2)}\n`);
  } else if (cmd === 'render') {
    writeReports(readJson(a, { checks: blocked('No sandbox results.') }), b, c);
  } else if (cmd === 'rpc') {
    const ok = rpcAllowed(a);
    if (!ok) process.exit(2);
    process.stdout.write(ok);
  } else if (cmd === 'osv-seed') {
    process.stdout.write(String(seedOsv(b, readJson(a, {}), c)));
  } else if (cmd === 'compare') {
    process.stdout.write(`${JSON.stringify(await compareDeployed(a, b, c))}\n`);
  } else if (cmd === 'export') {
    process.stdout.write(`${exportArtifacts(a, b, c || '')}\n`);
  } else {
    process.stderr.write('usage: sandbox-lib.mjs copy|plan|assess|solana|blocked|merge|render|rpc|osv-seed|compare|export ...\n');
    process.exit(2);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => { process.stderr.write(`${err.message || err}\n`); process.exit(1); });
}
