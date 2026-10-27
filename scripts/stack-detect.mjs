// Ecosystem router: decides which language stacks the target is made of, from manifests and
// production source files only. Tests, docs, scripts and fixtures are counted separately so a
// Node helper under frontend/scripts cannot make a Python service look like a Node app.
// Everything stack-specific (guidance, leads, scanners, test runners) keys off this profile.

import fs from 'node:fs';
import path from 'node:path';

const SKIP_DIRS = new Set([
  'node_modules', 'target', 'dist', 'build', '.git', 'vendor', 'coverage', '.next',
  '__pycache__', 'harness-fixtures', '.cargo', 'reports', '.venv', 'venv', 'env', '.tox', 'site-packages', '.mypy_cache', '.pytest_cache',
]);
const MAX_FILE = 512 * 1024;

const NON_PRODUCTION_DIR = /(?:^|\/)(?:tests?|__tests__|spec|e2e|docs?|examples?|fixtures?|scripts?|tools|benchmarks?|migrations?|alembic|mocks?)\//i;
const NON_PRODUCTION_FILE = /(?:^|\/)(?:test_[^/]*\.py|[^/]*_test\.py|conftest\.py|[^/]*\.(?:test|spec)\.[cm]?[jt]sx?)$/i;

export function isProductionPath(rel) {
  return !NON_PRODUCTION_DIR.test(rel) && !NON_PRODUCTION_FILE.test(rel);
}

const PY_MANIFEST = /^(?:requirements[\w.-]*\.(?:txt|in)|pyproject\.toml|setup\.py|setup\.cfg|Pipfile|Pipfile\.lock|poetry\.lock|uv\.lock|pdm\.lock|tox\.ini|pytest\.ini|\.python-version)$/;
const PY_FRAMEWORKS = [
  ['fastapi', /\bfastapi\b/i], ['starlette', /\bstarlette\b/i], ['django', /\bdjango\b/i], ['djangorestframework', /djangorestframework|rest_framework/i],
  ['flask', /\bflask\b/i], ['aiohttp', /\baiohttp\b/i], ['tornado', /\btornado\b/i], ['sanic', /\bsanic\b/i],
  ['sqlalchemy', /\bsqlalchemy\b/i], ['alembic', /\balembic\b/i], ['pydantic', /\bpydantic\b/i], ['celery', /\bcelery\b/i],
  ['redis', /\bredis\b/i], ['websockets', /\bwebsockets\b/i], ['python-jose', /python-jose|\bjose\b/i], ['pyjwt', /\bpyjwt\b|\bimport jwt\b/i],
  ['boto3', /\bboto3\b/i], ['grpc', /\bgrpcio\b/i], ['solana-py', /\bsolders\b|\bsolana\b/i],
];
const NODE_FRAMEWORKS = [
  ['express', /["']express["']/], ['nestjs', /@nestjs\//], ['fastify', /["']fastify["']/], ['next', /["']next["']/],
  ['react', /["']react["']/], ['vite', /["']vite["']/], ['solana-web3', /@solana\/web3\.js|@solana\/kit|@coral-xyz|@anchor-lang/],
];

function walk(root, onFile) {
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const ent of entries) {
      if (ent.isSymbolicLink()) continue;
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) { if (!SKIP_DIRS.has(ent.name)) stack.push(full); }
      else if (ent.isFile()) onFile(full, ent.name);
    }
  }
}

const read = (file) => {
  try { const st = fs.lstatSync(file); return st.isFile() && st.size <= MAX_FILE ? fs.readFileSync(file, 'utf8') : ''; } catch { return ''; }
};

// Declared interpreter: .python-version, requires-python, then a Dockerfile `FROM python:X.Y`.
export function declaredPython(root, manifestPaths, dockerfiles) {
  for (const rel of manifestPaths) {
    const base = path.posix.basename(rel);
    const text = read(path.join(root, rel));
    if (base === '.python-version') { const m = text.match(/^\s*(\d+\.\d+)(?:\.\d+)?/m); if (m) return { version: m[1], source: rel }; }
    if (base === 'pyproject.toml') { const m = text.match(/requires-python\s*=\s*["'][^"']*?(\d+\.\d+)/); if (m) return { version: m[1], source: rel }; }
  }
  for (const rel of dockerfiles) {
    const m = read(path.join(root, rel)).match(/^\s*FROM\s+(?:--platform=\S+\s+)?(?:docker\.io\/library\/)?python:(\d+\.\d+)/im);
    if (m) return { version: m[1], source: rel };
  }
  return null;
}

export function detectEcosystems(targetRoot) {
  const root = path.resolve(targetRoot);
  const py = { manifests: [], dockerfiles: [], sourceFiles: 0, testFiles: 0, frameworks: new Set(), pytestRoots: new Set() };
  const node = { manifests: [], lockfiles: [], sourceFiles: 0, testFiles: 0, frameworks: new Set() };
  const rust = { manifests: [], sourceFiles: 0 };
  const solana = { marks: [] };
  const other = { go: 0, java: 0, ruby: 0, php: 0 };

  walk(root, (file, name) => {
    const rel = path.relative(root, file).split(path.sep).join('/');
    const ext = path.extname(name).toLowerCase();
    const prod = isProductionPath(rel);
    if (PY_MANIFEST.test(name)) {
      py.manifests.push(rel);
      if (/^(?:requirements|pyproject|Pipfile|setup\.cfg)/.test(name)) {
        const text = read(file);
        for (const [id, re] of PY_FRAMEWORKS) if (re.test(text)) py.frameworks.add(id);
      }
    } else if (/^Dockerfile/.test(name) || name.endsWith('.dockerfile')) py.dockerfiles.push(rel);
    if (name === 'package.json') {
      node.manifests.push(rel);
      const text = read(file);
      for (const [id, re] of NODE_FRAMEWORKS) if (re.test(text)) node.frameworks.add(id);
    } else if (['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'].includes(name)) node.lockfiles.push(rel);
    else if (name === 'Cargo.toml') {
      rust.manifests.push(rel);
      if (/anchor-lang|solana-program|solana-sdk|pinocchio/.test(read(file))) solana.marks.push(rel);
    } else if (name === 'Anchor.toml') solana.marks.push(rel);

    if (ext === '.py') {
      if (prod) py.sourceFiles++; else py.testFiles++;
      if (/(?:^|\/)(?:test_[^/]*|[^/]*_test|conftest)\.py$/.test(rel)) py.pytestRoots.add(path.posix.dirname(rel));
    } else if (['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx'].includes(ext)) { if (prod) node.sourceFiles++; else node.testFiles++; }
    else if (ext === '.rs') { if (prod) rust.sourceFiles++; }
    else if (ext === '.go') other.go++;
    else if (ext === '.java' || ext === '.kt') other.java++;
    else if (ext === '.rb') other.ruby++;
    else if (ext === '.php') other.php++;
  });

  // A Python framework imported only in app code still counts when no manifest names it.
  const python = {
    detected: py.sourceFiles > 0,
    sourceFiles: py.sourceFiles,
    testFiles: py.testFiles,
    manifests: py.manifests.sort().slice(0, 30),
    frameworks: [...py.frameworks].sort(),
    declaredVersion: declaredPython(root, py.manifests, py.dockerfiles),
    hasPytestSignal: py.pytestRoots.size > 0,
  };
  const nodeEco = {
    detected: node.sourceFiles > 0,
    sourceFiles: node.sourceFiles,
    testFiles: node.testFiles,
    manifests: node.manifests.sort().slice(0, 30),
    lockfiles: node.lockfiles.sort().slice(0, 30),
    frameworks: [...node.frameworks].sort(),
  };
  const solanaEco = { detected: solana.marks.length > 0, marks: [...new Set(solana.marks)].sort().slice(0, 20) };
  const rustEco = { detected: rust.sourceFiles > 0, sourceFiles: rust.sourceFiles, manifests: rust.manifests.sort().slice(0, 30) };
  const ecosystems = { python, node: nodeEco, rust: rustEco, solana: solanaEco };
  const primary = Object.entries({ python: python.sourceFiles, node: nodeEco.sourceFiles, rust: rustEco.sourceFiles })
    .filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]).map(([id]) => id);
  return { ...ecosystems, primary, unsupported: Object.entries(other).filter(([, n]) => n).map(([id]) => id) };
}

const PY_LOCKFILES = new Set(['poetry.lock', 'uv.lock', 'Pipfile.lock', 'pdm.lock']);
const PY_REQUIREMENTS = /^requirements[\w.-]*\.(?:txt|in)$/;

// Which Python dependency files exist, and whether versions are resolvable offline.
// An unpinned `fastapi>=0.115` has no single version to match against an advisory database.
export function analysePythonDeps(targetRoot) {
  const root = path.resolve(targetRoot);
  const out = { requirements: [], lockfiles: [], pyprojects: [], unpinned: [], risky: [] };
  walk(root, (file) => {
    const name = path.basename(file);
    const r = path.relative(root, file).split(path.sep).join('/');
    if (PY_LOCKFILES.has(name)) out.lockfiles.push(r);
    else if (name === 'pyproject.toml') out.pyprojects.push(r);
    else if (PY_REQUIREMENTS.test(name)) {
      out.requirements.push(r);
      const text = read(file);
      text.split('\n').forEach((raw, i) => {
        const line = raw.replace(/\s+#.*$/, '').trim();
        if (!line || line.startsWith('#')) return;
        if (/^(?:-e\b|--editable|git\+|https?:|--(?:extra-)?index-url|--trusted-host|-f\b|--find-links)/.test(line)) { out.risky.push(`${r}:${i + 1} ${line.slice(0, 80)}`); return; }
        if (/^-/.test(line)) return;
        if (!/(?:===?)\s*[\w.!*+-]+/.test(line.split(';')[0])) out.unpinned.push(`${r}:${i + 1} ${line.slice(0, 80)}`);
      });
    }
  });
  const unlockedProjects = out.pyprojects.filter((f) => !out.lockfiles.some((l) => path.posix.dirname(l) === path.posix.dirname(f)));
  const unresolved = out.unpinned.length + out.risky.length + unlockedProjects.filter((f) => !out.requirements.length).length;
  return { ...out, unlockedProjects, unresolved, applicable: out.requirements.length + out.lockfiles.length + out.pyprojects.length > 0 };
}

const NODE_LOCKS = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb', 'npm-shrinkwrap.json'];
const NODE_LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepublish', 'prepare'];

// package.json files: lockfile presence (own directory or an ancestor workspace root), lifecycle scripts,
// non-registry sources and open version ranges. Without a lockfile an advisory scan has no versions to match.
export function analyseNodeDeps(targetRoot) {
  const root = path.resolve(targetRoot);
  const manifests = [], locks = new Set();
  walk(root, (file, name) => {
    const r = path.relative(root, file).split(path.sep).join('/');
    if (name === 'package.json') manifests.push({ file, rel: r });
    else if (NODE_LOCKS.includes(name)) locks.add(path.posix.dirname(r));
  });
  const out = { manifests: manifests.map((m) => m.rel), noLock: [], lifecycle: [], nonRegistry: [], loose: [] };
  for (const { file, rel: r } of manifests) {
    let pkg;
    try { pkg = JSON.parse(read(file) || '{}'); } catch { continue; }
    if (!pkg || typeof pkg !== 'object' || (!pkg.dependencies && !pkg.devDependencies && !pkg.scripts && !pkg.optionalDependencies)) continue;
    let dir = path.posix.dirname(r), locked = false;
    for (;;) { if (locks.has(dir)) { locked = true; break; } if (dir === '.') break; dir = path.posix.dirname(dir); }
    const hasDeps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies, ...pkg.optionalDependencies }).length > 0;
    if (!locked && hasDeps) out.noLock.push(r);
    for (const key of NODE_LIFECYCLE) if (pkg.scripts?.[key]) out.lifecycle.push(`${r} ${key}: ${String(pkg.scripts[key]).slice(0, 80)}`);
    for (const [name, spec] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies, ...pkg.optionalDependencies })) {
      const v = String(spec).trim();
      if (/^(?:git\+|git:|github:|https?:|file:|link:|[\w.-]+\/[\w.-]+(?:#.*)?$)/.test(v)) out.nonRegistry.push(`${r} ${name}@${v.slice(0, 60)}`);
      else if (v === '*' || v === '' || v === 'latest' || v === 'x') out.loose.push(`${r} ${name}@${v || '(empty)'}`);
    }
  }
  const unresolved = out.noLock.length + out.nonRegistry.length + out.loose.length;
  return { ...out, unresolved, applicable: out.manifests.length > 0 };
}
