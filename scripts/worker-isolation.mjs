import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { readReportText, validateAuditor, validCrosscheckRow } from './report-contract.mjs';
import { validateReviewRequest, requestBinding, validateTerminalReport } from './terminal-review-contract.mjs';

export const REVIEW_IMAGE = 'node@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392';
export const ADAPTERS = ['claude', 'grok', 'agy', 'codex'];
export const LIMITS = Object.freeze({ fileBytes: 2 * 1024 * 1024, totalBytes: 128 * 1024 * 1024, files: 10_000, entries: 50_000, depth: 32, outputBytes: 4 * 1024 * 1024, logBytes: 1024 * 1024 });
const SLUGS = ['auth', 'input', 'logic', 'config', 'deps', 'client'];
const SKIP_DIRS = new Set(['.git', 'node_modules', 'target', 'dist', 'build', '.next', 'coverage', '__pycache__', '.cargo', '.ssh', '.aws', '.docker', '.kube', '.grok', '.codex', '.gemini', '.agy', 'secrets']);
const SKIP_PATHS = new Set(['audit/reports', 'audit/pocs', 'audit/theme-previews', 'docs/reviews']);
const TEXT_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.json', '.yaml', '.yml', '.toml', '.rs', '.go', '.py', '.rb', '.php', '.java', '.kt', '.cs', '.c', '.h', '.cpp', '.hpp', '.sql', '.html', '.css', '.md', '.sh', '.txt', '.lock', '.prisma', '.proto', '.xml', '.properties', '.gradle', '.scala', '.swift', '.vue', '.svelte', '.graphql', '.ini', '.cfg']);
const OWNED = new Map();
const CAPTURES = new WeakMap();
export const hash = (value) => crypto.createHash('sha256').update(value).digest('hex');
const inside = (root, file) => file === root || file.startsWith(`${root}${path.sep}`);
export function expectedFiles(phase) {
  if (!['original', 'crosscheck', 'terminal'].includes(phase)) throw new Error('invalid output phase');
  return phase === 'crosscheck' ? ['report.json'] : ['report.json', 'report.md'];
}

export function requireOwnedSnapshot(capture) {
  const saved = CAPTURES.get(capture);
  if (!saved || !OWNED.has(saved.staging) || capture.snapshot !== saved.snapshot || capture.staging !== saved.staging || capture.manifest.digest !== saved.digest || hash(JSON.stringify(capture.manifest.files)) !== saved.digest) throw new Error('snapshot is not an owned sealed capture');
  const identity = OWNED.get(saved.staging);
  const stat = fs.lstatSync(saved.staging);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.dev !== identity.dev || stat.ino !== identity.ino || (fs.lstatSync(saved.snapshot).mode & 0o222) !== 0) throw new Error('snapshot ownership or seal changed');
  return saved.snapshot;
}

// No subscription adapter currently has a verified credential-free bridge.
export function backendStatus(adapter) {
  if (!ADAPTERS.includes(adapter)) throw new Error('unknown reviewer adapter');
  return { adapter, state: 'blocked', reason: 'subscription_bridge_unverified', credentialFree: false, toolsDisabled: false };
}

function secretName(name) {
  const n = name.toLowerCase();
  return /^\.env(?:\.|$)|keypair.*\.json$|\.pem$|\.key$|\.p12$|\.pfx$|^id_(rsa|ed25519|ecdsa|dsa)/.test(n)
    || ['id.json', '.npmrc', '.netrc', '.pypirc', '.git-credentials', '.envrc', 'auth.json', 'credentials', 'credentials.json', '.credentials.json', 'settings.local.json'].includes(n);
}

export function createSnapshot(source, { exclude = [], limits = LIMITS, only = null } = {}) {
  const root = fs.realpathSync(source);
  if (!fs.statSync(root).isDirectory()) throw new Error('snapshot source is not a directory');
  const staging = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-review-'));
  const identity = fs.lstatSync(staging);
  OWNED.set(staging, { dev: identity.dev, ino: identity.ino });
  try {
  fs.chmodSync(staging, 0o700);
  const snapshot = path.join(staging, 'source');
  fs.mkdirSync(snapshot, { mode: 0o700 });
  const excluded = [...exclude.map((p) => fs.existsSync(p) ? fs.realpathSync(p) : path.resolve(p)), fs.realpathSync(staging)];
  if (excluded.some((p) => p === root)) {
    disposeSnapshot({ staging });
    throw new Error('source root cannot also be an excluded output directory');
  }
  const files = [];
  const omissions = [];
  let bytes = 0;
  let entries = 0;
  const omit = (rel, reason) => omissions.push({ path: rel, reason });
  const walk = (dir, rel, depth) => {
    if (depth > limits.depth) { omit(rel, 'depth_limit'); return; }
    const handle = fs.opendirSync(dir);
    const names = [];
    try {
      for (let ent; (ent = handle.readSync());) {
        if (++entries > limits.entries) throw new Error('snapshot entry budget exceeded');
        names.push(ent.name);
      }
    } finally { handle.closeSync(); }
    for (const name of names.sort()) {
      const from = path.join(dir, name);
      const next = rel ? `${rel}/${name}` : name;
      if (only && !only.includes(next) && !only.some((p) => p.startsWith(`${next}/`))) { omit(next, 'outside_fixed_bundle'); continue; }
      if (excluded.some((p) => inside(p, from))) { omit(next, 'run_output'); continue; }
      const stat = fs.lstatSync(from);
      if (stat.isSymbolicLink()) { omit(next, 'symlink'); continue; }
      if (stat.isDirectory()) {
        if (SKIP_DIRS.has(name) || SKIP_PATHS.has(next)) { omit(next, 'excluded_directory'); continue; }
        fs.mkdirSync(path.join(snapshot, next), { mode: 0o700 });
        walk(from, next, depth + 1);
        continue;
      }
      if (!stat.isFile()) { omit(next, 'special_file'); continue; }
      if (secretName(name) || next === '.claude/settings.json') { omit(next, 'credential_name'); continue; }
      if (stat.nlink !== 1) { omit(next, 'hardlink'); continue; }
      const text = TEXT_EXT.has(path.extname(name).toLowerCase()) || /^(Dockerfile(?:\..*)?|Makefile|Cargo\.lock|go\.mod|go\.sum)$/.test(name);
      if (!text) { omit(next, 'non_source_extension'); continue; }
      if (stat.size > limits.fileBytes) { omit(next, 'file_byte_limit'); continue; }
      // Check descriptor identity and containment; seal exactly the bytes copied,
      // not an asserted atomic point-in-time view of a changing checkout.
      const fd = fs.openSync(from, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
      let data;
      try {
        const current = fs.fstatSync(fd);
        if (!current.isFile() || current.nlink !== 1 || current.dev !== stat.dev || current.ino !== stat.ino || !inside(root, fs.realpathSync(from))) throw new Error('snapshot source changed during capture');
        const buffer = Buffer.alloc(limits.fileBytes + 1);
        let n = 0;
        for (let count; (count = fs.readSync(fd, buffer, n, buffer.length - n, null));) {
          n += count;
          if (n > limits.fileBytes) throw new Error('snapshot file grew beyond budget');
        }
        data = buffer.subarray(0, n);
      } finally { fs.closeSync(fd); }
      if (data.includes(0)) { omit(next, 'binary_content'); continue; }
      try { new TextDecoder('utf-8', { fatal: true }).decode(data); } catch { omit(next, 'non_utf8_text'); continue; }
      if (files.length >= limits.files || bytes + data.length > limits.totalBytes) throw new Error('snapshot content budget exceeded');
      fs.writeFileSync(path.join(snapshot, next), data, { mode: 0o444, flag: 'wx' });
      files.push({ path: next, bytes: data.length, sha256: hash(data) });
      bytes += data.length;
    }
  };
  try {
    walk(root, '', 0);
    files.sort((a, b) => a.path.localeCompare(b.path, 'en'));
    omissions.sort((a, b) => a.path.localeCompare(b.path, 'en'));
    const manifest = { version: 1, scope: 'read_only_text_source', files, omissions, bytes, digest: hash(JSON.stringify(files)), secretFree: 'not_guaranteed' };
    const seal = (dir) => {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) if (ent.isDirectory()) seal(path.join(dir, ent.name));
      fs.chmodSync(dir, 0o555);
    };
    seal(snapshot);
    const capture = { staging, snapshot, manifest };
    CAPTURES.set(capture, { staging, snapshot, digest: manifest.digest });
    return capture;
  } catch (err) {
    disposeSnapshot({ staging });
    throw err;
  }
  } catch (err) {
    if (OWNED.has(staging)) {
      try { disposeSnapshot({ staging }); } catch { err.cleanupStaging = staging; }
    }
    throw err;
  }
}

export function disposeSnapshot({ staging }) {
  const identity = OWNED.get(staging);
  const stat = identity && fs.lstatSync(staging);
  if (!identity || !stat.isDirectory() || stat.isSymbolicLink() || stat.dev !== identity.dev || stat.ino !== identity.ino) throw new Error('refusing cleanup of an unowned or replaced staging directory');
  const unlock = (dir) => {
    fs.chmodSync(dir, 0o700);
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) if (ent.isDirectory() && !ent.isSymbolicLink()) unlock(path.join(dir, ent.name));
  };
  unlock(staging);
  fs.rmSync(staging, { recursive: true, force: true });
  OWNED.delete(staging);
}

export function createJob({ adapter, model, surface = 's1', phase = 'original', claims = [], sourceDigest, runtimeDigest }) {
  backendStatus(adapter);
  if (typeof model !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(model)) throw new Error('invalid requested model');
  if (!/^s[1-6]$/.test(surface) || !['original', 'crosscheck'].includes(phase)) throw new Error('invalid review phase or surface');
  if (![sourceDigest, runtimeDigest].every((d) => typeof d === 'string' && /^[a-f0-9]{64}$/.test(d))) throw new Error('invalid source/runtime digest');
  if (!Array.isArray(claims) || claims.length > 10_000 || (phase === 'original' && claims.length)) throw new Error('invalid assigned claims');
  if (claims.some((c) => !c || typeof c.id !== 'string' || !/^(claude|grok|agy|codex)-s[1-6]-[a-z]+#\d+$/.test(c.id)) || new Set(claims.map((c) => c.id)).size !== claims.length) throw new Error('invalid claim identities');
  const assigned = structuredClone(claims);
  const name = phase === 'crosscheck' ? `crosscheck-${adapter}` : `${adapter}-${surface}-${SLUGS[Number(surface.slice(1)) - 1]}`;
  return {
    version: 1, id: crypto.randomUUID(), name, adapter, requestedModel: model, phase, surface,
    sourceDigest, runtimeDigest, assignmentDigest: hash(JSON.stringify(assigned)), claims: assigned,
    expected: expectedFiles(phase),
    state: 'pending', credentialPolicy: 'none_in_worker', toolPolicy: 'source_read_report_write_only',
  };
}

export function validateOutput(job, root) {
  if (JSON.stringify(job.expected) !== JSON.stringify(expectedFiles(job.phase))) throw new Error('output names must be fixed by phase');
  const names = fs.readdirSync(root).sort();
  if (JSON.stringify(names) !== JSON.stringify([...job.expected].sort())) throw new Error('unexpected or missing private output files');
  const output = {};
  for (const name of job.expected) {
    const value = readReportText(root, name, LIMITS.outputBytes);
    if (!value.trim()) throw new Error('empty worker output');
    output[name] = value;
  }
  const json = JSON.parse(output['report.json']);
  if (job.phase === 'terminal') validateTerminalReport(json, job.terminalBinding);
  else if (job.phase === 'original') validateAuditor(json, job.name);
  else {
    if (!Array.isArray(json) || json.length !== job.claims.length) throw new Error('incomplete cross-check output');
    const expected = new Set(job.claims.map((c) => c.id));
    for (const row of json) {
      if (!validCrosscheckRow(row) || !expected.delete(row.id)) throw new Error('invalid cross-check output');
    }
  }
  return { files: output, hashes: Object.fromEntries(Object.entries(output).map(([name, value]) => [name, hash(value)])) };
}

export function createTerminalJob(request, runtime) {
  validateReviewRequest(request);
  if (!/^[a-f0-9]{64}$/.test(runtime)) throw new Error('invalid runtime identity');
  return { version: 1, id: request.jobId, name: 'terminal-local-review', adapter: 'user-terminal', requestedModel: 'unverified', phase: 'terminal', sourceDigest: request.sourceDigest, runtimeDigest: runtime, assignmentDigest: hash('[]'), claims: [], terminalBinding: requestBinding(request), expected: expectedFiles('terminal'), state: 'pending', credentialPolicy: 'none_in_worker', toolPolicy: 'bounded_terminal_data_only' };
}
