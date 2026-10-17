import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { classifyAuditFailure, FAILURE_MESSAGES } from './audit-process.mjs';
import { verificationHealth } from './verification-health.mjs';
import { REVIEW_WORKFLOW } from './review-workflow.mjs';
import { readCanonicalSubmission } from './audit-submission.mjs';

const LEVELS = new Set(['critical', 'high', 'medium', 'low', 'info']);
const CONFIDENCE = new Set(['confirmed', 'probable']);
const MAX_BYTES = 4 * 1024 * 1024;
const NAME = /^(claude|grok|agy|codex)-s[1-6]-(auth|input|logic|config|deps|client)$/;
const SLUGS = ['auth', 'input', 'logic', 'config', 'deps', 'client'];
const PROVIDERS = { claude: 'anthropic', codex: 'openai', grok: 'xai', agy: 'google' };

export function adapterOf(name) {
  return NAME.test(name) ? name.split('-')[0] : null;
}
export function readReportJson(root, rel, max = MAX_BYTES) {
  return JSON.parse(readReportText(root, rel, max));
}

export function writeReportFile(root, rel, value) {
  const bytes = Buffer.from(value);
  if (bytes.length > 64 * 1024 * 1024) throw new Error('derived report exceeds byte limit');
  const fd = fs.openSync(reportPath(root, rel), fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o600);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1) throw new Error('report output must be a singly linked regular file');
    fs.ftruncateSync(fd, 0);
    fs.writeFileSync(fd, bytes);
  } finally {
    fs.closeSync(fd);
  }
}

// Adapter identity is an assertion, not attestation of the served model/provider.
export function providerOf(name) {
  return PROVIDERS[adapterOf(name)] || null;
}

function reportPath(root, rel) {
  const base = fs.realpathSync(root);
  const file = path.resolve(base, rel);
  if (!file.startsWith(`${base}${path.sep}`)) throw new Error('report path outside root');
  const parent = fs.realpathSync(path.dirname(file));
  if (parent !== base && !parent.startsWith(`${base}${path.sep}`)) throw new Error('report parent outside root');
  return file;
}

export function readReportText(root, rel, max = MAX_BYTES) {
  const fd = fs.openSync(reportPath(root, rel), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > max) throw new Error('report must be a bounded, singly linked regular file');
    const chunks = [];
    const buf = Buffer.alloc(64 * 1024);
    let total = 0;
    while (total <= max) {
      const n = fs.readSync(fd, buf, 0, Math.min(buf.length, max + 1 - total), null);
      if (!n) return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks));
      total += n;
      chunks.push(Buffer.from(buf.subarray(0, n)));
    }
    throw new Error('report grew beyond the byte limit');
  } finally {
    fs.closeSync(fd);
  }
}

const record = (x) => x && typeof x === 'object' && !Array.isArray(x);
function normalizeMeta(meta, errors) {
  for (const key of ['name', 'mode', 'source', 'ref', 'commit', 'date']) {
    if (meta[key] != null && (typeof meta[key] !== 'string' || meta[key].length > 2000)) {
      errors.push(`Invalid metadata field: ${key}.`);
      delete meta[key];
    }
  }
  if (meta.date && !Number.isFinite(Date.parse(meta.date))) {
    errors.push('Invalid metadata date.');
    delete meta.date;
  }
  if (!Array.isArray(meta.agents) || !meta.agents.length || !meta.agents.every((a) => typeof a === 'string' && Object.hasOwn(PROVIDERS, a)) || new Set(meta.agents).size !== meta.agents.length) {
    errors.push('Invalid adapter inventory.');
    meta.agents = [];
  }
  if (meta.models != null && (typeof meta.models !== 'object' || Array.isArray(meta.models) || !Object.entries(meta.models).every(([a, m]) => Object.hasOwn(PROVIDERS, a) && typeof m === 'string' && m.length <= 128))) {
    errors.push('Invalid requested-model metadata.');
    meta.models = {};
  }
  if (meta.finalized !== true || !Array.isArray(meta.stageFailures) || !meta.stageFailures.every((s) => typeof s === 'string') || !record(meta.crosscheckExits) || !record(meta.workerExits)) {
    errors.push('Missing or invalid finalized stage/exit metadata.');
  }
}

const text = (x) => typeof x === 'string' && x.trim().length > 0 && x.length <= 20_000;
const strings = (x, allowEmpty = false) => Array.isArray(x) && x.length <= 100 && (allowEmpty || x.length > 0) && x.every(text);
export const citation = (p) => typeof p === 'string' && p.length <= 1000 && /^[^:\n]+:[1-9]\d*$/.test(p) && !path.isAbsolute(p) && !p.split(/[\\/]/).includes('..');
export function validCrosscheckRow(row) {
  return row && typeof row.id === 'string' && ['upheld', 'partial', 'refuted'].includes(row.verdict)
    && typeof row.reason === 'string' && row.reason.trim().length > 0 && row.reason.length <= 20_000
    && Array.isArray(row.evidence) && row.evidence.length > 0 && row.evidence.length <= 100 && row.evidence.every(citation)
    && (row.severity == null || (typeof row.severity === 'string' && LEVELS.has(row.severity)));
}

function verifyCommittedOutput(root, meta, name, data) {
  if (meta.submissionAuthority !== 'mcp_commit') return;
  const identity = readReportJson(root, `harness/identities/${name}.json`);
  const manifest = readReportJson(root, 'source-manifest.json');
  const assignment = readReportJson(root, `harness/assignments/${name}.json`);
  const assignmentDigest = crypto.createHash('sha256').update(JSON.stringify(assignment)).digest('hex');
  if (identity.model !== meta.models?.[identity.agent] || identity.sourceDigest !== manifest.digest || identity.assignmentDigest !== assignmentDigest) throw new Error('Submission source/model/assignment mismatch');
  if (meta.workflow === REVIEW_WORKFLOW && identity.workflow !== REVIEW_WORKFLOW) throw new Error('Submission workflow mismatch');
  const submission = readCanonicalSubmission(root, name, identity);
  if (meta.workflow === REVIEW_WORKFLOW && identity.role === 'auditor' && (data.slice(0, -1).some(row => row.attack.length || row.poc || !text(row.analysis) || !text(row.validation)) || data.at(-1).verified_safe.some(row => !text(row.evidence)))) throw new Error('Source review evidence contract mismatch');
  if (!isDeepStrictEqual(submission.report.payload, data)) throw new Error('Derived report differs from the canonical submission');
}

export function validateAuditor(data, name) {
  if (!NAME.test(name)) throw new Error('unknown auditor identity');
  const [, , surface, slug] = name.match(/^(claude|grok|agy|codex)-(s[1-6])-(\w+)$/);
  if (SLUGS[Number(surface.slice(1)) - 1] !== slug) throw new Error('auditor surface mismatch');
  if (!Array.isArray(data) || !data.length || data.length > 1000) throw new Error('expected findings plus a final control-assertions object');
  for (const row of data.slice(0, -1)) {
    if (!row || typeof row !== 'object' || Array.isArray(row) || row.verified_safe) throw new Error('invalid finding object');
    if (!text(row.title) || !LEVELS.has(row.severity) || !CONFIDENCE.has(row.confidence)) throw new Error('invalid finding title, severity or confidence');
    if (row.surface !== surface.toUpperCase()) throw new Error('finding surface mismatch');
    if (!strings(row.location) || !row.location.every(citation)) throw new Error('expected relative file:line citations');
    if (!text(row.impact) || typeof row.preconditions !== 'string' || row.preconditions.length > 20_000 || !strings(row.attack, true)) throw new Error('invalid finding evidence fields');
    if (typeof row.poc !== 'string' || row.poc.length > 20_000 || !text(row.fix)) throw new Error('invalid finding remediation fields');
  }
  const final = data.at(-1);
  if (!final || !Array.isArray(final.verified_safe) || final.verified_safe.length > 1000 || final.title) throw new Error('missing final control assertions');
  for (const row of final.verified_safe) {
    if (!row || !text(row.control) || !text(row.how_attacked) || typeof row.holds !== 'boolean') throw new Error('invalid control assertion');
  }
  return data;
}

export function expectedAuditors(meta) {
  if (Array.isArray(meta.auditors)) return meta.auditors;
  if (!Array.isArray(meta.agents) || !meta.agents.length || !meta.agents.every((a) => PROVIDERS[a])) return [];
  const ids = meta.surface === 'all' ? SLUGS.map((_, i) => i) : [SLUGS.indexOf(meta.surface)];
  if (ids[0] === -1) {
    const match = String(meta.surface || '').match(/^s([1-6])$/i);
    if (!match) return [];
    ids[0] = Number(match[1]) - 1;
  }
  if (meta.surface === 'all') return ids.map((i) => `${meta.agents[i % meta.agents.length]}-s${i + 1}-${SLUGS[i]}`);
  return meta.agents.map((a) => `${a}-s${ids[0] + 1}-${SLUGS[ids[0]]}`);
}

export function loadAuditors(root) {
  const errors = [];
  let meta = {};
  try {
    meta = readReportJson(root, 'meta.json');
    if (!meta || typeof meta !== 'object' || Array.isArray(meta)) throw new Error('invalid metadata');
  } catch {
    meta = {};
    errors.push('Missing or invalid meta.json; expected reviewers are unknown.');
  }
  normalizeMeta(meta, errors);
  let expected = expectedAuditors({ ...meta, auditors: undefined });
  if (meta.auditors != null && (!Array.isArray(meta.auditors) || !meta.auditors.every((n) => typeof n === 'string') || JSON.stringify([...meta.auditors].sort()) !== JSON.stringify([...expected].sort()))) {
    errors.push('Declared auditor inventory does not match requested scope.');
  }
  if (!expected.length || !expected.every((n) => typeof n === 'string' && NAME.test(n)) || new Set(expected).size !== expected.length) {
    errors.push('Missing or invalid expected auditor inventory.');
    expected = [];
  }
  const reports = [];
  let jobs = [];
  try {
    const manifest = readReportJson(root, 'workers.json');
    if (Array.isArray(manifest?.jobs)) jobs = manifest.jobs;
  } catch { /* older reports may not include process diagnostics */ }
  const failureDetail = (name, crosscheck = false) => {
    const code = crosscheck ? meta.crosscheckExits?.[name] : meta.workerExits?.[name];
    const rel = `harness/sandbox-run/${crosscheck ? 'crosscheck' : 'agent'}-${name}.log`;
    let log = '';
    let hasLog = false;
    try { log = readReportText(root, rel, 8 * 1024 * 1024); hasLog = true; } catch { /* older runs may have no log */ }
    const observed = code === 130 ? meta.stageFailures?.includes('sandbox_unavailable') ? 'sandbox_unavailable' : 'cancelled' : undefined;
    const recorded = observed || (crosscheck ? meta.providerFailures?.[name] : jobs.find(job => job?.name === name)?.failure?.reason);
    const message = Object.hasOwn(FAILURE_MESSAGES, recorded) ? FAILURE_MESSAGES[recorded] : classifyAuditFailure({ code, stdout: log }).message;
    return `${message}${hasLog ? ` Log: ${rel}.` : ''}`;
  };
  try {
    const sandbox = readReportText(root, 'harness/sandbox.md');
    if (!/^# Sandbox/m.test(sandbox) || !/^\| .+ \| (ran|failed|impossible) \| .+ \|$/m.test(sandbox)) throw new Error('invalid coverage record');
  } catch {
    errors.push('Sandbox coverage record is missing or invalid; coverage is unknown.');
  }
  for (const name of expected) {
    try {
      const data = validateAuditor(readReportJson(root, `auditors/${name}.json`), name);
      verifyCommittedOutput(root, meta, name, data);
      // Require both declared outputs, without interpreting markdown as evidence.
      const md = path.join(root, 'auditors', `${name}.md`);
      const stat = fs.lstatSync(md);
      if (!stat.isFile() || stat.size === 0 || stat.size > MAX_BYTES) throw new Error('missing or invalid markdown output');
      if (meta.workerExits?.[name] !== 0) errors.push(`${name}: worker exit is missing or nonzero. ${failureDetail(name)}`);
      reports.push({ name, data });
    } catch (err) {
      errors.push(`${name}: missing or invalid outputs (${err.code || 'contract validation failed'}). ${failureDetail(name)}`);
    }
  }
  try {
    const extra = fs.readdirSync(path.join(root, 'auditors')).filter((n) => n.endsWith('.json') && !n.startsWith('crosscheck-') && !expected.includes(n.slice(0, -5)));
    if (extra.length) errors.push('Unexpected auditor or tiebreak files were excluded.');
  } catch { errors.push('Auditor directory is missing.'); }
  if (Array.isArray(meta.stageFailures) && meta.stageFailures.length) errors.push('One or more review stages failed.');
  const assignments = {};
  for (const adapter of meta.agents) {
    const ids = reports.flatMap((r) => adapterOf(r.name) === adapter ? [] : r.data.slice(0, -1).map((_, i) => `${r.name}#${i}`));
    if (!ids.length) continue;
    assignments[adapter] = ids;
    if (meta.crosscheckExits?.[adapter] !== 0) errors.push(`${adapter}: missing or failed cross-check exit. ${failureDetail(adapter, true)}`);
    try {
      const data = readReportJson(root, `auditors/crosscheck-${adapter}.json`);
      verifyCommittedOutput(root, meta, `crosscheck-${adapter}`, data);
    } catch { errors.push(`${adapter}: expected cross-check output is missing or invalid.`); }
  }
  for (const adapter of Object.keys(record(meta.crosscheckExits) ? meta.crosscheckExits : {})) {
    if (!assignments[adapter]) errors.push('Unexpected cross-check worker was excluded.');
  }
  const verification = meta.workflow === REVIEW_WORKFLOW ? verificationHealth(root, rel => readReportJson(root, rel, 40 * 1024 * 1024)) : null;
  const reviewState = errors.length ? 'incomplete' : 'validated_outputs';
  if (verification) errors.push(...verification.gaps);
  return {
    meta, reports, assignments,
    health: { state: errors.length ? 'incomplete' : 'validated_outputs', reviewState, verification, expected, accepted: reports.map((r) => r.name), errors, provenance: 'unverified', executionEvidence: 'not_collected' },
  };
}
