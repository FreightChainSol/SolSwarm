#!/usr/bin/env node
/**
 * generate-html-report.mjs
 *
 * Writes two standalone pages in the report directory:
 *   report.html              the quorum review
 *   findings-by-model.html   each model's own findings, counted by severity
 *
 * The target (name, source, ref, commit) comes from <report-dir>/meta.json, written by orchestrate.sh.
 * Everything an auditor wrote is untrusted (it was derived from a third-party repo), so it is HTML-escaped.
 *
 * Usage:
 *   node audit/scripts/generate-html-report.mjs [report-dir]   (default: newest dir under audit/reports)
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import { loadAuditors, adapterOf, readReportText, readReportJson, writeReportFile } from './report-contract.mjs';

const scriptsDir = path.dirname(fileURLToPath(import.meta.url));

function newestReportDir() {
  const root = path.join(scriptsDir, '..', 'reports');
  if (!fs.existsSync(root)) return null;
  return fs.readdirSync(root, { withFileTypes: true })
    .filter((d) => d.isDirectory() && fs.existsSync(path.join(root, d.name, 'auditors')))
    .map((d) => ({ dir: path.join(root, d.name), mtime: fs.statSync(path.join(root, d.name)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime)[0]?.dir || null;
}

const reportDir = process.argv[2] || newestReportDir();
if (!reportDir) {
  console.error('No report directory given and none found under audit/reports');
  process.exit(1);
}
const assetsDir = path.join(reportDir, 'assets');

// Revalidate current inputs; an old scored file is not evidence of completeness.
try {
  execFileSync('node', [path.join(scriptsDir, 'verify-and-adjudicate.mjs'), reportDir], { stdio: 'inherit' });
} catch (err) {
  if (err.status !== 2 || !fs.existsSync(path.join(reportDir, 'report-health.json'))) throw err;
}

const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const readJson = (file, fallback) => {
  try { return readReportJson(reportDir, file, 64 * 1024 * 1024); } catch { return fallback; }
};

const findings = readReportJson(reportDir, 'findings-and-scores.json', 64 * 1024 * 1024);
const verifiedSafe = readJson('verified-safe.json', []);
const { meta, reports, health: currentHealth } = loadAuditors(reportDir);
const health = readJson('report-health.json', currentHealth);
const nonce = crypto.randomBytes(24).toString('base64');
const policy = `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'`;
const workerManifest = readJson('workers.json', {});
const workerJobs = Array.isArray(workerManifest?.jobs) ? workerManifest.jobs.slice(0, 1000).filter((j) => j && typeof j.name === 'string' && typeof j.state === 'string') : [];
let sandboxMd = '';
try { sandboxMd = readReportText(reportDir, 'harness/sandbox.md'); } catch { /* disclose unavailable coverage */ }
const sandboxRows = String(sandboxMd).split('\n').flatMap((line) => {
  const m = line.match(/^\| (.+?) \| (ran|failed|impossible) \| (.*) \|$/);
  return m ? [{ name: m[1], result: m[2], detail: m[3] }] : [];
});

const targetName = meta.name || path.basename(path.resolve(reportDir));
const dateLabel = (meta.date ? new Date(meta.date) : new Date()).toISOString().slice(0, 10);
const sourceLine = [meta.source, meta.ref && `@ ${meta.ref}`, meta.commit && `(${meta.commit})`].filter(Boolean).join(' ');
// Assets share the report's trust boundary; display source, never active SVG.
const diagrams = fs.existsSync(assetsDir)
  ? fs.readdirSync(assetsDir).filter((f) => f.endsWith('.svg') && fs.lstatSync(path.join(assetsDir, f)).isFile() && fs.statSync(path.join(assetsDir, f)).size <= 512 * 1024).sort().map((f) => ({
      title: f.replace(/\.svg$/, '').replace(/[-_]+/g, ' '),
      svg: readReportText(reportDir, `assets/${f}`, 512 * 1024),
    }))
  : [];

// Compute summary counts
const counts = {
  total: findings.length,
  high: findings.filter((f) => f.severity === 'high' || f.severity === 'critical').length,
  medium: findings.filter((f) => f.severity === 'medium').length,
  low: findings.filter((f) => f.severity === 'low').length,
  info: findings.filter((f) => f.severity === 'info').length,
  modelAgreement: findings.filter((f) => f.status === 'MODEL_AGREEMENT').length,
};

// Same generic surfaces as orchestrate.sh
const SURFACE_NAMES = {
  S1: 'Identity & Access Control',
  S2: 'Input Handling & Injection',
  S3: 'Business Logic & Value Flows',
  S4: 'Secrets, Config & Infra',
  S5: 'Dependencies & Supply Chain',
  S6: 'Client & Web Surface',
};
const surfaces = Object.fromEntries(
  Object.keys(SURFACE_NAMES).map((id) => {
    const rows = findings.filter((f) => String(f.surface).toUpperCase().startsWith(id));
    const levels = { high: 0, medium: 0, low: 0, info: 0 };
    for (const f of rows) {
      const sev = f.severity === 'critical' ? 'high' : f.severity;
      if (Object.hasOwn(levels, sev)) levels[sev] += 1;
    }
    return [id, { total: rows.length, ...levels }];
  }),
);

// Raw findings per model. A cluster in findings-and-scores.json is shared, so it is the wrong count.
const SEVERITY_LEVELS = ['high', 'medium', 'low', 'info'];
const MODEL_ORDER = ['claude', 'gpt', 'codex', 'grok', 'agy', 'gemini'];

function severityLevel(raw) {
  const token = String(raw ?? '').toLowerCase().match(/[a-z]+/)?.[0] || '';
  if (token === 'critical') return 'high';
  return token;
}

function loadModelRows() {
  const buckets = new Map();
  const ensure = (key) => {
    if (!buckets.has(key)) buckets.set(key, { key, counts: {} });
    return buckets.get(key);
  };
  {
    for (const { name, data: items } of reports) {
      const key = adapterOf(name);
      const row = ensure(key);
      for (const item of items) {
        if (!item || typeof item !== 'object' || item.verified_safe) continue;
        if (!item.severity && !item.title) continue;
        const level = severityLevel(item.severity);
        if (!level) continue;
        row.counts[level] = (row.counts[level] || 0) + 1;
      }
    }
  }
  if (Array.isArray(meta.agents)) {
    for (const agent of meta.agents) ensure(String(agent).toLowerCase());
  }
  const extra = [];
  for (const row of buckets.values()) {
    for (const level of Object.keys(row.counts)) {
      if (!SEVERITY_LEVELS.includes(level) && !extra.includes(level)) extra.push(level);
    }
  }
  const levels = [...SEVERITY_LEVELS, ...extra.sort()];
  const rows = [...buckets.values()].map((row) => {
    const slug = meta.models && meta.models[row.key];
    const total = levels.reduce((n, level) => n + (row.counts[level] || 0), 0);
    const available = reports.some((r) => adapterOf(r.name) === row.key);
    const expectedOutputs = (health.expected || []).filter(name => adapterOf(name) === row.key).length;
    const acceptedOutputs = (health.accepted || []).filter(name => adapterOf(name) === row.key).length;
    return { ...row, label: slug || row.key, available, total, expectedOutputs, acceptedOutputs };
  }).sort((a, b) => {
    const ia = MODEL_ORDER.indexOf(a.key);
    const ib = MODEL_ORDER.indexOf(b.key);
    if (ia === -1 && ib === -1) return a.key.localeCompare(b.key);
    if (ia === -1) return 1;
    if (ib === -1) return -1;
    return ia - ib;
  });
  return { rows, levels };
}

const { rows: modelRows, levels: modelLevels } = loadModelRows();
const modelMax = Math.max(1, ...modelRows.map((r) => r.total));

function modelChart() {
  if (!modelRows.length) return '<p class="note">No auditor findings were filed.</p>';
  return modelRows.map((row) => {
    const width = row.total ? (row.total / modelMax) * 100 : 0;
    const segs = modelLevels.map((level) => {
      const n = row.counts[level] || 0;
      if (!n) return '';
      const cls = SEVERITY_LEVELS.includes(level) ? level : 'other';
      return `<span class="seg seg-${cls}" style="width:${((n / row.total) * 100).toFixed(2)}%"></span>`;
    }).join('');
    return `<div class="chart-row">
      <div class="chart-name">${esc(row.label)}<div class="note">${row.available ? `${row.acceptedOutputs}/${row.expectedOutputs} outputs received` : 'no valid outputs'}</div></div>
      <div class="chart-track"><div class="chart-fill" style="width:${width.toFixed(2)}%">${segs}</div></div>
      <div class="chart-total">${row.total}</div>
    </div>`;
  }).join('');
}

function modelTable() {
  const head = modelLevels.map((level) => `<th>${esc(level)}</th>`).join('');
  const body = modelRows.map((row) => {
    const cells = modelLevels.map((level) => {
      const n = row.counts[level] || 0;
      const cls = !n ? 'zero' : (level === 'high' ? 'high' : '');
      return `<td${cls ? ` class="${cls}"` : ''}>${n}</td>`;
    }).join('');
    return `<tr><th scope="row">${esc(row.label)}<div class="note">${row.available ? `${row.acceptedOutputs}/${row.expectedOutputs} outputs received` : 'no valid outputs'}</div></th>${cells}<td>${row.total}</td></tr>`;
  }).join('');
  const totals = modelLevels.map((level) => {
    const n = modelRows.reduce((sum, row) => sum + (row.counts[level] || 0), 0);
    return `<td${level === 'high' && n ? ' class="high"' : ''}>${n}</td>`;
  }).join('');
  const grand = modelRows.reduce((sum, row) => sum + row.total, 0);
  return `<table>
    <thead><tr><th>Model</th>${head}<th>Total</th></tr></thead>
    <tbody>${body}</tbody>
    <tfoot><tr><th scope="row">All models</th>${totals}<td>${grand}</td></tr></tfoot>
  </table>`;
}

const styles = fs.readFileSync(path.join(scriptsDir, 'report-style.css'), 'utf8');
const browserScript = fs.readFileSync(path.join(scriptsDir, 'report-browser.js'), 'utf8');
const accepted = health.accepted?.length || 0;
const expected = health.expected?.length || 0;
const complete = health.state === 'validated_outputs';
const reviewComplete = health.reviewState ? health.reviewState === 'validated_outputs' : complete;
const statusLabel = complete ? 'Outputs validated' : reviewComplete ? 'Verification incomplete' : 'Incomplete review';
const incompleteLabel = reviewComplete ? 'INCOMPLETE VERIFICATION' : 'INCOMPLETE REVIEW';
const toneOf = (level) => ({ critical: 'red', high: 'red', medium: 'orange', low: 'blue', info: 'blue' })[level] || 'blue';
const shortSurface = { S1: 'Identity & access', S2: 'Input & injection', S3: 'Logic & value', S4: 'Secrets & config', S5: 'Dependencies', S6: 'Client & web' };

// Format only inert text; source Markdown never supplies links, HTML or attributes.
function inline(value) {
  return esc(value).replace(/`([^`\n]+)`/g, '<code>$1</code>').replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
}
function prose(value) {
  return String(value || '').split(/(```[\s\S]*?```)/g).map((part) => {
    if (part.startsWith('```')) return `<pre><code>${esc(part.replace(/^```[^\n]*\n?/, '').replace(/```$/, ''))}</code></pre>`;
    return part.split(/\n\s*\n/).filter(Boolean).map((block) => {
      const lines = block.split('\n');
      if (lines.every((line) => /^\s*[-*] /.test(line))) return `<ul>${lines.map((line) => `<li>${inline(line.replace(/^\s*[-*] /, ''))}</li>`).join('')}</ul>`;
      if (lines.every((line) => /^\s*\d+\. /.test(line))) return `<ol>${lines.map((line) => `<li>${inline(line.replace(/^\s*\d+\. /, ''))}</li>`).join('')}</ol>`;
      return `<p>${inline(block)}</p>`;
    }).join('');
  }).join('');
}
const block = (title, text, tone = '') => text ? `<div class="content-block ${tone}"><h4>${esc(title)}</h4><div class="prose">${prose(text)}</div></div>` : '';
const citations = (items) => items?.length ? `<div class="citations">${items.map(item => `<code>${esc(item)}</code>`).join('')}</div>` : '';
const disclosure = (title, body) => `<details class="disclosure"><summary>${esc(title)}</summary>${body}</details>`;

// Scored clusters retain only a short impact. Recover full analysis from accepted claims.
const originalClaims = new Map();
for (const report of reports) {
  report.data.filter(item => item.title && !item.verified_safe).forEach((item, index) => originalClaims.set(`${report.name}#${index}`, item));
}
function findingCard(f, index) {
  const originals = (f.claimIds || []).map(id => originalClaims.get(id)).filter(Boolean);
  const primary = originals[0] || f.findings?.[0] || {};
  const impact = primary.impact || 'No impact statement was provided by the auditor.';
  const status = String(f.status || '').replace(/_/g, ' ').toLowerCase();
  const reviews = Array.isArray(f.reviews) ? f.reviews : [];
  const technical = originals.length ? originals : [primary];
  return `<details class="finding ${toneOf(f.severity)}" data-severity="${esc(severityLevel(f.severity))}" data-surface="${esc(String(f.surface).toUpperCase().slice(0, 2))}">
    <summary><span class="finding-index">${String(index + 1).padStart(2, '0')}</span><div>
      <div class="finding-tags"><span class="pill ${toneOf(f.severity)}">${esc(f.severity)}</span><span class="meta-label">${esc(f.surface)}</span><span class="pill">${esc(status)}</span></div>
      <h3>${esc(f.title)}</h3><p class="finding-preview">${esc(impact)}</p>
    </div><span class="expand-icon" aria-hidden="true"></span></summary>
    <div class="finding-body">
      <div class="finding-priority"><strong>Priority ${esc(f.score)}</strong><span>Heuristic · not a probability</span><span>${esc((f.auditors || f.vendors || []).join(' · '))}</span></div>
      <div class="action-grid">${block('Impact', impact, 'red')}${block('Recommended fix', f.remediation || primary.fix || 'No fix was provided.', 'green')}</div>
      ${disclosure('Source analysis & validation', technical.map((claim, i) => `${technical.length > 1 ? `<p class="meta-label">Claim ${i + 1} · ${esc(f.claimIds?.[i] || '')}</p>` : ''}${block('Preconditions', claim.preconditions)}${block('Analysis', claim.analysis)}${block('Validation & limits', claim.validation)}${claim.attack?.length ? block('Historical review notes', claim.attack.join('\n\n')) : ''}`).join(''))}
      ${f.locations?.length ? disclosure(`Affected files · ${f.locations.length}`, citations(f.locations)) : ''}
      ${reviews.length ? disclosure(`Peer reviews · ${reviews.length}`, `<p class="note">Model statements; no independent reproduction evidence.</p>${reviews.map(r => `<div class="review"><span class="pill ${r.verdict === 'refuted' ? 'red' : r.verdict === 'upheld' ? 'green' : 'orange'}">${esc(r.reviewer)} · ${esc(r.verdict)}</span><div class="prose">${prose(r.reason)}</div>${citations(r.evidence)}</div>`).join('')}`) : ''}
      ${f.pocs?.length ? disclosure('Historical regression material · unexecuted', `<pre>${esc(f.pocs.join('\n'))}</pre>`) : ''}
    </div></details>`;
}

function rail(modelPage) {
  return `<aside class="rail"><a href="report.html" class="brand"><span class="emblem" aria-hidden="true"></span><span>AUDIT / CORE<small>SOURCE SECURITY REVIEW</small></span></a>
    <div class="rail-label">Report navigation</div><nav aria-label="Report">
    <a href="report.html" ${!modelPage ? 'class="active" aria-current="page"' : ''}><span>01</span>Overview</a>
    <a href="${modelPage ? 'report.html' : ''}#findings"><span>02</span>Findings <small>${counts.total}</small></a>
    <a href="findings-by-model.html" ${modelPage ? 'class="active" aria-current="page"' : ''}><span>03</span>By model</a>
    <a href="${modelPage ? 'report.html' : ''}#evidence"><span>04</span>Evidence & scope</a></nav>
    <div class="rail-bottom"><span class="signal"></span>SAVED REVIEW<br>${esc(dateLabel)}<br>REF / ${esc(meta.commit || 'not recorded')}</div></aside>`;
}
function page(body, modelPage = false) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta http-equiv="Content-Security-Policy" content="${esc(policy)}"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(targetName)} — ${modelPage ? 'Findings by model' : 'Security audit'}</title><style>${styles}</style></head>
    <body><a class="skip-link" href="#main">Skip to report</a>${rail(modelPage)}<div class="workspace">
    <div class="topbar"><span><b>Security intelligence</b> / ${modelPage ? 'Model comparison' : 'Audit overview'}</span><span class="topbar-detail">${esc(dateLabel)} &nbsp; / &nbsp; ${expected} review assignments</span></div>
    <main id="main">${body}<footer class="footer"><span>Audit / Core · Source security review</span><span>Model assertions · Unverified provenance</span><span>${esc(meta.commit || dateLabel)}</span></footer></main></div>
    ${!modelPage ? `<script nonce="${nonce}">${browserScript}</script>` : ''}</body></html>`;
}
function hero(modelPage = false) {
  return `<header class="hero"><div><div class="eyebrow">${modelPage ? 'Reviewer output / 03' : 'Source assessment / 01'}</div><h1>${modelPage ? 'MODEL <span>REPORT.</span>' : 'AUDIT <span>REPORT.</span>'}</h1><p class="target">${esc(targetName)}</p><div class="source">${esc([meta.mode === 'remote' ? 'GITHUB' : 'SOURCE', meta.commit && `REF ${meta.commit}`, meta.surface && `SCOPE ${meta.surface}`].filter(Boolean).join(' / '))}</div></div>
    <div class="hero-status"><span class="eyebrow">${statusLabel}</span><strong>${accepted} / ${expected} assignments</strong><p>${reviewComplete ? 'Review outputs accepted. Claims remain unverified.' : 'Review coverage gaps remain. See evidence & scope.'}</p><div class="progress" aria-hidden="true">${Array.from({ length: expected }, (_, i) => `<i${i < accepted ? ' class="done"' : ''}></i>`).join('')}</div></div></header>`;
}
const notice = `<div class="notice"><b>${complete ? 'UNVERIFIED CLAIMS' : incompleteLabel}</b><span>Model assertions, not a safety certificate. ${complete ? 'Zero findings does not prove safety.' : reviewComplete ? 'Review outputs are complete; required execution coverage still has gaps.' : 'Missing reviews are not passes.'}</span><a href="report.html#validation">View limitations ↗</a></div>`;
const sectionTitle = (id, title, side = '') => `<div class="section-heading"><h2><span class="section-num">${id}</span>${title}</h2>${side ? `<span class="meta-label">${esc(side)}</span>` : ''}</div>`;
const requestedModels = modelRows.map(row => `<tr><td><strong>${esc(row.key)}</strong></td><td>${esc(row.label)}</td><td>${row.available ? 'Valid outputs available' : 'no valid outputs'}</td></tr>`).join('');
const validationDetails = `<p class="note"><strong>${complete ? 'OUTPUTS VALIDATED — NOT A CLEAN-AUDIT CERTIFICATE' : incompleteLabel}</strong>. These are unverified model assertions. No authenticated execution evidence or served-model/provider attestation was collected. Zero findings is not proof of safety.</p>
  ${(health.errors || []).length ? `<ul class="validation-errors">${health.errors.map(error => `<li>${esc(error)}</li>`).join('')}</ul>` : ''}
  <p class="note">Agreement means matching titles and citations across asserted adapters. First-pass independence and served-provider identity are not enforced. Peer verdicts are model statements; priority scores are heuristic.</p>
  <div class="table-scroll"><table><caption class="meta-label">Requested models · served identity unverified</caption><thead><tr><th>Adapter</th><th>Requested model</th><th>Output</th></tr></thead><tbody>${requestedModels}</tbody></table></div>
  ${sourceLine ? `<p class="note">Captured source: <code>${esc(sourceLine)}</code></p>` : ''}
  ${meta.isolation?.sourceDigest ? `<p class="note">Snapshot SHA-256: <code>${esc(meta.isolation.sourceDigest)}</code></p>` : ''}`;
const isolationDetails = meta.isolation?.policy === 'read_only_source_review'
  ? `<h3>Read-only worker isolation policy</h3><p class="note">Live transport is blocked: subscription delegation and tools-disabled transport are not verified. No host reviewer fallback, model call, lead scanner or target build was started. These are parent-recorded blocked jobs, not successful reviews.</p>${workerJobs.map(j => `<p class="note">${esc(j.name)} · ${esc(j.state)} · ${esc(j.reason || '')}</p>`).join('')}`
  : meta.isolation?.policy === 'report_finalization'
    ? `<h3>Saved review finalization</h3><p class="note">No new Docker container, build, test, scanner or source inspection ran during finalization. Coverage was copied from <code>${esc(meta.recovery?.fromReport || 'the prior review')}</code> for the same source digest; untested coverage is not a pass.</p>` : '';
const sandboxDetails = sandboxRows.length
  ? `<p class="note">${sandboxRows.filter(r => r.result === 'ran').length} finished · ${sandboxRows.filter(r => r.result === 'failed').length} failed · ${sandboxRows.filter(r => r.result === 'impossible').length} not started. Sandbox-reported records are not authenticated execution evidence. Finished does not mean passed; failed or not started is not a pass.</p><div class="table-scroll"><table><thead><tr><th>Check</th><th>Observed status</th><th>Coverage & limits</th></tr></thead><tbody>${sandboxRows.map(r => `<tr><td>${esc(r.name)}</td><td class="result-${r.result}">${r.result === 'impossible' ? 'Not started' : r.result === 'ran' ? 'Finished' : 'Failed'}</td><td>${esc(r.detail)}</td></tr>`).join('')}</tbody></table></div>`
  : '<p class="note">Sandbox coverage unavailable or invalid — not a pass.</p>';
// Per-ecosystem coverage: what was detected, which existing suites ran, and which scanners were required but incomplete.
function stackCoverage() {
  const profile = readJson('harness/stack-profile.json', null);
  const catalog = readJson('harness/existing-tests.json', { tests: [] });
  const verification = health.verification || {};
  const suites = new Map((verification.suites || []).map(suite => [suite.id, suite.state]));
  const gaps = verification.gaps || [];
  const eco = profile?.ecosystems;
  if (!eco) return '<p class="note">Stack profile unavailable or predates ecosystem detection; per-stack coverage cannot be derived.</p>';
  const suiteRows = kinds => (catalog.tests || []).filter(test => kinds.includes(test.kind)).map(test => `${test.description}: ${suites.get(test.id) === 'passed' ? 'passed' : suites.get(test.id) === 'failed_or_unverified' ? 'failed or unverified' : 'not run'}`);
  const gapRows = pattern => gaps.filter(gap => pattern.test(gap));
  const rows = [
    ['Python', eco.python.detected, `${eco.python.sourceFiles} production files; ${eco.python.frameworks.join(', ') || 'no framework recognised'}${eco.python.declaredVersion ? `; declared Python ${eco.python.declaredVersion.version}` : ''}`, suiteRows(['pytest']), gapRows(/python-deps|osv-scanner|semgrep|pytest/)],
    ['Node / TypeScript', eco.node.detected, `${eco.node.sourceFiles} production files; ${eco.node.frameworks.join(', ') || 'no framework recognised'}`, suiteRows(['npm']), gapRows(/npm-audit|node-deps|npm existing/)],
    ['Solana program', eco.solana.detected, eco.solana.marks.join(', ') || 'none', suiteRows(['cargo']), [...gapRows(/cargo-audit|cargo existing/), 'Reproducible build and deployed-bytes comparison are outside this review by policy.']],
  ];
  return `<div class="table-scroll"><table><thead><tr><th>Stack</th><th>Detected</th><th>Existing tests</th><th>Open coverage gaps</th></tr></thead><tbody>${rows.map(([name, detected, detail, tests, open]) => `<tr><td><b>${esc(name)}</b><br><small>${esc(detail)}</small></td><td>${detected ? 'yes' : 'absent'}</td><td>${detected ? (tests.length ? tests.map(esc).join('<br>') : 'no suite catalogued') : '—'}</td><td>${detected ? (open.length ? open.map(esc).join('<br>') : 'none recorded') : '—'}</td></tr>`).join('')}</tbody></table></div><p class="note">Source review of a detected stack is performed by the assigned surfaces S1–S6 (see the surface map); this table shows only tool-reported test and scanner coverage. A failed or missing item is not a pass.</p>`;
}
const controlsDetails = verifiedSafe.length ? `<details class="panel"><summary><span class="pill green">Controls</span>Auditor control assertions<span class="meta-label">${verifiedSafe.length} reported</span></summary><div class="panel-body"><p class="note">Unverified model assertions, not certified controls. Contradiction detection and tiebreak escalation are not implemented.</p><div class="controls-list">${verifiedSafe.map(s => `<details class="control"><summary><span>${esc(s.control)}</span><span class="pill ${s.holds === false ? 'red' : 'green'}">${s.holds === false ? 'Reported broken' : 'Reported holding'}</span></summary><div class="prose">${prose(s.evidence || s.how_attacked)}<p class="meta-label">${esc(s.auditor)} · unverified</p></div></details>`).join('')}</div></div></details>` : '';

const html = page(`${hero()}${notice}
  <section class="stats" aria-label="Finding totals">
    ${[
      ['red', 'High severity', counts.high, 'Critical + high model claims', '01'],
      ['orange', 'Medium severity', counts.medium, 'Medium model claims', '02'],
      ['blue', 'Low + info', counts.low + counts.info, 'Lower severity model claims', '03'],
      ['green', 'Model agreement', counts.modelAgreement, 'Matching claims · unverified', '04'],
    ].map(([tone, label, number, detail, index]) => `<div class="stat ${tone}"><div class="stat-label">${label}<span>${index}</span></div><div class="stat-number">${number}</div><small>${detail}</small></div>`).join('')}
  </section>
  <section aria-labelledby="surface-heading">${sectionTitle('01', '<span id="surface-heading">Surface map</span>', 'Select a surface to filter')}<div class="surface-grid">
    ${Object.entries(SURFACE_NAMES).map(([id, label]) => {
      const s = surfaces[id];
      const assignments = (health.expected || []).filter(name => String(name).includes(`-${id.toLowerCase()}-`));
      const valid = assignments.filter(name => (health.accepted || []).includes(name)).length;
      const missing = assignments.length > valid;
      const coverage = !assignments.length ? 'Outside scope' : missing ? 'Review incomplete' : 'Outputs received';
      return `<button type="button" class="surface" data-surface-filter="${id}" aria-pressed="false" aria-label="Filter ${id}: ${esc(label)}, ${s.total} findings. ${coverage}"><div><div class="surface-code">${id} / ${String(Object.keys(SURFACE_NAMES).indexOf(id) + 1).padStart(2, '0')}</div><div class="surface-name">${esc(shortSurface[id])}</div></div><span class="surface-total">${s.total}</span><div class="surface-bottom">${s.total ? `<span><span class="red">${s.high}H</span> / <span class="orange">${s.medium}M</span> / <span class="blue">${s.low + s.info}L</span></span>` : '<span class="no-claims">No claims</span>'}<span class="${missing ? 'coverage-gap' : 'no-claims'}">${!assignments.length ? 'Out of scope' : missing ? 'Incomplete' : `${valid}/${assignments.length} received`}</span></div></button>`;
    }).join('')}
  </div></section>
  <section id="findings" aria-label="Findings">${sectionTitle('02', 'Findings', `${counts.total} prioritized model claims`)}
    <div class="toolbar"><div class="filter-group" role="group" aria-label="Filter by severity">
      ${[['all', 'All', counts.total], ['high', 'High+', counts.high], ['medium', 'Medium', counts.medium], ['low', 'Low + info', counts.low + counts.info]].map(([key, label, n]) => `<button type="button" class="filter-btn${key === 'all' ? ' active' : ''}" data-filter="${key}" aria-pressed="${key === 'all'}">${label}<span>${n}</span></button>`).join('')}
    </div><label class="search-wrap"><span aria-hidden="true">⌕</span><input type="search" id="search-box" aria-label="Search findings, files, fixes and evidence" placeholder="Search findings, files, fixes…"></label></div>
    <div class="list-caption"><span id="results-count" role="status" aria-live="polite">${counts.total} / ${counts.total} findings</span><button type="button" id="reset-filters" class="text-button" hidden>Clear filters</button><button type="button" id="expand-all" class="text-button">Expand findings</button></div>
    <div id="findings-container">${findings.map(findingCard).join('')}</div><div class="empty" id="empty-results" hidden>No findings match. Try another filter or search.</div>
  </section>
  <section id="evidence" aria-label="Evidence and scope">${sectionTitle('03', 'Evidence & scope', 'Full detail on demand')}
    <details class="panel" id="validation"><summary><span class="pill orange">${complete ? 'Validated' : 'Incomplete'}</span>Review status & limitations<span class="meta-label">${health.errors?.length || 0} gaps</span></summary><div class="panel-body">${validationDetails}${isolationDetails}</div></details>
    <details class="panel"><summary><span class="pill blue">Coverage</span>Sandbox & checks<span class="meta-label">${sandboxRows.length} records</span></summary><div class="panel-body">${sandboxDetails}${sandboxMd ? disclosure('Original sandbox record', `<pre>${esc(sandboxMd)}</pre>`) : ''}</div></details>
    <details class="panel"><summary><span class="pill blue">Stacks</span>Coverage by stack<span class="meta-label">Python · Node · Solana</span></summary><div class="panel-body">${stackCoverage()}</div></details>
    ${controlsDetails}
    ${diagrams.length ? `<details class="panel"><summary>Attached diagram source<span class="meta-label">${diagrams.length} files</span></summary><div class="panel-body"><p class="note">Attachments are displayed as inert source.</p>${diagrams.map(d => disclosure(d.title, `<pre>${esc(d.svg)}</pre>`)).join('')}</div></details>` : ''}
  </section>`);

const modelHtml = page(`${hero(true)}${notice}${sectionTitle('03', 'Findings by model', 'Before deduplication')}
  <p class="note">Each model’s own claims, before merging. Critical is grouped with high. Counts measure output, not reviewer quality.</p>
  <section class="panel"><ul class="legend">${modelLevels.map(level => `<li><i class="swatch swatch-${SEVERITY_LEVELS.includes(level) ? level : 'other'}" aria-hidden="true"></i>${esc(level)}</li>`).join('')}</ul><div aria-hidden="true">${modelChart()}</div></section>
  <section class="panel model-meta"><h2>Severity breakdown</h2><div class="table-scroll">${modelTable()}</div></section>
  <details class="panel"><summary>Requested models & validation<span class="meta-label">Identity unverified</span></summary><div class="panel-body">${validationDetails}${isolationDetails}</div></details>`, true);

writeReportFile(reportDir, 'report.html', html);
writeReportFile(reportDir, 'findings-by-model.html', modelHtml);
console.log(`Standalone review pages written to ${reportDir}`);
if (health.state === 'incomplete') process.exitCode = 2;
