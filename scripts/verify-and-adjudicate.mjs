#!/usr/bin/env node
/**
 * verify-and-adjudicate.mjs
 *
 * Reads individual auditor JSON reports from a specified directory, clusters findings
 * conservatively by cited location and title, and records model review statements.
 * Scores are heuristic priorities, not execution evidence or calibrated confidence.
 *
 * Legacy title-substring tiebreak files are excluded as untrusted overrides.
 *
 * Cross-check: auditors/crosscheck-<agent>.json is an array of
 *   { id: '<auditor>#<index>', verdict: 'upheld'|'partial'|'refuted', severity?, reason?, evidence? }
 * The id is the auditor file stem plus the index of that finding (objects with a title, skipping verified_safe).
 * A review from the same asserted adapter provider is ignored.
 *
 * Usage:
 *   node audit/scripts/verify-and-adjudicate.mjs [<report-dir>]   (default: newest dir under audit/reports)
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadAuditors, providerOf, readReportJson, validCrosscheckRow, writeReportFile } from './report-contract.mjs';

function newestReportDir() {
  const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'reports');
  if (!fs.existsSync(root)) return null;
  const dirs = fs.readdirSync(root, { withFileTypes: true })
    .filter((d) => d.isDirectory() && fs.existsSync(path.join(root, d.name, 'auditors')))
    .map((d) => ({ dir: path.join(root, d.name), mtime: fs.statSync(path.join(root, d.name)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime);
  return dirs[0]?.dir || null;
}

const reportDir = process.argv[2] || newestReportDir();
if (!reportDir) {
  console.error('No report directory given and none found under audit/reports');
  process.exit(1);
}
const auditorsDir = path.join(reportDir, 'auditors');


const SEVERITY_WEIGHT = {
  critical: 10.0,
  high: 8.5,
  medium: 5.5,
  low: 2.5,
  info: 1.0,
};

const { reports, health, assignments } = loadAuditors(reportDir);
const initialErrorCount = health.errors.length;
const jsonFiles = reports.map((r) => `${r.name}.json`);
const allFindings = [];
const allVerifiedSafe = [];

for (const { name: auditorName, data } of reports) {
  const findings = data.slice(0, -1).map((x, i) => ({ ...x, claimId: `${auditorName}#${i}` }));
  for (const f of findings) allFindings.push({ ...f, auditor: auditorName });
  for (const s of data.at(-1).verified_safe) allVerifiedSafe.push({ ...s, auditor: auditorName, evidence: 'model_assertion' });
}

// Cluster findings by signature / surface / target
const clusters = [];

function findCluster(finding) {
  const normTitle = finding.title.toLowerCase();
  for (const c of clusters) {
    if (c.surface.slice(0, 2) !== finding.surface.slice(0, 2)) continue;
    // Shared prose alone is not a shared root cause.
    if (normTitle === c.normTitle && c.findings.some((f) => f.location.some((p) => finding.location.includes(p)))) {
      return c;
    }
  }
  return null;
}

for (const f of allFindings) {
  const existing = findCluster(f);
  if (existing) {
    existing.findings.push(f);
    if (!existing.auditors.includes(f.auditor)) existing.auditors.push(f.auditor);
    if (f.claimId && !existing.claimIds.includes(f.claimId)) existing.claimIds.push(f.claimId);
    // Upgrade confidence if any has confirmed
    if (String(f.confidence).startsWith('confirmed')) existing.confidence = 'confirmed';
    if (SEVERITY_WEIGHT[f.severity] > SEVERITY_WEIGHT[existing.severity]) {
      existing.severity = f.severity;
    }
  } else {
    const norm = f.title.toLowerCase();
    clusters.push({
      id: `CLUSTER-${clusters.length + 1}`,
      surface: f.surface,
      primaryTitle: f.title,
      normTitle: norm,
      severity: f.severity || 'medium',
      confidence: f.confidence || 'probable',
      auditors: [f.auditor],
      claimIds: f.claimId ? [f.claimId] : [],
      findings: [f],
    });
  }
}

function readJsonArray(file) {
  try {
    const rows = readReportJson(reportDir, path.relative(reportDir, file));
    if (!Array.isArray(rows) || rows.length > 10_000) throw new Error('expected bounded array');
    return rows;
  } catch {
    health.errors.push('Invalid cross-check JSON was excluded.');
    return [];
  }
}

const reviewsByClaim = new Map();
const claimAuthors = new Map(allFindings.map((f) => [f.claimId, providerOf(f.auditor)]));
for (const file of (fs.existsSync(auditorsDir) ? fs.readdirSync(auditorsDir) : []).filter((f) => f.startsWith('crosscheck-') && f.endsWith('.json'))) {
  const reviewer = file.slice('crosscheck-'.length, -'.json'.length);
  if (!Object.hasOwn(assignments, reviewer)) {
    health.errors.push('Unknown cross-check reviewer was excluded.');
    continue;
  }
  const seen = new Set();
  for (const row of readJsonArray(path.join(auditorsDir, file))) {
    const verdict = row?.verdict;
    if (!validCrosscheckRow(row) || !assignments[reviewer].includes(row.id) || seen.has(row.id)) {
      health.errors.push(`${file}: invalid or duplicate cross-check entry was excluded.`);
      continue;
    }
    seen.add(row.id);
    const list = reviewsByClaim.get(String(row.id)) || [];
    list.push({
      claimId: row.id,
      reviewer,
      verdict,
      severity: row.severity ? String(row.severity).toLowerCase() : '',
      reason: String(row.reason || '').slice(0, 800),
      evidence: Array.isArray(row.evidence) ? row.evidence.map(String).slice(0, 8) : [],
    });
    reviewsByClaim.set(String(row.id), list);
  }
  if (assignments[reviewer].some((id) => !seen.has(id))) health.errors.push(`${file}: cross-check verdicts do not cover every assigned claim.`);
}

function applyReview(status, cluster) {
  const reviews = [];
  for (const id of cluster.claimIds || []) {
    for (const row of reviewsByClaim.get(id) || []) {
      if (claimAuthors.get(id) === providerOf(`${row.reviewer}-s1-auth`)) continue;
      reviews.push(row);
    }
  }
  if (!reviews.length) return { status, reviews };
  const upheld = reviews.some((r) => r.verdict === 'upheld');
  const refuted = reviews.some((r) => r.verdict === 'refuted');
  const partial = reviews.some((r) => r.verdict === 'partial');
  let next = status;
  if (refuted && upheld) next = 'PARTIAL_REVIEW';
  else if (refuted && status === 'MODEL_AGREEMENT') next = 'PARTIAL_REVIEW';
  else if (refuted) next = 'REFUTED_REVIEW';
  else if (partial) next = 'PARTIAL_REVIEW';
  else if (upheld && status !== 'MODEL_AGREEMENT') next = 'UPHELD_REVIEW';
  else if (!upheld && !refuted) next = 'PARTIAL_REVIEW';
  const severities = reviews.map((r) => r.severity).filter((s) => SEVERITY_WEIGHT[s] != null);
  if (next === 'PARTIAL_REVIEW' && severities.length && severities.every((s) => s === severities[0])) {
    cluster.severity = severities[0];
  }
  return { status: next, reviews };
}


const scoredFindings = clusters.map((c) => {
  const vendorSet = new Set(c.auditors.map(providerOf).filter(Boolean));

  let status = 'MODEL_ASSERTION';
  if (vendorSet.size >= 2) {
    status = 'MODEL_AGREEMENT';
  }

  const reviewed = applyReview(status, c);
  status = reviewed.status;


  const baseScore = SEVERITY_WEIGHT[c.severity] || 5.0;
  const quorumMultiplier = status === 'MODEL_AGREEMENT' ? 0.8 :
                           status === 'UPHELD_REVIEW' ? 0.75 :
                           status === 'PARTIAL_REVIEW' ? 0.7 :
                           status === 'REFUTED_REVIEW' ? 0.0 : 0.6;
  const finalScore = Number((baseScore * quorumMultiplier).toFixed(1));

  return {
    clusterId: c.id,
    surface: c.surface,
    title: c.primaryTitle,
    severity: c.severity,
    confidence: c.confidence,
    status,
    score: finalScore,
    vendors: Array.from(vendorSet),
    provenance: 'unverified_adapter_identity',
    executionEvidence: 'not_collected',
    auditorCount: c.auditors.length,
    auditors: c.auditors,
    claimIds: c.claimIds,
    reviews: reviewed.reviews,
    locations: Array.from(new Set(c.findings.flatMap((f) => f.location || []))),
    pocs: c.findings.map((f) => f.poc).filter(Boolean),
    remediation: c.findings[0]?.fix || null,
    // the HTML report reads findings[0] for the harm / attack sections
    findings: c.findings.slice(0, 1).map(({ impact, preconditions, attack }) => ({ impact, preconditions, attack })),
  };
});

// Sort by score descending
scoredFindings.sort((a, b) => b.score - a.score);

const outputJsonPath = path.join(reportDir, 'findings-and-scores.json');
writeReportFile(reportDir, 'findings-and-scores.json', JSON.stringify(scoredFindings, null, 2));
// controls the auditors attacked that held, for the HTML report
writeReportFile(reportDir, 'verified-safe.json', JSON.stringify(allVerifiedSafe, null, 2));
health.security = { state: scoredFindings.some(row => row.status !== 'REFUTED_REVIEW') ? 'review_required' : 'not_certified', unresolvedClaims: scoredFindings.filter(row => row.status !== 'REFUTED_REVIEW').length, note: 'Valid reports and passing tests do not certify security or accept residual risks.' };
if (health.errors.length > initialErrorCount) health.reviewState = 'incomplete';
health.state = health.errors.length ? 'incomplete' : 'validated_outputs';
writeReportFile(reportDir, 'report-health.json', `${JSON.stringify(health, null, 2)}\n`);

console.log(`\n======================================================`);
console.log(` Output validation: ${health.state}; ${scoredFindings.length} model-claim clusters`);
console.log(` Processed from ${allFindings.length} raw findings across ${jsonFiles.length} auditors`);
console.log(` Findings & scores written to: ${outputJsonPath}`);
console.log(`======================================================\n`);

console.log(
  'Score'.padEnd(7) +
  'Severity'.padEnd(10) +
  'Status'.padEnd(22) +
  'Vendors'.padEnd(20) +
  'Finding'
);
console.log('-'.repeat(90));

for (const f of scoredFindings) {
  console.log(
    String(f.score).padEnd(7) +
    f.severity.toUpperCase().padEnd(10) +
    f.status.padEnd(22) +
    f.vendors.join(',').padEnd(20) +
    f.title.slice(0, 50)
  );
}
if (health.state === 'incomplete') {
  console.error(health.reviewState === 'validated_outputs'
    ? 'INCOMPLETE VERIFICATION: review outputs validated, but required execution coverage has gaps; this is not a security pass.'
    : 'INCOMPLETE: missing, failed or invalid review outputs; zero findings is not a clean audit.');
  for (const error of health.errors) console.error(`  - ${error}`);
  process.exitCode = 2;
}
