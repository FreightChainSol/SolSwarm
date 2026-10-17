import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { readReportJson, writeReportFile, validateAuditor, validCrosscheckRow } from './report-contract.mjs';

const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const fingerprint = value => crypto.createHash('sha256').update(JSON.stringify(stable(value))).digest('hex');
const validKey = key => /^(?:(?:claude|grok|agy|codex)-s[1-6]-(?:auth|input|logic|config|deps|client)|crosscheck-(?:claude|grok|agy|codex))$/.test(key);

export function validateSubmissionIdentity(identity, key) {
  if (!validKey(key) || !identity || !['auditor', 'crosscheck'].includes(identity.role) || !/^[a-f0-9]{64}$/.test(identity.sourceDigest) || !/^[a-f0-9]{64}$/.test(identity.assignmentDigest) || !/^[\w.:-]{1,128}$/.test(identity.model) || !['claude', 'codex', 'grok', 'agy'].includes(identity.agent) || identity.name !== key) throw new Error('Invalid submission identity');
  if (identity.role === 'crosscheck' ? key !== `crosscheck-${identity.agent}` : !key.startsWith(`${identity.agent}-`)) throw new Error('Submission reviewer mismatch');
  return identity;
}

export function commitSubmission(root, key, identity, payload, summary = '') {
  validateSubmissionIdentity(identity, key);
  if (identity.role === 'auditor') validateAuditor(payload, key);
  else if (!Array.isArray(payload) || !payload.every(validCrosscheckRow)) throw new Error('Invalid canonical peer report');
  if (typeof summary !== 'string' || Buffer.byteLength(summary) > 2 * 1024 * 1024) throw new Error('Invalid report summary');
  const report = { payload, summary };
  const hash = fingerprint(report);
  fs.mkdirSync(path.join(root, 'submissions'), { recursive: true, mode: 0o700 });
  const file = `submissions/${key}.json`;
  if (fs.existsSync(path.join(root, file))) {
    const previous = readCanonicalSubmission(root, key, identity);
    if (previous.hash !== hash) throw new Error('A different report is already committed for this assignment. Do not replace a committed report with a second result.');
    return previous;
  }
  const submission = { version: 1, identity, hash, report, committedAt: new Date().toISOString() };
  const temporary = `submissions/${key}.next.json`;
  writeReportFile(root, temporary, JSON.stringify(submission, null, 2) + '\n');
  fs.renameSync(path.join(root, temporary), path.join(root, file));
  return submission;
}

export function readCanonicalSubmission(root, key, identity) {
  validateSubmissionIdentity(identity, key);
  const value = readReportJson(root, `submissions/${key}.json`, 4 * 1024 * 1024);
  if (value.version !== 1 || !isDeepStrictEqual(value.identity, identity) || value.hash !== fingerprint(value.report)) throw new Error('Canonical submission identity or hash mismatch');
  if (identity.role === 'auditor') validateAuditor(value.report.payload, key);
  else if (!Array.isArray(value.report.payload) || !value.report.payload.every(validCrosscheckRow)) throw new Error('Invalid canonical peer report');
  return value;
}

export function deriveSubmission(root, submission, renderMarkdown) {
  const { identity, report } = submission;
  fs.mkdirSync(path.join(root, 'auditors'), { recursive: true, mode: 0o700 });
  writeReportFile(root, `auditors/${identity.name}.json`, JSON.stringify(report.payload, null, 2) + '\n');
  if (identity.role === 'auditor') {
    const findings = report.payload.slice(0, -1);
    const controls = report.payload.at(-1).verified_safe;
    // Counts and finding details always come from the structured submission.
    const markdown = renderMarkdown(identity.name, findings[0]?.surface || identity.surface, findings, controls);
    writeReportFile(root, `auditors/${identity.name}.md`, markdown + (report.summary ? `\n## Reviewer scope and coverage notes\n\n${report.summary}\n` : ''));
  }
}
