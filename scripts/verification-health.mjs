import crypto from 'node:crypto';
import fs from 'node:fs';
import { scannerEvidence, testCounts, missingTestArtifact, dominantTestFailure } from './scanner-evidence.mjs';

// Review output validation and executed coverage are different gates.
export function verificationHealth(root, read) {
  const gaps = [], suites = [], scans = [];
  let manifest, catalog;
  try {
    manifest = read('source-manifest.json');
    catalog = read('harness/existing-tests.json');
    if (!Array.isArray(manifest.files) || catalog.sourceDigest !== manifest.digest || !Array.isArray(catalog.tests) || catalog.tests.some(entry => !entry || typeof entry.id !== 'string' || typeof entry.description !== 'string')) throw Error();
  } catch { catalog = null; gaps.push('Source-bound existing test catalog is missing or invalid.'); }
  const attempts = [];
  let files = [];
  try { files = fs.readdirSync(`${root}/harness`); } catch { gaps.push('Test evidence directory is missing.'); }
  for (const name of files.filter(name => /^existing-test-results-[\w-]+\.json$/.test(name))) {
    try {
      const rows = read(`harness/${name}`);
      if (!Array.isArray(rows) || rows.some(row => !row || typeof row !== 'object' || Array.isArray(row))) throw Error();
      attempts.push(...rows);
    } catch { gaps.push(`Invalid existing test evidence: ${name}.`); }
  }
  if (!catalog?.tests?.length) gaps.push('No executable test suite was catalogued; test coverage is unverified.');
  for (const entry of catalog?.tests || []) {
    const rows = attempts.filter(row => row.testId === entry.id && row.sourceDigest === manifest.digest);
    const details = new Set();
    let passed = rows.length > 0;
    for (const row of rows) {
      try {
        if (!/^harness\/existing-test-output-[\w-]+-\d+\.json$/.test(row.evidenceFile)) throw Error();
        const evidence = read(row.evidenceFile);
        const hash = crypto.createHash('sha256').update(JSON.stringify(evidence)).digest('hex');
        const counts = testCounts(evidence.stdout);
        if (hash !== row.evidenceHash) throw Error();
        if (row.exitCode !== 0) { const detail = missingTestArtifact(evidence.stderr); if (detail) details.add(detail); }
        // Aggregated per-crate summaries can sit in the omitted middle of an oversized output.
        if (evidence.omittedBytes) details.add(`Output exceeded the capture limit (${evidence.omittedBytes} bytes omitted).`);
        if (!(row.exitCode === 0 && counts?.passed > 0 && counts.failed === 0 && counts.skipped === 0 && !evidence.omittedBytes)) {
          passed = false;
          details.add(`Exit ${row.exitCode}; ${counts ? `${counts.passed} passed, ${counts.failed} failed or errored, ${counts.skipped} skipped` : 'no test summary in the output'}.`);
          const cause = dominantTestFailure(evidence.stdout);
          if (cause) details.add(`Most common failure (${cause.count}x): ${cause.message}`);
        }
      } catch { passed = false; gaps.push(`Missing or altered test output for ${entry.id}.`); }
    }
    suites.push({ id: entry.id, state: passed ? 'passed' : rows.length ? 'failed_or_unverified' : 'not_run', attempts: rows.length });
    if (!passed) gaps.push(`${entry.description}: no successful execution with nonzero test counts and no skipped tests.${details.size ? ' ' + [...details].join(' ') : ''}`);
  }
  try {
    const record = read('harness/scanner-results.json');
    if (record.version !== 1 || !Array.isArray(record.checks)) throw Error();
    const names = file => file.path.split('/').at(-1);
    const vendored = file => /(?:^|\/)(?:node_modules|vendor|dist|build|coverage|target|\.next|harness-fixtures|reports|\.cargo|__pycache__|\.venv|venv|env|\.tox|site-packages)\//.test(file.path);
    const hasNode = manifest.files.some(file => names(file) === 'package.json' && !vendored(file));
    const hasPython = manifest.files.some(file => !vendored(file) && /^(?:requirements[\w.-]*\.(?:txt|in)|pyproject\.toml|Pipfile(?:\.lock)?|poetry\.lock|uv\.lock|pdm\.lock)$/.test(names(file)));
    const tools = ['gitleaks', 'semgrep', 'osv-scanner', 'cargo-audit', 'npm-audit', ...(hasPython ? ['python-deps'] : []), ...(hasNode ? ['node-deps'] : [])];
    for (const tool of tools) {
      const rows = record.checks.filter(row => row.tool === tool);
      scans.push(...rows);
      const detail = rows.find(row => row.detail && !['passed', 'findings', 'not_applicable'].includes(row.state))?.detail;
      if (!rows.length || rows.some(row => !['passed', 'findings', 'not_applicable'].includes(row.state))) gaps.push(`${tool}: required scanner coverage is unavailable or failed.${detail ? ' ' + detail : ''}`);
      // Applicability is derived from the captured files, never a scanner's self-exemption.
      const locks = tool === 'cargo-audit' ? 'Cargo.lock' : tool === 'npm-audit' ? 'package-lock.json' : null;
      if (rows.some(row => row.state === 'not_applicable') && (!locks || manifest.files.some(file => file.path.split('/').at(-1) === locks))) gaps.push(`${tool}: invalid not-applicable claim.`);
      for (const row of rows.filter(row => ['passed', 'findings'].includes(row.state))) {
        if (!row.evidenceFile || !/^harness\/scanner-output-[\w-]+-\d+\.json$/.test(row.evidenceFile)) { gaps.push(`${tool}: scanner output evidence is missing.`); continue; }
        const evidence = read(row.evidenceFile);
        if (scannerEvidence(tool, evidence).state !== row.state) gaps.push(`${tool}: scanner output does not support its recorded status.`);
      }
    }
  } catch { gaps.push('Structured scanner evidence is missing or invalid.'); }
  return { state: gaps.length ? 'incomplete' : 'passed', gaps, suites, scans, scope: 'captured_source_and_existing_tests', outsideScope: ['private source absent from the supplied snapshot', 'deployed program bytes and production configuration', 'live service behavior'], evidenceLimit: 'Test counts and scanner results are tool-reported; they do not prove vulnerability reproduction or attest model identity.' };
}
