// Scanner exits and schemas are evidence; an error-shaped JSON object is never a clean scan.
export function scannerEvidence(tool, result) {
  const row = { tool, exitCode: result.code, state: 'failed', findings: null };
  try {
    if (![0, 1].includes(result.code)) return row;
    const data = JSON.parse(result.stdout);
    let findings;
    if (tool === 'gitleaks' && Array.isArray(data)) findings = data.length;
    if (tool === 'semgrep' && Array.isArray(data.results) && Array.isArray(data.errors) && !data.errors.length) findings = data.results.length;
    if (tool === 'osv-scanner' && Array.isArray(data.results)) findings = data.results.reduce((n, group) => n + group.packages.reduce((m, pkg) => m + (pkg.vulnerabilities || []).length, 0), 0);
    if (tool === 'cargo-audit' && Array.isArray(data.vulnerabilities?.list)) findings = data.vulnerabilities.list.length;
    if (tool === 'npm-audit' && data.metadata?.vulnerabilities && data.vulnerabilities && !data.error) findings = Object.keys(data.vulnerabilities).length;
    if (!Number.isSafeInteger(findings) || findings < 0 || result.code === 1 && findings === 0) return row;
    return { ...row, state: findings ? 'findings' : 'passed', findings };
  } catch { return row; }
}

export function testCounts(stdout) {
  const rust = [...stdout.matchAll(/test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored/g)];
  if (rust.length) return rust.reduce((sum, match) => ({ passed: sum.passed + Number(match[1]), failed: sum.failed + Number(match[2]), skipped: sum.skipped + Number(match[3]) }), { passed: 0, failed: 0, skipped: 0 });
  const value = key => stdout.match(new RegExp('^# ' + key + ' (\\d+)\\s*$', 'm'))?.[1];
  if (value('pass') != null && value('fail') != null) return { passed: Number(value('pass')), failed: Number(value('fail')), skipped: Number(value('skipped') || 0) + Number(value('todo') || 0) };
  return null;
}
export function missingTestArtifact(stderr) {
  const name = String(stderr).match(/couldn't read [^\n]*\/deploy\/([A-Za-z0-9_-]+\.so)[^\n]*No such file or directory/)?.[1];
  return name ? `Missing program artifact deploy/${name}; build it separately and supply --test-artifacts <cargo-target-dir>.` : null;
}
