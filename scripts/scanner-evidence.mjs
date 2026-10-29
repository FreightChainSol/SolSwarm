// Scanner exits and schemas are evidence; an error-shaped JSON object is never a clean scan.
export function scannerEvidence(tool, result) {
  const row = { tool, exitCode: result.code, state: 'failed', findings: null };
  try {
    if (![0, 1].includes(result.code)) return row;
    const data = JSON.parse(result.stdout);
    let findings;
    if (tool === 'gitleaks' && Array.isArray(data)) findings = data.length;
    // Semgrep reports per-file parse problems as level "warn" and still scans every other file;
    // any other error (rule, config or fatal engine failure) leaves the scan incomplete.
    if (tool === 'semgrep' && Array.isArray(data.results) && Array.isArray(data.errors) && data.errors.every(error => error?.level === 'warn')) {
      findings = data.results.length;
      if (data.errors.length) row.parseWarnings = data.errors.length;
    }
    if (tool === 'osv-scanner' && Array.isArray(data.results)) findings = data.results.reduce((n, group) => n + group.packages.reduce((m, pkg) => m + (pkg.vulnerabilities || []).length, 0), 0);
    if (tool === 'cargo-audit' && Array.isArray(data.vulnerabilities?.list)) findings = data.vulnerabilities.list.length;
    // Resolvability record: only written when every Python requirement is exact-pinned or locked.
    if (tool === 'python-deps' && result.code === 0 && (data.pythonDeps?.unresolved === 0 || data.pythonDeps?.resolvedScan === true)) findings = 0;
    if (tool === 'node-deps' && result.code === 0 && data.nodeDeps?.unresolved === 0) findings = 0;
    if (tool === 'npm-audit' && data.metadata?.vulnerabilities && data.vulnerabilities && !data.error) findings = Object.keys(data.vulnerabilities).length;
    if (!Number.isSafeInteger(findings) || findings < 0 || result.code === 1 && findings === 0) return row;
    return { ...row, state: findings ? 'findings' : 'passed', findings };
  } catch { return row; }
}

export function testCounts(stdout) {
  const rust = [...stdout.matchAll(/test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored/g)];
  if (rust.length) return rust.reduce((sum, match) => ({ passed: sum.passed + Number(match[1]), failed: sum.failed + Number(match[2]), skipped: sum.skipped + Number(match[3]) }), { passed: 0, failed: 0, skipped: 0 });
  // pytest -q summary: "3 failed, 120 passed, 2 skipped, 1 error, 26 subtests passed in 4.21s"
  const pytest = stdout.match(/^=*\s*((?:\d+ [a-z]+(?: [a-z]+)?(?:, )?)+)\s+in [\d.]+s/m)?.[1];
  if (pytest) {
    const n = name => Number(pytest.match(new RegExp('(?:^|, )(\\d+) ' + name + '(?:,|$)'))?.[1] || 0);
    return { passed: n('passed'), failed: n('failed') + n('errors?'), skipped: n('skipped') + n('xfailed') };
  }
  // Vitest: "Tests  2 failed | 2371 passed | 3 skipped (2376)"; files that fail to load report only under "Test Files".
  const vitest = (label) => {
    const line = stdout.replace(/\x1b\[[0-9;]*m/g, '').match(new RegExp('^\\s*' + label + '\\s+((?:\\d+ [a-z]+(?: \\| )?)+)', 'm'))?.[1];
    const n = name => Number(line?.match(new RegExp('(\\d+) ' + name))?.[1] || 0);
    return line ? { passed: n('passed'), failed: n('failed'), skipped: n('skipped') + n('todo') } : null;
  };
  const tests = vitest('Tests'), files = vitest('Test Files');
  if (tests && files) return { passed: tests.passed, failed: tests.failed + files.failed, skipped: tests.skipped };
  const value = key => stdout.match(new RegExp('^(?:# |ℹ )' + key + ' (\\d+)\\s*$', 'm'))?.[1];
  if (value('pass') != null && value('fail') != null) return { passed: Number(value('pass')), failed: Number(value('fail')), skipped: Number(value('skipped') || 0) + Number(value('todo') || 0) };
  return null;
}
// pytest prints "E   <message>" under tracebacks and "FAILED|ERROR <test> - <message>" in its short
// summary; a shared cause names the coverage gap. Summary lines win when present.
export function dominantTestFailure(stdout) {
  const counts = new Map();
  const text = String(stdout);
  const summary = [...text.matchAll(/^(?:FAILED|ERROR) \S+ - (\S.{0,199})/gm)];
  for (const [, message] of summary.length ? summary : text.matchAll(/^E {3}(\S.{0,199})/gm)) counts.set(message, (counts.get(message) || 0) + 1);
  const [message, count] = [...counts].sort((a, b) => b[1] - a[1])[0] || [];
  return count >= 2 ? { message, count } : null;
}
export function missingTestArtifact(stderr) {
  const name = String(stderr).match(/couldn't read [^\n]*\/deploy\/([A-Za-z0-9_-]+\.so)[^\n]*No such file or directory/)?.[1];
  return name ? `Missing program artifact deploy/${name}; build it separately and supply --test-artifacts <cargo-target-dir>.` : null;
}

// Name why a suite could not even start, so a gap reads as a setup problem rather than "no test summary".
export function testSetupCause(stdout, stderr) {
  const out = `${stderr}\n${stdout}`;
  const pkg = out.match(/Cannot find package '([^']+)'/)?.[1];
  const cmd = out.match(/sh: \d+: ([\w.@/-]+): not found/)?.[1];
  if (pkg || cmd) return `Dependencies are not installed${pkg ? ` (missing package ${pkg})` : ` (${cmd} not found)`}; npm install only runs from a lockfile, so a package.json without one cannot run its tests.`;
  const fetched = out.match(/request to https:\/\/registry\.npmjs\.org\/([^\s]+) failed: cache mode is 'only-if-cached'/)?.[1];
  if (fetched) return `The test script fetches ${decodeURIComponent(fetched)} through npx, which the offline sandbox cannot do; declare it as a locked devDependency.`;
  if (/Cannot find module '\.prisma\/client/.test(out)) return 'Prisma client is not generated (install scripts are disabled in the sandbox), so suites importing it cannot load.';
  if (/failed to find a workspace root/.test(out)) return 'Cargo crate inherits from a workspace root that is not in the review snapshot.';
  if (/run `anchor build` first/.test(out)) return 'Test needs a prebuilt Solana program or IDL ("run `anchor build` first"); build it separately and supply --test-artifacts <cargo-target-dir>.';
  const input = out.match(/couldn't read `([^`]+)`: No such file or directory/)?.[1];
  if (input && !/\/deploy\/[\w-]+\.so$/.test(input)) return `Test input missing from the review snapshot: ${input.replace(/^\/work\/src\//, '')}.`;
  return null;
}
