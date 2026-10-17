// Trusted review-only runtime. No shell, scanner, installer or model-auth tools.
// Live subscription transport is intentionally absent; fixtures are not audits.
import fs from 'node:fs';
import { readReportJson, readReportText } from './report-contract.mjs';
import { LIMITS, backendStatus, expectedFiles, hash } from './worker-isolation.mjs';
import { validateReviewRequest, exactKeys, validateResult, terminalReport, encodeFrame, readJsonLine, terminalSafeJson } from './terminal-review-contract.mjs';

const mode = process.argv[2];
if (mode === 'hold') {
  // Keep the private tmpfs volume mounted after the worker exits.
  setInterval(() => {}, 1000);
} else if (mode === 'collect') {
  const { job } = readReportJson('/input', 'job.json');
  const expected = expectedFiles(job.phase);
  if (JSON.stringify(fs.readdirSync('/out').sort()) !== JSON.stringify([...expected].sort())) throw new Error('outbox inventory rejected');
  const files = {};
  for (const name of expected) files[name] = Buffer.from(readReportText('/out', name, LIMITS.outputBytes)).toString('base64');
  process.stdout.write(JSON.stringify({ version: 1, files }));
} else if (mode === 'fixture') {
  const input = readReportJson('/input', 'job.json');
  if (input.executionMode !== 'inert_fixture' || !['probe', 'wait', 'malformed', 'extra', 'oversized'].includes(input.fixture)) throw new Error('unsupported fixture');
  if (input.fixture === 'wait') {
    setInterval(() => {}, 1000);
  } else {
    let sourceWriteDenied = false;
    try { fs.writeFileSync('/source/sample.txt', 'inert fixture write attempt'); } catch { sourceWriteDenied = true; }
    const credentialNames = ['AUDIT_TEST_CREDENTIAL', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GOOGLE_API_KEY', 'XAI_API_KEY', 'GROK_API_KEY', 'CODEX_HOME', 'SSH_AUTH_SOCK', 'AWS_ACCESS_KEY_ID'];
    const checks = {
      nonRoot: process.getuid() === 10001,
      sourceWriteDenied,
      sourceText: readReportText('/source', 'sample.txt', 1000),
      parentAbsent: !fs.existsSync('/parent-reports'),
      peerAbsent: !fs.existsSync('/peer-outbox'),
      socketAbsent: !fs.existsSync('/var/run/docker.sock'),
      credentialsAbsent: credentialNames.every((n) => !Object.hasOwn(process.env, n)),
      homeIsPrivate: process.env.HOME === '/home/reviewer' && fs.readdirSync('/home/reviewer').length === 0,
    };
    const safe = [{ verified_safe: [{ control: 'Inert worker boundary fixture — not an audit', how_attacked: JSON.stringify(checks), holds: Object.entries(checks).filter(([key]) => key !== 'sourceText').every(([, value]) => value === true) }] }];
    const cross = input.job.claims.map((c) => ({ id: c.id, verdict: 'partial', reason: 'Inert fixture only; no security review occurred.', evidence: ['sample.txt:1'] }));
    const json = input.job.phase === 'original' ? safe : cross;
    const report = input.fixture === 'malformed' ? '{' : JSON.stringify(json);
    fs.writeFileSync('/out/report.json', input.fixture === 'oversized' ? 'x'.repeat(LIMITS.outputBytes + 1) : report, { mode: 0o600 });
    if (input.job.phase === 'original') fs.writeFileSync('/out/report.md', 'INERT ISOLATION FIXTURE — no security review or model call.\n', { mode: 0o600 });
    if (input.fixture === 'extra') fs.writeFileSync('/out/unexpected.txt', 'inert fixture', { mode: 0o600 });
  }
} else if (mode === 'terminal-review') {
  const input = readReportJson('/input', 'job.json');
  const request = validateReviewRequest(input.terminalRequest);
  if (input.executionMode !== 'terminal_supplied_unverified' || input.job.phase !== 'terminal' || request.jobId !== input.job.id || request.sourceDigest !== input.job.sourceDigest) throw new Error('terminal worker policy rejected');
  for (const file of request.files) {
    const source = readReportText('/source', file.path, 64 * 1024);
    if (source !== file.code || hash(source) !== file.sha256) throw new Error('terminal source mismatch');
  }
  process.stdout.write(encodeFrame(request));
  const response = await readJsonLine(process.stdin, { timeoutMs: input.terminalDeadlineMs });
  exactKeys(response, ['version', 'type', 'requestId', 'jobId', 'sourceDigest', 'result']);
  if (response.version !== 1 || response.type !== 'review.result' || response.requestId !== request.requestId || response.jobId !== request.jobId || response.sourceDigest !== request.sourceDigest) throw new Error('terminal reply identity rejected');
  validateResult(response.result, request);
  fs.writeFileSync('/out/report.json', JSON.stringify(terminalReport(request, response.result)), { mode: 0o600 });
  fs.writeFileSync('/out/report.md', `USER-TERMINAL SOURCE REVIEW — UNVERIFIED\nNo provider identity, tool-free inference or execution evidence is attested.\n${terminalSafeJson(response.result)}\n`, { mode: 0o600 });
  process.stdin.destroy();
} else if (mode === 'review') {
  const input = readReportJson('/input', 'job.json');
  process.stdout.write(JSON.stringify(backendStatus(input.job.adapter)));
  process.exitCode = 2;
} else {
  throw new Error('runtime mode refused');
}
