import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { expectedAuditors, loadAuditors, providerOf, validateAuditor, readReportText } from './report-contract.mjs';
import { commitSubmission } from './audit-submission.mjs';
import { digest } from './agent-session-store.mjs';
import { loadAuditorFindings } from './crosscheck.mjs';

const scripts = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scripts, '..');
const finding = (extra = {}) => ({
  title: 'Review evidence label is overstated', surface: 'S1', severity: 'low',
  confidence: 'confirmed', location: ['src/report.ts:12'], impact: 'Report could mislead.',
  preconditions: 'Source review only', attack: [], poc: '', fix: 'Use an assertion label.', ...extra,
});

test('cross-check preparation rejects unknown adapter identities', (t) => {
  const f = fixture(t);
  const r = spawnSync(process.execPath, [path.join(scripts, 'crosscheck.mjs'), 'prepare', f.dir, 'claude,unknown'], { encoding: 'utf8', timeout: 5000 });
  assert.notEqual(r.status, 0);
  assert.equal(fs.existsSync(path.join(f.dir, 'crosscheck')), false);
});
const controls = { verified_safe: [] };
function fixture(t, agents = ['claude']) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-report-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(dir, 'auditors'));
  fs.mkdirSync(path.join(dir, 'harness'));
  fs.writeFileSync(path.join(dir, 'harness/sandbox.md'), '# Sandbox\n| fixture | impossible | Benign data fixture, no target execution. |\n');
  const meta = { agents, surface: 's1', models: { claude: 'requested-model' }, workerExits: {}, crosscheckExits: {}, stageFailures: [], finalized: true };
  const put = (rel, value) => fs.writeFileSync(path.join(dir, rel), JSON.stringify(value));
  const save = (adapter, data = [finding(), controls]) => {
    const name = `${adapter}-s1-auth`;
    meta.workerExits[name] = 0;
    put(`auditors/${name}.json`, data);
    fs.writeFileSync(path.join(dir, 'auditors', `${name}.md`), 'Source review only.\n');
    put('meta.json', meta);
  };
  put('meta.json', meta);
  const cross = () => {
    const { assignments } = loadAuditors(dir);
    for (const [adapter, ids] of Object.entries(assignments)) {
      meta.crosscheckExits[adapter] = 0;
      put(`auditors/crosscheck-${adapter}.json`, ids.map((id) => ({ id, verdict: 'upheld', reason: 'Source statement only.', evidence: ['src/report.ts:12'] })));
    }
    put('meta.json', meta);
  };
  return { dir, meta, put, save, cross };
}
const run = (file, dir) => spawnSync(process.execPath, [path.join(scripts, file), dir], { encoding: 'utf8', timeout: 10_000 });

test('valid empty findings still require the final controls object', () => {
  assert.deepEqual(validateAuditor([controls], 'claude-s1-auth'), [controls]);
  assert.throws(() => validateAuditor([], 'claude-s1-auth'));
});

test('strict schema rejects malformed evidence rather than salvaging it', () => {
  for (const extra of [{ title: 7 }, { confidence: 'possible' }, { severity: 'urgent' }, { location: ['../outside.ts:1'] }, { surface: 'S2' }, { attack: 'steps' }]) {
    assert.throws(() => validateAuditor([finding(extra), controls], 'claude-s1-auth'));
  }
  assert.throws(() => validateAuditor([{ findings: [] }], 'claude-s1-auth'));
  assert.throws(() => validateAuditor([{ verified_safe: [{ control: 'Review', how_attacked: 'Read', holds: 'true' }] }], 'claude-s1-auth'));
});

test('adapter names are exact and unknown filenames are not vendors', () => {
  assert.equal(providerOf('claude-s1-auth'), 'anthropic');
  assert.equal(providerOf('codex-s1-auth'), 'openai');
  assert.equal(providerOf('gpt-extra'), null);
  assert.equal(providerOf('unrelated-grok-report'), null);
});

test('expected inventory follows single-surface and breadth-first contracts', () => {
  assert.deepEqual(expectedAuditors({ agents: ['claude', 'codex'], surface: 's1' }), ['claude-s1-auth', 'codex-s1-auth']);
  assert.deepEqual(expectedAuditors({ agents: ['claude'], surface: 'all' }), ['claude-s1-auth', 'claude-s2-input', 'claude-s3-logic', 'claude-s4-config', 'claude-s5-deps', 'claude-s6-client']);
});

test('missing workers cannot become a complete zero-finding report', (t) => {
  const f = fixture(t, ['claude', 'grok']);
  f.save('claude', [controls]);
  assert.equal(loadAuditors(f.dir).health.state, 'incomplete');
  assert.equal(run('verify-and-adjudicate.mjs', f.dir).status, 2);
  assert.equal(JSON.parse(fs.readFileSync(path.join(f.dir, 'report-health.json'))).state, 'incomplete');
});

test('cancelled cross-checks are not relabeled from historical MCP error prose', t => {
  const f = fixture(t, ['claude', 'grok']);
  f.save('claude'); f.save('grok'); f.cross();
  f.meta.crosscheckExits.grok = 130;
  f.put('meta.json', f.meta);
  fs.mkdirSync(path.join(f.dir, 'harness/sandbox-run'));
  fs.writeFileSync(path.join(f.dir, 'harness/sandbox-run/crosscheck-grok.log'), 'Historical audit_docker unavailable message.');
  const message = loadAuditors(f.dir).health.errors.find(error => error.startsWith('grok: missing or failed cross-check exit'));
  assert.match(message, /Review cancelled/);
  assert.doesNotMatch(message, /Docker MCP tools were unavailable/);
});

test('incomplete reports explain recorded policy refusals, MCP failures and timeouts', (t) => {
  const f = fixture(t, ['claude', 'grok', 'agy', 'codex']);
  const logs = path.join(f.dir, 'harness', 'sandbox-run');
  fs.mkdirSync(logs);
  f.meta.workerExits = { 'claude-s1-auth': 1, 'grok-s1-auth': 124, 'agy-s1-auth': 124, 'codex-s1-auth': 1 };
  f.put('meta.json', f.meta);
  fs.writeFileSync(path.join(logs, 'agent-claude-s1-auth.log'), "You've hit your session limit");
  fs.writeFileSync(path.join(logs, 'agent-grok-s1-auth.log'), 'The project MCP server never attached');
  fs.writeFileSync(path.join(logs, 'agent-codex-s1-auth.log'), 'This content was flagged for possible cybersecurity risk');
  const health = loadAuditors(f.dir).health;
  assert.equal(health.state, 'incomplete');
  for (const expected of [/usage\/session limit/, /MCP tools were unavailable/, /exceeded its time budget/, /Provider refused/]) assert.ok(health.errors.some(error => expected.test(error)));
  const result = run('verify-and-adjudicate.mjs', f.dir);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Provider refused/);
  f.put('workers.json', { jobs: [{ name: 'agy-s1-auth', failure: { reason: 'invalid_report', message: 'DO_NOT_TRUST_CUSTOM_TEXT' } }] });
  const diagnostics = loadAuditors(f.dir).health.errors.join('\n');
  assert.match(diagnostics, /Submitted report failed contract validation/);
  assert.ok(!diagnostics.includes('DO_NOT_TRUST_CUSTOM_TEXT'));
});

test('nonzero or absent worker exit remains incomplete with valid JSON', (t) => {
  const f = fixture(t);
  f.save('claude');
  f.meta.workerExits['claude-s1-auth'] = 1;
  f.put('meta.json', f.meta);
  assert.equal(loadAuditors(f.dir).health.state, 'incomplete');
  delete f.meta.workerExits;
  f.put('meta.json', f.meta);
  assert.equal(loadAuditors(f.dir).health.state, 'incomplete');
});

test('malformed metadata and report JSON fail closed', (t) => {
  const f = fixture(t);
  f.put('meta.json', null);
  assert.equal(loadAuditors(f.dir).health.state, 'incomplete');
  f.save('claude');
  fs.writeFileSync(path.join(f.dir, 'auditors/claude-s1-auth.json'), '{');
  assert.equal(run('verify-and-adjudicate.mjs', f.dir).status, 2);
});

test('missing markdown and unexpected files are coverage errors', (t) => {
  const f = fixture(t);
  f.save('claude');
  fs.unlinkSync(path.join(f.dir, 'auditors/claude-s1-auth.md'));
  assert.equal(loadAuditors(f.dir).reports.length, 0);
  f.save('claude');
  f.put('auditors/grok-extra.json', [finding(), controls]);
  assert.equal(loadAuditors(f.dir).health.state, 'incomplete');
  assert.equal(loadAuditorFindings(path.join(f.dir, 'auditors')).length, 1);
});

test('source-only confirmed claims never acquire POC execution status', (t) => {
  const f = fixture(t);
  f.save('claude');
  assert.equal(run('verify-and-adjudicate.mjs', f.dir).status, 0);
  const [row] = JSON.parse(fs.readFileSync(path.join(f.dir, 'findings-and-scores.json')));
  assert.equal(row.status, 'MODEL_ASSERTION');
  assert.equal(row.executionEvidence, 'not_collected');
  assert.deepEqual(row.claimIds, ['claude-s1-auth#0']);
});

test('same title at different locations does not manufacture agreement', (t) => {
  const f = fixture(t, ['claude', 'grok']);
  f.save('claude');
  f.save('grok', [finding({ location: ['src/other.ts:8'] }), controls]);
  f.cross();
  assert.equal(run('verify-and-adjudicate.mjs', f.dir).status, 0);
  const rows = JSON.parse(fs.readFileSync(path.join(f.dir, 'findings-and-scores.json')));
  assert.equal(rows.length, 2);
  assert.ok(rows.every((r) => r.status === 'UPHELD_REVIEW'));
});

test('matching model claims remain unverified agreement, not quorum proof', (t) => {
  const f = fixture(t, ['claude', 'grok']);
  f.save('claude');
  f.save('grok');
  f.cross();
  assert.equal(run('verify-and-adjudicate.mjs', f.dir).status, 0);
  const [row] = JSON.parse(fs.readFileSync(path.join(f.dir, 'findings-and-scores.json')));
  assert.equal(row.status, 'MODEL_AGREEMENT');
  assert.equal(row.provenance, 'unverified_adapter_identity');
});

test('partial and empty cross-check verdict sets remain incomplete', (t) => {
  const f = fixture(t, ['claude', 'grok']);
  f.save('claude');
  f.save('grok');
  f.cross();
  f.put('auditors/crosscheck-grok.json', []);
  assert.equal(run('verify-and-adjudicate.mjs', f.dir).status, 2);
  f.cross();
  delete f.meta.finalized;
  f.put('meta.json', f.meta);
  assert.equal(run('verify-and-adjudicate.mjs', f.dir).status, 2);
});

test('peer authors can dispute individual claims inside an agreeing cluster', (t) => {
  const f = fixture(t, ['claude', 'grok']);
  f.save('claude');
  f.save('grok');
  f.cross();
  f.put('auditors/crosscheck-grok.json', [{ id: 'claude-s1-auth#0', verdict: 'refuted', reason: 'The source statement is disputed.', evidence: ['src/report.ts:12'] }]);
  assert.equal(run('verify-and-adjudicate.mjs', f.dir).status, 0);
  const [row] = JSON.parse(fs.readFileSync(path.join(f.dir, 'findings-and-scores.json')));
  assert.equal(row.status, 'PARTIAL_REVIEW');
  assert.ok(row.reviews.some((r) => r.claimId === 'claude-s1-auth#0' && r.verdict === 'refuted'));
});

test('cross-check enums and citations are strict', (t) => {
  const f = fixture(t, ['claude', 'grok']);
  f.save('claude');
  f.save('grok');
  for (const extra of [{ verdict: ['upheld'] }, { evidence: [''] }, { severity: ['low'] }]) {
    f.cross();
    f.put('auditors/crosscheck-grok.json', [{ id: 'claude-s1-auth#0', verdict: 'upheld', reason: 'Read.', evidence: ['src/report.ts:12'], ...extra }]);
    assert.equal(run('verify-and-adjudicate.mjs', f.dir).status, 2);
  }
});

test('metadata presentation errors still render an incomplete banner', (t) => {
  const f = fixture(t);
  for (const value of [null, { ...f.meta, date: 'not a date' }, { ...f.meta, name: 9, source: [], models: ['unexpected'] }]) {
    f.put('meta.json', value);
    assert.equal(run('generate-html-report.mjs', f.dir).status, 2);
    assert.match(fs.readFileSync(path.join(f.dir, 'report.html'), 'utf8'), /INCOMPLETE REVIEW/);
  }
});

test('bounded text reads reject oversize and non-regular entries', (t) => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.dir, 'oversize.txt'), 'ordinary text');
  assert.throws(() => readReportText(f.dir, 'oversize.txt', 4));
  assert.throws(() => readReportText(f.dir, 'auditors'));
});

test('legacy tiebreak overrides are excluded, never elevated to confirmation', (t) => {
  const f = fixture(t);
  f.save('claude');
  f.put('auditors/tiebreak-old.json', [{ match: ['review'], verdict: 'upheld' }]);
  assert.equal(run('verify-and-adjudicate.mjs', f.dir).status, 2);
  const [row] = JSON.parse(fs.readFileSync(path.join(f.dir, 'findings-and-scores.json')));
  assert.equal(row.status, 'MODEL_ASSERTION');
});

test('unknown cross-check claims and missing expected cross-checks are incomplete', (t) => {
  const f = fixture(t, ['claude', 'grok']);
  f.save('claude');
  f.save('grok');
  f.put('auditors/crosscheck-grok.json', [{ id: 'unknown#0', verdict: 'upheld', reason: 'Read', evidence: ['src/report.ts:12'] }]);
  assert.equal(run('verify-and-adjudicate.mjs', f.dir).status, 2);
  fs.unlinkSync(path.join(f.dir, 'auditors/crosscheck-grok.json'));
  f.meta.crosscheckExits = { grok: 0 };
  f.put('meta.json', f.meta);
  assert.equal(run('verify-and-adjudicate.mjs', f.dir).status, 2);
});

test('renderer discloses unavailable outputs and sandbox coverage', (t) => {
  const f = fixture(t);
  fs.unlinkSync(path.join(f.dir, 'harness/sandbox.md'));
  assert.equal(run('generate-html-report.mjs', f.dir).status, 2);
  const html = fs.readFileSync(path.join(f.dir, 'report.html'), 'utf8');
  const chart = fs.readFileSync(path.join(f.dir, 'findings-by-model.html'), 'utf8');
  assert.match(html, /INCOMPLETE REVIEW/);
  assert.match(html, /Sandbox coverage unavailable or invalid/);
  assert.match(chart, /no valid outputs/);
  assert.doesNotMatch(html, /Quorum Security Review/);
});

test('complete reviewer outputs with execution gaps render incomplete verification', t => {
  const f = fixture(t);
  f.meta.workflow = 'source_security_review_v1';
  f.save('claude', [controls]);
  assert.equal(run('generate-html-report.mjs', f.dir).status, 2);
  const html = fs.readFileSync(path.join(f.dir, 'report.html'), 'utf8');
  assert.match(html, /INCOMPLETE VERIFICATION/);
  assert.match(html, /Review outputs are complete/);
  assert.doesNotMatch(html, /Missing reviews are not passes/);
});

test('renderer displays benign SVG source inertly and remains offline', (t) => {
  const f = fixture(t);
  f.save('claude');
  fs.mkdirSync(path.join(f.dir, 'assets'));
  fs.writeFileSync(path.join(f.dir, 'assets/diagram.svg'), '<svg><text>ordinary diagram</text></svg>');
  assert.equal(run('generate-html-report.mjs', f.dir).status, 0);
  const html = fs.readFileSync(path.join(f.dir, 'report.html'), 'utf8');
  assert.doesNotMatch(html, /<svg>/);
  assert.match(html, /&lt;svg&gt;/);
  assert.match(html, /Content-Security-Policy/);
  assert.match(html, /<script nonce="/);
  assert.doesNotMatch(html, /onclick=|fonts\.googleapis/);
  assert.match(html, /unverified/);
  f.meta.isolation = { policy: 'report_finalization' };
  f.meta.recovery = { fromReport: '<prior-review>' };
  f.put('meta.json', f.meta);
  assert.equal(run('generate-html-report.mjs', f.dir).status, 0);
  const recovered = fs.readFileSync(path.join(f.dir, 'report.html'), 'utf8');
  assert.match(recovered, /Saved review finalization/);
  assert.match(recovered, /No new Docker container/);
  assert.match(recovered, /&lt;prior-review&gt;/);
});

test('renderer preserves original analysis and formats it without activating source markup', (t) => {
  const f = fixture(t);
  f.save('claude', [finding({
    analysis: '**Ownership control**\n\n- Check `wallet_id`.\n- Keep the original evidence.',
    validation: 'Source only. <img src=x onerror="alert(1)">',
    fix: 'Reject `<script>` in the rendered source.',
  }), controls]);
  assert.equal(run('generate-html-report.mjs', f.dir).status, 0);
  const html = fs.readFileSync(path.join(f.dir, 'report.html'), 'utf8');
  assert.match(html, /<strong>Ownership control<\/strong>/);
  assert.match(html, /<li>Check <code>wallet_id<\/code>\.<\/li>/);
  assert.match(html, /Keep the original evidence\./);
  assert.match(html, /&lt;img src=x onerror=&quot;alert\(1\)&quot;&gt;/);
  assert.doesNotMatch(html, /<img src=x|<script>/);
  const findingTags = html.match(/<details class="finding [^>]+>/g);
  assert.equal(findingTags.length, 1);
  assert.ok(findingTags.every(tag => !/\sopen(?:\s|=|>)/.test(tag)));
});

test('both skill copies stay identical and describe incomplete reviews', () => {
  const a = fs.readFileSync(path.join(root, 'skills/security-audit/SKILL.md'), 'utf8');
  const b = fs.readFileSync(path.join(root, '.claude/skills/security-audit/SKILL.md'), 'utf8');
  assert.equal(a, b);
  assert.match(a, /incomplete.*not zero-finding passes/);
  assert.match(a, /Normal permissions and prompt instructions are not containment/);
  const evals = JSON.parse(fs.readFileSync(path.join(root, 'skills/security-audit/evals.json')));
  assert.equal(evals.mode, 'classification_only');
  assert.equal(evals.evals.length, 3);
  assert.ok(evals.evals.every((e) => e.prompt.includes('do not run commands')));
});

test('host PoC refusal executes no Node or TypeScript file', (t) => {
  const f = fixture(t);
  const pocs = path.join(f.dir, 'pocs');
  fs.mkdirSync(pocs);
  fs.writeFileSync(path.join(pocs, 'ordinary.test.mjs'), '// inert fixture\n');
  fs.writeFileSync(path.join(pocs, 'ordinary.spec.ts'), '// inert fixture\n');
  const r = spawnSync('bash', [path.join(scripts, 'run-pocs.sh'), '--target', f.dir, '--pocs', pocs], { encoding: 'utf8', timeout: 5000 });
  assert.equal(r.status, 2);
  assert.match(r.stdout, /BLOCKED: Node/);
  assert.match(r.stdout, /BLOCKED: TypeScript/);
  assert.doesNotMatch(r.stdout, /REPRODUCED/);
  const source = fs.readFileSync(path.join(scripts, 'run-pocs.sh'), 'utf8');
  assert.doesNotMatch(source, /&& node --test|npx --no-install/);
});

test('host launchers do not supply permission-bypass flags', () => {
  const source = fs.readFileSync(path.join(scripts, 'orchestrate.sh'), 'utf8');
  assert.doesNotMatch(source, /--dangerously-skip-permissions|--always-approve/);
  assert.match(source, /output directory must be empty/);
});


test('ACP report validation requires the committed identity and rejects altered derived output', t => {
  const f = fixture(t);
  f.save('claude');
  f.meta.submissionAuthority = 'mcp_commit';
  f.put('meta.json', f.meta);
  assert.equal(loadAuditors(f.dir).health.state, 'incomplete');
  const name = 'claude-s1-auth';
  const assignment = { surface: 'S1' };
  const identity = { name, agent: 'claude', role: 'auditor', model: 'requested-model', sourceDigest: 'a'.repeat(64), assignmentDigest: digest(assignment), surface: 'S1' };
  fs.mkdirSync(path.join(f.dir, 'harness/identities'));
  fs.mkdirSync(path.join(f.dir, 'harness/assignments'));
  f.put(`harness/identities/${name}.json`, identity);
  f.put(`harness/assignments/${name}.json`, assignment);
  f.put('source-manifest.json', { digest: identity.sourceDigest });
  commitSubmission(f.dir, name, identity, [finding(), controls], 'Source only');
  assert.equal(loadAuditors(f.dir).health.state, 'validated_outputs');
  f.put(`auditors/${name}.json`, [controls]);
  assert.equal(loadAuditors(f.dir).health.state, 'incomplete');
  f.put(`auditors/${name}.json`, [finding(), controls]);
  f.put(`harness/assignments/${name}.json`, { surface: 'S2' });
  assert.equal(loadAuditors(f.dir).health.state, 'incomplete');
});
