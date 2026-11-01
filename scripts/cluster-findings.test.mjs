import assert from 'node:assert/strict';
import test from 'node:test';
import { clusterFindings, dedupCandidates, isCompoundTitle, sharedAnchorFiles } from './cluster-findings.mjs';

let n = 0;
const claim = (auditor, surface, title, location, severity = 'medium') =>
  ({ auditor, surface, title, location, severity, confidence: 'probable', claimId: `${auditor}#${n++}` });

// Synthetic shapes of a real duplicated report: three auditors on one endpoint, two on a script
// loader, plus claims that touch the same shared files but are different issues.
const claims = () => {
  n = 0;
  return [
    claim('codex-s4-config', 'S4', 'Receipt endpoint bypasses visibility', ['api/ride.controller.ts:27', 'api/get-ride.handler.ts:19', 'api/ride.dto.ts:54']),
    claim('agy-s3-logic', 'S3', 'Missing replay gate on public ride route', ['api/ride.controller.ts:27', 'api/get-ride.handler.ts:18'], 'high'),
    claim('grok-s6-client', 'S6', 'Public ride JSON leaks seed and wallet', ['api/ride.controller.ts:28', 'api/get-ride.handler.ts:18', 'api/ride.dto.ts:66']),
    claim('claude-s5-deps', 'S5', 'Signing library loaded without SRI', ['web/pay.js:11', 'web/play.html:32']),
    claim('grok-s6-client', 'S6', 'Game pages load CDN scripts without SRI', ['web/play.html:32', 'web/pay.js:12']),
    // Decoys: one shared file only, or same auditor.
    claim('grok-s2-input', 'S2', 'Hidden and locked replays return different errors', ['domain/replay-visibility.ts:22', 'api/ride.controller.ts:27']),
    claim('codex-s4-config', 'S4', 'Promo error reveals code state', ['api/errors.ts:10', 'api/promo.handler.ts:55']),
    claim('claude-s1-auth', 'S1', 'Pay mismatch reveals wallet prefix', ['api/errors.ts:11', 'api/pay.handler.ts:37']),
    claim('agy-s3-logic', 'S3', 'Payout plan persisted early', ['svc/payout.ts:100', 'svc/ranking.ts:20']),
    claim('agy-s3-logic', 'S3', 'Payout ranking uses stale verdicts', ['svc/payout.ts:101', 'svc/ranking.ts:21']),
  ];
};

test('cross-auditor claims on the same root cause merge across surfaces and titles', () => {
  const clusters = clusterFindings(claims());
  const sets = clusters.map((c) => c.claimIds.length).sort();
  assert.equal(clusters.length, 7);
  assert.deepEqual(sets, [1, 1, 1, 1, 1, 2, 3]);
  const triple = clusters.find((c) => c.claimIds.length === 3);
  assert.deepEqual([...triple.auditors].sort(), ['agy-s3-logic', 'codex-s4-config', 'grok-s6-client']);
  const pair = clusters.find((c) => c.claimIds.length === 2);
  assert.deepEqual([...pair.auditors].sort(), ['claude-s5-deps', 'grok-s6-client']);
});

test('a single shared file never chains unrelated claims together', () => {
  const clusters = clusterFindings(claims());
  const decoy = clusters.find((c) => c.primaryTitle.startsWith('Hidden and locked'));
  assert.equal(decoy.claimIds.length, 1);
  assert.equal(clusters.find((c) => c.primaryTitle.startsWith('Promo')).claimIds.length, 1);
});

test('one auditor splitting an issue in two is respected', () => {
  const clusters = clusterFindings(claims());
  assert.equal(clusters.filter((c) => c.auditors.includes('agy-s3-logic') && c.findings.some((f) => f.location[0].startsWith('svc/'))).length, 2);
});

test('cluster leads with its highest-severity claim and keeps the severity spread', () => {
  const triple = clusterFindings(claims()).find((c) => c.claimIds.length === 3);
  assert.equal(triple.severity, 'high');
  assert.equal(triple.primaryTitle, 'Missing replay gate on public ride route');
  assert.equal(triple.claimIds[0], triple.findings[0].claimId);
  assert.deepEqual([...triple.severities].sort(), ['high', 'medium']);
});

test('exact title with a shared citation still merges, even on a single anchor', () => {
  n = 0;
  const clusters = clusterFindings([
    claim('claude-s1-auth', 'S1', 'Same issue', ['src/a.ts:12']),
    claim('grok-s1-auth', 'S1', 'same issue', ['src/a.ts:12']),
    claim('codex-s1-auth', 'S1', 'Same issue', ['src/b.ts:8']),
  ]);
  assert.equal(clusters.length, 2);
});

test('near-line tolerance is bounded', () => {
  assert.deepEqual(sharedAnchorFiles({ location: ['a.ts:10', 'b.ts:5'] }, { location: ['a.ts:13', 'b.ts:9'] }), ['a.ts']);
});

test('unmerged cross-auditor overlaps are reported as dedup candidates, merged ones are not', () => {
  const clusters = clusterFindings(claims());
  const candidates = dedupCandidates(clusters);
  assert.ok(candidates.some((c) => c.sharedFiles.includes('api/errors.ts')));
  assert.ok(candidates.some((c) => c.sharedFiles.includes('api/ride.controller.ts')));
  assert.ok(!candidates.some((c) => c.sharedFiles.includes('svc/payout.ts')), 'same-auditor overlap is not a candidate');
});

test('bundled titles are flagged as compound, single issues are not', () => {
  assert.ok(isCompoundTitle('Missing gate on GET /api/rides/:id/public, Unauthenticated Pledge Queries, and Solana Pay Owner Enumeration'));
  assert.ok(!isCompoundTitle('Public ride JSON skips the replay gate and returns seed, full wallet, and payment data'));
  assert.ok(!isCompoundTitle('Wallet-signing @solana/web3.js and three.js are loaded from jsDelivr without SRI'));
});
