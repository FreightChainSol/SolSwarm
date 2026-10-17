import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { createSnapshot, disposeSnapshot, createTerminalJob, backendStatus, hash } from './worker-isolation.mjs';
import { runtimeDigest } from './worker-supervisor.mjs';
import { buildReviewRequest, validateReviewRequest, validateResult, validateSubmission, terminalReport, validateTerminalReport, terminalSafeJson, parseFrame, encodeFrame, readJsonLine, FRAME_BYTES } from './terminal-review-contract.mjs';
import { createTerminalRelay, relayCall } from './terminal-relay.mjs';
import { parseLocalReview } from './terminal-local-review.mjs';
import { readTerminalInput } from './terminal-review-client.mjs';

function fixture(t, code = 'export const label = (s) => String(s).trim();\n') {
  const source = fs.mkdtempSync(path.join(os.tmpdir(), 'terminal-relay-test-'));
  fs.mkdirSync(path.join(source, 'src'));
  fs.writeFileSync(path.join(source, 'src/sample.mjs'), code);
  const snapshot = createSnapshot(source, { only: ['src/sample.mjs'] });
  t.after(() => { disposeSnapshot(snapshot); fs.rmSync(source, { recursive: true, force: true }); });
  return buildReviewRequest(snapshot, ['src/sample.mjs']);
}
const result = { summary: 'Inert terminal-side review fixture; no model was called.', notes: [{ path: 'src/sample.mjs', line: 1, kind: 'maintainability', message: 'The contract is concise.', recommendation: 'Document expected input types.' }] };
const submit = (request, claimId, review = result) => ({ version: 1, method: 'review.submit', requestId: request.requestId, jobId: request.jobId, sourceDigest: request.sourceDigest, claimId, result: review });

test('request is limited to explicit sealed local source and fixed policy', (t) => {
  const request = fixture(t);
  assert.equal(validateReviewRequest(request), request);
  assert.equal(request.files.length, 1);
  assert.equal(request.files[0].path, 'src/sample.mjs');
  assert.throws(() => validateReviewRequest({ ...request, command: 'not an operation' }));
  assert.throws(() => validateReviewRequest({ ...request, instruction: 'different policy' }));
  assert.throws(() => validateReviewRequest({ ...request, files: [{ ...request.files[0], path: '../outside' }] }));
});

test('result schema denies out-of-scope citations, arbitrary fields and exploit/command fields', (t) => {
  const request = fixture(t);
  assert.equal(validateResult(result, request), result);
  for (const extra of [{ path: 'outside.mjs' }, { line: 9999 }, { kind: 'execute' }]) assert.throws(() => validateResult({ ...result, notes: [{ ...result.notes[0], ...extra }] }, request));
  for (const field of ['command', 'env', 'url', 'credentials', 'poc', 'attack']) assert.throws(() => validateResult({ ...result, [field]: 'not accepted' }, request));
});

test('submission must match request, job, source digest and claimed terminal exchange', (t) => {
  const request = fixture(t);
  const value = submit(request, 'claim-id');
  assert.equal(validateSubmission(value, request, 'claim-id'), value);
  for (const key of ['requestId', 'jobId', 'sourceDigest', 'claimId']) assert.throws(() => validateSubmission({ ...value, [key]: 'different' }, request, 'claim-id'));
});

test('terminal reports cannot attest identity, tools or execution', (t) => {
  const request = fixture(t);
  const report = terminalReport(request, result);
  assert.equal(validateTerminalReport(report, request), report);
  assert.equal(report.origin, 'terminal_supplied_unverified');
  assert.throws(() => validateTerminalReport({ ...report, modelIdentity: 'verified' }, request));
  const job = createTerminalJob(request, runtimeDigest());
  assert.equal(job.adapter, 'user-terminal');
  assert.equal(backendStatus('codex').state, 'blocked');
});

test('framing rejects oversized, invalid UTF-8 and incomplete messages', async () => {
  assert.throws(() => parseFrame(Buffer.from([0xff])));
  assert.throws(() => encodeFrame({ text: 'x'.repeat(FRAME_BYTES) }));
  const stream = new PassThrough();
  const pending = readJsonLine(stream);
  stream.end('{"partial":');
  await assert.rejects(pending, /incomplete/);
  const extra = new PassThrough();
  const duplicate = readJsonLine(extra);
  extra.end('{}\n{}\n');
  await assert.rejects(duplicate, /one frame/);
});

test('frame deadlines and cancellation are bounded', async () => {
  const stream = new PassThrough();
  await assert.rejects(readJsonLine(stream, { timeoutMs: 20 }), /deadline/);
  const controller = new AbortController();
  const pending = readJsonLine(stream, { signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, /cancelled/);
  stream.destroy();
});

test('terminal rendering escapes controls and bidirectional text', () => {
  const shown = terminalSafeJson({ source: '\u001b[31m\u009b\u202e\u2066inert' });
  assert.doesNotMatch(shown, /[\u001b\u009b\u202e\u2066]/);
  assert.match(shown, /\\u001b/);
  assert.match(shown, /\\u202e/);
});

test('owner-only relay supports one authorized claim and one matching result', async (t) => {
  const request = fixture(t);
  const relay = await createTerminalRelay(request);
  t.after(() => relay.close());
  assert.equal(fs.statSync(path.dirname(relay.socketPath)).mode & 0o077, 0);
  assert.equal(fs.statSync(relay.socketPath).mode & 0o077, 0);
  const pending = relay.activate(request);
  const claimed = await relayCall(relay.socketPath, { version: 1, method: 'review.claim' });
  assert.deepEqual(claimed.request, request);
  await assert.rejects(relayCall(relay.socketPath, { version: 1, method: 'review.claim' }));
  await assert.rejects(relayCall(relay.socketPath, { ...submit(request, claimed.claimId), sourceDigest: '0'.repeat(64) }));
  assert.equal(relay.state(), 'claimed');
  await relayCall(relay.socketPath, submit(request, claimed.claimId));
  assert.deepEqual(await pending, result);
  await assert.rejects(relayCall(relay.socketPath, submit(request, claimed.claimId)));
  assert.equal((await relayCall(relay.socketPath, { version: 1, method: 'review.status' })).state, 'submitted');
});

test('relay never accepts host execution, reads, environment or HTTP methods', async (t) => {
  const request = fixture(t);
  const relay = await createTerminalRelay(request);
  t.after(() => relay.close());
  relay.activate(request);
  for (const method of ['exec', 'host.read', 'env.get', 'http.forward', 'model.call']) await assert.rejects(relayCall(relay.socketPath, { version: 1, method }));
  assert.equal(relay.state(), 'pending');
});

test('unauthorized worker frames and expired relay submissions are rejected', async (t) => {
  const request = fixture(t);
  const relay = await createTerminalRelay(request, { deadlineMs: 50 });
  t.after(() => relay.close());
  assert.throws(() => relay.activate({ ...request, jobId: '12345678-1234-1234-1234-123456789abc' }));
  await assert.rejects(relay.completion, /timed_out/);
  assert.throws(() => relay.activate(request), (err) => err.code === 'terminal_timeout');
  assert.throws(() => relay.activate({ ...request, jobId: '12345678-1234-1234-1234-123456789abc' }), /unauthorized worker request/);
  await assert.rejects(relayCall(relay.socketPath, { version: 1, method: 'review.claim' }));
  const controller = new AbortController();
  const cancelled = await createTerminalRelay(request, { signal: controller.signal });
  t.after(() => cancelled.close());
  controller.abort();
  await assert.rejects(cancelled.completion, /cancelled/);
  assert.throws(() => cancelled.activate(request), (err) => err.code === 'terminal_cancelled');
});

test('local entry point refuses remote targets, implicit source selection and duplicate paths', () => {
  assert.throws(() => parseLocalReview(['--github', 'owner/repo']));
  assert.throws(() => parseLocalReview(['--repo', '.', '--out', 'out']));
  assert.throws(() => parseLocalReview(['--repo', '.', '--out', 'out', '--file', '../outside']));
  assert.throws(() => parseLocalReview(['--repo', '.', '--out', 'out', '--file', 'a.mjs', '--file', 'a.mjs']));
});

test('source cardinality and total source bytes are explicit limits', (t) => {
  const request = fixture(t);
  assert.throws(() => validateReviewRequest({ ...request, files: Array(4).fill(request.files[0]) }), /inventory/);
  const code = 'x'.repeat(64 * 1024 + 1);
  assert.throws(() => validateReviewRequest({ ...request, files: [{ path: 'src/sample.mjs', code, sha256: hash(code), lineCount: 1 }] }), /source byte limit/);
});

test('terminal input reader enforces deadline and maximum bytes', async () => {
  const stream = new PassThrough();
  await assert.rejects(readTerminalInput(stream, 20), /deadline/);
  const large = new PassThrough();
  const pending = readTerminalInput(large);
  large.end(Buffer.alloc(FRAME_BYTES + 1, 120));
  await assert.rejects(pending, /byte limit/);
});

test('BOM-prefixed UTF-8 source preserves its captured byte identity', (t) => {
  const request = fixture(t, '\ufeffexport const inert = 1;\n');
  assert.equal(request.files[0].code.charCodeAt(0), 0xfeff);
  assert.equal(hash(request.files[0].code), request.files[0].sha256);
});

test('default relay waits through silence until submission or explicit cancellation', async (t) => {
  const request = fixture(t);
  const controller = new AbortController();
  const relay = await createTerminalRelay(request, { signal: controller.signal });
  t.after(() => relay.close());
  relay.activate(request);
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.equal(relay.state(), 'pending');
  controller.abort();
  await assert.rejects(relay.completion, /cancelled/);
});
