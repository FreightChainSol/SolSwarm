import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createSnapshot, disposeSnapshot, createTerminalJob } from './worker-isolation.mjs';
import { createTerminalRelay } from './terminal-relay.mjs';
import { buildReviewRequest, relativeFile, terminalSafeJson } from './terminal-review-contract.mjs';
import { runtimeDigest, runTerminalReview } from './worker-supervisor.mjs';
import { writeReportFile } from './report-contract.mjs';

export function parseLocalReview(argv) {
  const result = { files: [] };
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i];
    const value = argv[i + 1];
    if (!value || !['--repo', '--out', '--file'].includes(flag)) throw new Error('usage: review-local --repo <local-directory> --file <relative-file> [--file <relative-file>] --out <empty-directory>');
    if (flag === '--file') result.files.push(value);
    else {
      const key = flag.slice(2);
      if (result[key]) throw new Error('duplicate local review option');
      result[key] = value;
    }
  }
  if (!result.repo || !result.out || !result.files.length || result.files.length > 3 || new Set(result.files).size !== result.files.length || !result.files.every(relativeFile) || /^[a-z]+:\/\//i.test(result.repo)) throw new Error('local directory and one to three relative source files required');
  return result;
}

export async function localTerminalReview({ repo, out, files }, { signal, deadlineMs = null, onReady } = {}) {
  const source = fs.realpathSync(repo);
  const output = path.resolve(out);
  if (source === output) throw new Error('review output cannot be the source root');
  if (fs.existsSync(output) && (fs.lstatSync(output).isSymbolicLink() || fs.readdirSync(output).length)) throw new Error('review output must be a new or empty directory');
  fs.mkdirSync(output, { recursive: true, mode: 0o700 });
  fs.chmodSync(output, 0o700);
  const journal = path.join(output, 'journal');
  fs.mkdirSync(journal, { mode: 0o700 });
  const interrupted = new AbortController();
  const cancelled = signal ? AbortSignal.any([signal, interrupted.signal]) : interrupted.signal;
  const stop = () => { interrupted.abort(); process.exitCode = 130; };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
  let snapshot;
  let relay;
  let outcome;
  const started = Date.now();
  const heartbeat = setInterval(() => {
    const status = { state: 'running', elapsedMs: Date.now() - started, at: new Date().toISOString(), timeLimitMs: deadlineMs };
    process.stderr.write(`Review heartbeat: running ${Math.floor(status.elapsedMs / 1000)}s; ${deadlineMs == null ? 'no time limit' : 'explicit deadline'}.\n`);
    try { writeReportFile(output, 'heartbeat.json', JSON.stringify(status)); } catch { /* keep the active review running */ }
  }, 30_000);
  try {
    snapshot = createSnapshot(source, { only: files, exclude: [output] });
    const request = buildReviewRequest(snapshot, files);
    const job = createTerminalJob(request, runtimeDigest());
    writeReportFile(output, 'source-manifest.json', JSON.stringify(snapshot.manifest, null, 2));
    writeReportFile(output, 'job.json', JSON.stringify(job, null, 2));
    relay = await createTerminalRelay(request, { signal: cancelled, deadlineMs });
    outcome = await runTerminalReview(snapshot, job, request, (frame) => {
      const response = relay.activate(frame);
      if (onReady) onReady({ socketPath: relay.socketPath, requestId: request.requestId, jobId: job.id });
      return response;
    }, { signal: cancelled, deadlineMs, recordDir: journal });
    writeReportFile(output, 'relay-events.json', JSON.stringify(relay.events, null, 2));
    writeReportFile(output, 'job.json', JSON.stringify(job, null, 2));
    if (job.state !== 'collected' || !outcome.artifacts || outcome.ledger.cleanup.state !== 'removed' || outcome.ledger.recordPersistence !== 'saved') throw new Error('terminal review incomplete; inspect the parent journal');
  } finally {
    clearInterval(heartbeat);
    try { writeReportFile(output, 'heartbeat.json', JSON.stringify({ state: outcome?.artifacts ? 'exited' : 'stopped', at: new Date().toISOString(), elapsedMs: Date.now() - started, timeLimitMs: deadlineMs })); } catch { /* cleanup must still run */ }
    let relayRemoved = !relay;
    let sourceRemoved = !snapshot;
    try {
      if (relay) await relay.close();
      relayRemoved = !relay || !fs.existsSync(relay.socketPath);
    } finally {
      process.removeListener('SIGINT', stop);
      process.removeListener('SIGTERM', stop);
      try {
        if (snapshot) disposeSnapshot(snapshot);
        sourceRemoved = !snapshot || !fs.existsSync(snapshot.staging);
      } finally {
        writeReportFile(output, 'relay-state.json', JSON.stringify({ state: relay?.state() || 'not_started', socketRemoved: relayRemoved, sourceRemoved, origin: 'terminal_supplied_unverified', events: relay?.events || [] }, null, 2));
      }
    }
  }
  for (const [name, value] of Object.entries(outcome.artifacts.files)) writeReportFile(output, name, value);
  writeReportFile(output, 'result-state.json', JSON.stringify({ state: 'collected', origin: 'terminal_supplied_unverified', modelIdentity: 'unverified', toolsDisabled: 'unverified', executionEvidence: 'not_collected', outputHashes: outcome.artifacts.hashes }, null, 2));
  return outcome;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const options = parseLocalReview(process.argv.slice(2));
    await localTerminalReview(options, { onReady: (info) => process.stdout.write(`${terminalSafeJson({ state: 'awaiting_user_terminal', ...info, client: 'node audit/scripts/terminal-review-client.mjs claim --socket <socketPath>', note: 'Data-only handoff. Supply a structured result; no model is launched.' })}\n`) });
    process.stdout.write('Terminal review transport completed. Model identity and tool-free inference remain unverified.\n');
  } catch {
    console.error('Local terminal review failed or is incomplete. No model CLI or target code was executed.');
    process.exitCode = 2;
  }
}
