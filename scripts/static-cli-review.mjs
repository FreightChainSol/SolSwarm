import { pathToFileURL } from 'node:url';
import { parseLocalReview, localTerminalReview } from './terminal-local-review.mjs';
import { connectTerminal } from './terminal-model-connector.mjs';
import { ConnectorError } from './model-cli-claude.mjs';
import { REVIEW_PROFILES, createReviewAdapter } from './model-cli-profile.mjs';
import { terminalSafeJson } from './terminal-review-contract.mjs';
import { writeReportFile } from './report-contract.mjs';
import { providerDiagnostic } from './provider-error-diagnostic.mjs';

export function parseStaticReview(argv) {
  const local = [];
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i];
    const value = argv[i + 1];
    if (typeof value !== 'string' || !value || value.startsWith('--')) throw new ConnectorError('static_review_usage');
    if (['--repo', '--out', '--file'].includes(flag)) local.push(flag, value);
    else if (['--provider', '--model'].includes(flag) && !options[flag.slice(2)]) options[flag.slice(2)] = value;
    else throw new ConnectorError('static_review_usage');
  }
  if (!REVIEW_PROFILES.includes(options.provider)) throw new ConnectorError('provider_tool_free_mode_unverified');
  if (typeof options.model !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(options.model)) throw new ConnectorError('requested_model_rejected');
  try { return { ...parseLocalReview(local), ...options }; } catch { throw new ConnectorError('static_review_usage'); }
}

// Dependency injection is internal test support, never command-line/RPC configuration.
export async function staticCliReview(options, { adapter, signal, runLocal = localTerminalReview, connect = connectTerminal, deadlineMs = null } = {}) {
  if (!options || Object.keys(options).some((key) => !['repo', 'out', 'files', 'provider', 'model'].includes(key)) || !Array.isArray(options.files)) throw new ConnectorError('static_review_usage');
  const parsed = parseStaticReview(['--repo', options.repo, '--out', options.out, ...options.files.flatMap((file) => ['--file', file]), '--provider', options.provider, '--model', options.model]);
  if (deadlineMs != null && (!Number.isSafeInteger(deadlineMs) || deadlineMs < 50 || deadlineMs > 2_147_483_647)) throw new ConnectorError('connector_deadline_rejected');
  const controller = new AbortController();
  const active = signal ? AbortSignal.any([signal, controller.signal]) : controller.signal;
  if (active.aborted) throw new ConnectorError('connector_cancelled');
  return (adapter || createReviewAdapter(parsed.provider, parsed.model)).withSession(async (session) => {
    if (active.aborted) throw new ConnectorError('connector_cancelled');
    let connection;
    let connectorFailure;
    let started = false;
    try {
      await runLocal(parsed, {
        signal: active, deadlineMs,
        onReady: ({ socketPath }) => {
          if (started) throw new ConnectorError('duplicate_review_request');
          started = true;
          connection = Promise.resolve().then(() => connect({ operation: 'connect', provider: parsed.provider, model: parsed.model, socket: socketPath }, {
            signal: active,
            adapter: { withSession: async (callback, { signal: inner } = {}) => {
              // The reused CLI session must also observe connector job-loss cancellation.
              const abort = () => controller.abort();
              inner?.addEventListener('abort', abort, { once: true });
              try {
                if (inner?.aborted) abort();
                return await callback(session);
              } finally { inner?.removeEventListener('abort', abort); }
            } },
          }));
          connection.catch((err) => { connectorFailure = err; controller.abort(); });
        },
      });
      if (!connection) throw new ConnectorError('connector_not_started');
      const result = await connection;
      if (active.aborted) throw new ConnectorError('connector_cancelled');
      if (result?.state !== 'submitted') throw new ConnectorError('connector_submission_incomplete');
      const status = { ...result, state: 'collected', scope: 'explicit_local_text_review_only', toolsDisabled: 'unverified', executionEvidence: 'not_collected' };
      writeReportFile(parsed.out, 'connector-state.json', JSON.stringify(status, null, 2));
      return status;
    } catch (err) {
      controller.abort();
      if (connection) await connection.catch(() => {});
      const failure = connectorFailure || err;
      const reason = failure instanceof ConnectorError ? failure.code : signal?.aborted ? 'connector_cancelled' : 'terminal_review_incomplete';
      const event = failure instanceof ConnectorError ? failure.event : undefined;
      const diagnostic = failure instanceof ConnectorError ? providerDiagnostic(failure.diagnostic) : undefined;
      if (started) writeReportFile(parsed.out, 'connector-state.json', JSON.stringify({ state: 'blocked_or_incomplete', provider: parsed.provider, requestedModel: parsed.model, reason, event, diagnostic, executionEvidence: 'not_collected' }, null, 2));
      const rejected = new ConnectorError(reason, event);
      if (diagnostic) rejected.diagnostic = diagnostic;
      throw rejected;
    }
  }, { signal: active });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const controller = new AbortController();
  const stop = () => { controller.abort(); process.exitCode = 130; };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
  try {
    const result = await staticCliReview(parseStaticReview(process.argv.slice(2)), { signal: controller.signal });
    process.stdout.write(`${terminalSafeJson(result)}\n`);
  } catch (err) {
    const reason = err instanceof ConnectorError ? err.code : 'terminal_review_incomplete';
    const event = err instanceof ConnectorError ? err.event : undefined;
    const diagnostic = err instanceof ConnectorError ? providerDiagnostic(err.diagnostic) : undefined;
    process.stderr.write(`${terminalSafeJson({ state: 'blocked_or_incomplete', reason, event, diagnostic, note: 'No unrestricted fallback. Inspect private output records if a job started; source was not executed.' })}\n`);
    if (!process.exitCode) process.exitCode = 2;
  } finally {
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
  }
}
