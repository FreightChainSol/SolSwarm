import { pathToFileURL } from 'node:url';
import { ConnectorError } from './model-cli-claude.mjs';
import { REVIEW_PROFILES, createReviewAdapter } from './model-cli-profile.mjs';
import { relayCall } from './terminal-relay.mjs';
import { validateReviewRequest, validateResult, terminalSafeJson } from './terminal-review-contract.mjs';
import { MODEL_CLIS, checkModelCli, checkAllModelClis } from './model-cli-status.mjs';
import { providerDiagnostic } from './provider-error-diagnostic.mjs';

export function parseConnectorArgs(argv) {
  const [operation, ...flags] = argv;
  if (!['check', 'connect'].includes(operation)) throw new ConnectorError('connector_usage');
  if (operation === 'check' && flags.length === 1 && flags[0] === '--all') return { operation, all: true };
  const options = { operation };
  for (let i = 0; i < flags.length; i += 2) {
    const flag = flags[i];
    const value = flags[i + 1];
    if (!['--provider', '--model', '--socket'].includes(flag) || !value || options[flag.slice(2)]) throw new ConnectorError('connector_usage');
    options[flag.slice(2)] = value;
  }
  if (operation === 'connect' && !REVIEW_PROFILES.includes(options.provider)) throw new ConnectorError('provider_tool_free_mode_unverified');
  if (operation === 'check' && !MODEL_CLIS.includes(options.provider) && !REVIEW_PROFILES.includes(options.provider)) throw new ConnectorError('provider_unknown');
  if (operation === 'connect' && (!options.socket || typeof options.model !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(options.model))) throw new ConnectorError('connector_usage');
  if (operation === 'check' && (options.socket || options.model)) throw new ConnectorError('connector_usage');
  return options;
}
export async function connectTerminal(options, { adapter, signal, call = relayCall } = {}) {
  if (options.operation === 'check' && options.all === true) return checkAllModelClis({ signal });
  if (options.operation === 'check' && !REVIEW_PROFILES.includes(options.provider)) return checkModelCli(options.provider, { signal });
  if (!REVIEW_PROFILES.includes(options.provider) || !['check', 'connect'].includes(options.operation)) throw new ConnectorError('provider_tool_free_mode_unverified');
  if (options.operation === 'connect' && (!options.socket || typeof options.model !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(options.model))) throw new ConnectorError('connector_usage');
  const job = new AbortController();
  const activeSignal = signal ? AbortSignal.any([signal, job.signal]) : job.signal;
  return (adapter || createReviewAdapter(options.provider, options.model, options.operation === 'check')).withSession(async (session) => {
    if (signal?.aborted) throw new ConnectorError('connector_cancelled');
    const nativeIdentity = session.sourceCommit ? { sourceCommit: session.sourceCommit, ...(session.brokerIdentity ? { brokerIdentity: session.brokerIdentity } : {}) } : {};
    if (options.operation === 'check') return { state: 'ready', profile: options.provider, provider: session.provider, cliVersion: session.version, authMethod: session.authMethod, ...nativeIdentity, scope: 'explicit_local_text_review_only' };
    const claimed = await call(options.socket, { version: 1, method: 'review.claim' }, { signal });
    if (signal?.aborted) throw new ConnectorError('connector_cancelled');
    const request = validateReviewRequest(claimed.request);
    let watching = true;
    let polling = false;
    const monitor = new AbortController();
    const watch = setInterval(async () => {
      if (polling || !watching) return;
      polling = true;
      try {
        const status = await call(options.socket, { version: 1, method: 'review.status' }, { signal: monitor.signal });
        if (watching && status?.state !== 'claimed') job.abort();
      } catch { if (watching) job.abort(); } finally { polling = false; }
    }, 500);
    let answer;
    try { answer = await session.review(request, options.model); } finally {
      watching = false;
      clearInterval(watch);
      monitor.abort();
    }
    const { review, cliReportedModel } = answer;
    if (activeSignal.aborted) throw new ConnectorError('connector_cancelled');
    if (signal?.aborted) throw new ConnectorError('connector_cancelled');
    validateResult(review, request);
    await call(options.socket, { version: 1, method: 'review.submit', requestId: request.requestId, jobId: request.jobId, sourceDigest: request.sourceDigest, claimId: claimed.claimId, result: review }, { signal });
    if (activeSignal.aborted) throw new ConnectorError('submission_outcome_unknown');
    return { state: 'submitted', profile: options.provider, provider: session.provider, cliVersion: session.version, ...nativeIdentity, requestedModel: options.model, cliReportedModel, provenance: 'terminal_supplied_unverified', modelIdentity: 'unverified', executionEvidence: 'not_collected' };
  }, { signal: activeSignal });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const controller = new AbortController();
  const stop = () => { controller.abort(); process.exitCode = 130; };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
  try {
    const result = await connectTerminal(parseConnectorArgs(process.argv.slice(2)), { signal: controller.signal });
    process.stdout.write(`${terminalSafeJson(result)}\n`);
    if (['blocked', 'unavailable'].includes(result.state)) process.exitCode = 2;
  } catch (err) {
    const reason = err instanceof ConnectorError ? err.code : 'connector_failed';
    const event = err instanceof ConnectorError ? err.event : undefined;
    const diagnostic = err instanceof ConnectorError ? providerDiagnostic(err.diagnostic) : undefined;
    process.stderr.write(`${terminalSafeJson({ state: 'blocked_or_incomplete', reason, event, diagnostic, note: 'No unrestricted CLI fallback. Use official subscription login if required; do not provide credentials to the relay.' })}\n`);
    if (!process.exitCode) process.exitCode = 2;
  } finally {
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
  }
}
