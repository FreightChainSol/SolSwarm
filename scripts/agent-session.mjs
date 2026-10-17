import fs from 'node:fs';
import path from 'node:path';
import { AgentRpc, SessionError } from './agent-rpc.mjs';
import { openSessionStore } from './agent-session-store.mjs';
import { buildSessionLaunch } from './agent-session-launch.mjs';
import { classifyAuditFailure } from './audit-process.mjs';

import { REVIEW_TOOLS as TOOLS } from './review-workflow.mjs';

export function permissionDecision(params, expectedSession) {
  if (params?.sessionId !== expectedSession) return { outcome: { outcome: 'cancelled' } };
  const call = params.toolCall;
  const name = call?._meta?.claudeCode?.toolName;
  const qualified = typeof name === 'string' && name.startsWith('mcp__audit_docker__') && TOOLS.has(name.slice('mcp__audit_docker__'.length));
  const codexMcp = call?._meta?.is_mcp_tool_call === true && call.rawInput?.server === 'audit_docker' && TOOLS.has(call.rawInput.tool);
  const grokTool = call?._meta?.['x.ai/tool'];
  const grokName = call?.rawInput?.tool_name;
  const grokMcp = grokTool?.version === 1 && grokTool.name === 'use_tool' && grokTool.kind === 'use_tool' && call.rawInput?.variant === 'UseTool' && typeof grokName === 'string' && grokName.startsWith('audit_docker__') && TOOLS.has(grokName.slice('audit_docker__'.length));
  const kind = qualified || codexMcp || grokMcp ? 'allow_once' : 'reject_once';
  const option = params.options?.find(o => o.kind === kind);
  return option ? { outcome: { outcome: 'selected', optionId: option.optionId } } : { outcome: { outcome: 'cancelled' } };
}

function modelValue(options) { return options?.find(option => option.category === 'model' || option.id === 'model')?.currentValue; }

export async function preflightBridge(server, { cwd, env, signal, expectedRole }) {
  const rpc = new AgentRpc({ executable: server.command, args: server.args, cwd, env });
  const abort = () => rpc.fail(new SessionError('cancelled'));
  signal?.addEventListener('abort', abort, { once: true });
  try {
    if (signal?.aborted) throw new SessionError('cancelled');
    await rpc.request('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'audit-preflight', version: '1.0.0' } });
    rpc.notify('notifications/initialized');
    const result = await rpc.request('tools/list');
    const names = new Set(result.tools?.map(tool => tool.name));
    const required = expectedRole === 'crosscheck' ? 'submit_crosscheck_report' : 'submit_audit_report';
    if (['write_poc', 'run_container_check', 'get_attack_plan'].some(name => names.has(name)) || !names.has('list_existing_tests') || !names.has('run_existing_tests') || !names.has('get_audit_context') || !names.has('read_file') || !names.has(required)) throw new SessionError('mcp_unavailable');
    await rpc.request('ping');
    return { state: 'ready', tools: [...names] };
  } catch (err) { throw err.reason === 'cancelled' ? err : new SessionError('mcp_unavailable'); }
  finally { signal?.removeEventListener('abort', abort); await rpc.close(); }
}

// All four providers use this ACP client. Native CLI compatibility is isolated
// behind native-acp-agent; the coordinator never parses their terminal prose.
export async function runReviewSession(options, { launch = buildSessionLaunch, preflight = preflightBridge, heartbeatMs = 30_000, maxRecoveries = 1 } = {}) {
  if (!Number.isSafeInteger(heartbeatMs) || heartbeatMs < 10 || heartbeatMs > 2_147_483_647 || !Number.isInteger(maxRecoveries) || maxRecoveries < 0 || maxRecoveries > 2) throw new SessionError('setup_error');
  const { directory, identity, bridgeArgs, prompt, signal, onProgress = () => {}, legacyConversationId, env = process.env, logFile } = options;
  const store = openSessionStore(directory, identity);
  const started = Date.now();
  let lastAgent = null;
  let lastTransport = null;
  let lastProcess = null;
  let phase = 'starting';
  let currentRpc = null;
  let activeModel;
  let sessionId = store.state.sessionId;
  let totalRecoveries = 0;
  let observedExit;
  const progress = () => {
    const now = Date.now();
    const status = { phase, elapsedMs: now - started, agentIdleMs: lastAgent == null ? null : now - lastAgent, transportIdleMs: lastTransport == null ? null : now - lastTransport, processIdleMs: lastProcess == null ? null : now - lastProcess, pid: currentRpc?.child.pid, sessionId, timeLimitMs: null };
    store.save(phase, { heartbeat: status });
    onProgress(status);
  };
  const timer = setInterval(() => {
    try { progress(); }
    catch { currentRpc?.fail(new SessionError('session_record_failed')); }
  }, heartbeatMs);
  const abort = () => {
    phase = 'cancelling';
    try { if (sessionId) currentRpc?.notify('session/cancel', { sessionId }); } catch { /* transport already lost */ }
    currentRpc?.rejectPending(new SessionError('cancelled'));
  };
  signal?.addEventListener('abort', abort, { once: true });
  try {
    if (signal?.aborted) throw new SessionError('cancelled');
    const spec = launch({ agent: identity.agent, model: identity.model, workDir: store.workspace, bridgeArgs, legacyConversationId, env });
    const bridge = await preflight(spec.mcpServers[0], { cwd: store.workspace, env: spec.invocation.env, signal, expectedRole: identity.role });
    store.save('bridge_ready', { bridge, transport: spec.transport });
    for (;;) {
      let resumeCapable = false;
      const attempt = totalRecoveries;
      currentRpc = new AgentRpc(spec.invocation, {
        logFile: logFile ? attempt ? `${logFile}.recovery-${attempt}` : logFile : undefined,
        onActivity: kind => { if (kind === 'transport') lastTransport = Date.now(); else lastProcess = Date.now(); },
        onRequest: async (method, params) => {
          if (method !== 'session/request_permission') throw new SessionError('permission_denied');
          phase = 'waiting_permission';
          const decision = permissionDecision(params, sessionId);
          store.save(phase, { event: decision.outcome.outcome === 'selected' ? 'permission_decided' : 'permission_denied' });
          phase = 'running';
          return decision;
        },
        onNotification: (method, params) => {
          if (method !== 'session/update') return;
          // During load, an adapter may replay history before returning. Its
          // notifications must still belong to the exact saved session.
          if (sessionId && params?.sessionId !== sessionId) throw new SessionError('session_identity_rejected');
          lastAgent = Date.now();
          const update = params?.update;
          if (update?.sessionUpdate === 'config_option_update') {
            const value = modelValue(update.configOptions);
            if (value && activeModel && value !== activeModel) throw new SessionError('model_changed');
          }
          if (['tool_call', 'tool_call_update', 'plan'].includes(update?.sessionUpdate)) store.save(phase, { activity: update.sessionUpdate });
        },
      });
      try {
        phase = 'initializing';
        const init = await currentRpc.request('initialize', { protocolVersion: 1, clientInfo: { name: 'freightchain-audit', version: '1.0.0' }, clientCapabilities: { fs: { readTextFile: false, writeTextFile: false }, terminal: false } });
        if (init.protocolVersion !== 1) throw new SessionError('protocol_error');
        resumeCapable = init.agentCapabilities?.loadSession === true;
        const agentInfo = init.agentInfo || (typeof init._meta?.agentVersion === 'string' ? { name: identity.agent, version: init._meta.agentVersion.slice(0, 128) } : {});
        store.save(phase, { agentCapabilities: init.agentCapabilities || {}, agentInfo, resumeCapable });
        const params = { cwd: store.workspace, mcpServers: spec.mcpServers, ...(spec.sessionMeta ? { _meta: spec.sessionMeta } : {}) };
        let opened;
        if (sessionId) {
          if (!resumeCapable) throw new SessionError('resume_unsupported');
          phase = 'resuming';
          opened = await currentRpc.request('session/load', { ...params, sessionId }, 60_000);
        } else {
          opened = await currentRpc.request('session/new', params, 60_000);
          if (typeof opened.sessionId !== 'string' || !/^[A-Za-z0-9_.:-]{1,200}$/.test(opened.sessionId)) throw new SessionError('protocol_error');
          sessionId = opened.sessionId;
        }
        activeModel = modelValue(opened.configOptions) || opened.models?.currentModelId;
        if (['codex', 'grok'].includes(identity.agent) && activeModel && activeModel.split('[')[0] !== identity.model) throw new SessionError('model_changed');
        store.save('running', { sessionId, selectedModel: activeModel || identity.model });
        phase = 'running';
        if (signal?.aborted) throw new SessionError('cancelled');
        const continuation = attempt || options.resume ? '\n\nContinue the saved review for this exact source and assignment. Retain supported work and disclose remaining coverage. Use the current audit MCP bridge. If the report was already submitted successfully, finish without resubmitting it.' : '';
        const result = await currentRpc.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: prompt + continuation }] }, null);
        // A loaded conversation can replay old errors, and a review can quote them.
        // Only the current RPC failure/stop status controls whether this turn succeeded.
        if (result.stopReason === 'cancelled' || signal?.aborted) throw new SessionError('cancelled');
        if (result.stopReason !== 'end_turn') throw new SessionError('turn_incomplete');
        if (init.agentCapabilities?.sessionCapabilities?.close) await currentRpc.request('session/close', { sessionId });
        const exit = await currentRpc.close();
        if (exit.code != null && exit.code !== 0) throw new SessionError('process_error');
        phase = 'completed';
        store.save(phase, { stopReason: result.stopReason, completedAt: new Date().toISOString() });
        return { code: 0, observedExitCode: exit.code, processSignal: exit.signal, elapsedMs: Date.now() - started, sessionId, directory, transport: spec.transport, stopReason: result.stopReason, recoveryAttempts: totalRecoveries };
      } catch (error) {
        const failure = classifyAuditFailure({ code: 1, stderr: error.message });
        const reason = signal?.aborted ? 'cancelled' : error.reason === 'provider_error' && ['provider_policy', 'usage_limit', 'auth_required', 'mcp_unavailable'].includes(failure.reason) ? failure.reason : error.reason || 'process_error';
        if (reason === 'transport_lost' && resumeCapable && sessionId && totalRecoveries < maxRecoveries && !signal?.aborted) {
          totalRecoveries++;
          store.save('interrupted', { reason, recoveryAttempts: (store.state.recoveryAttempts || 0) + 1 });
          await currentRpc.close();
          continue;
        }
        throw new SessionError(reason);
      } finally { observedExit = await currentRpc.close(); currentRpc = null; }
    }
  } catch (error) {
    phase = error.reason === 'cancelled' ? 'cancelled' : 'failed';
    store.save(phase, { failureReason: error.reason || 'process_error', observedExitCode: observedExit?.code ?? null, processSignal: observedExit?.signal ?? null });
    return { code: error.reason === 'cancelled' ? 130 : 1, observedExitCode: observedExit?.code, processSignal: observedExit?.signal, elapsedMs: Date.now() - started, failureReason: error.reason || 'process_error', sessionId, directory };
  } finally { clearInterval(timer); signal?.removeEventListener('abort', abort); }
}
