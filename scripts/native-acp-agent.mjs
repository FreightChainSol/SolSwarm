import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';
import { fileURLToPath } from 'node:url';
import { buildCliInvocation } from './agent-launch.mjs';
import { readReportJson, writeReportFile } from './report-contract.mjs';
import { SessionError } from './agent-rpc.mjs';

const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const send = message => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', ...message }) + '\n');

// AGY exposes a structured stream. This adapter supplies ACP v1 lifecycle
// around its native saved conversations.
export class NativeAcpAgent {
  constructor(config, output = send) {
    if (config.agent !== 'agy' || !path.isAbsolute(config.cwd) || !path.isAbsolute(config.cli)) throw new SessionError('setup_error');
    if (config.legacyConversationId && (!UUID.test(config.legacyConversationId))) throw new SessionError('session_identity_rejected');
    this.config = config;
    this.output = output;
    this.active = null;
  }
  update(update) { this.output({ method: 'session/update', params: { sessionId: this.state.sessionId, update } }); }
  save() { writeReportFile(this.config.cwd, 'native-session.json', JSON.stringify(this.state)); }
  validateSetup(params) {
    if (params.cwd !== this.config.cwd || JSON.stringify(params.mcpServers) !== JSON.stringify(this.config.mcpServers)) throw new SessionError('session_identity_rejected');
  }
  async request(method, params = {}) {
    if (method === 'initialize') {
      if (params.protocolVersion !== 1) throw new SessionError('protocol_error');
      return { protocolVersion: 1, agentInfo: { name: `audit-${this.config.agent}-adapter`, version: '1.0.0' }, agentCapabilities: { loadSession: true, mcpCapabilities: { http: false, sse: false } }, authMethods: [] };
    }
    if (method === 'session/new') {
      this.validateSetup(params);
      if (this.state) throw new SessionError('protocol_error');
      const sessionId = crypto.randomUUID();
      this.state = { version: 1, sessionId, agent: this.config.agent, model: this.config.model, nativeId: this.config.legacyConversationId || null, turns: 0 };
      this.save();
      return { sessionId };
    }
    if (method === 'session/load') {
      this.validateSetup(params);
      const state = readReportJson(this.config.cwd, 'native-session.json');
      if (state.sessionId !== params.sessionId || state.agent !== this.config.agent || state.model !== this.config.model || !UUID.test(state.nativeId || '')) throw new SessionError('session_identity_rejected');
      this.state = state;
      return {};
    }
    if (method === 'session/cancel') {
      if (this.state?.sessionId !== params.sessionId) throw new SessionError('session_identity_rejected');
      this.cancelled = true;
      this.stop('SIGTERM');
      return {};
    }
    if (method === 'session/prompt') return this.prompt(params);
    throw new SessionError('unsupported_method');
  }
  stop(signal) {
    if (!this.active?.pid) return;
    // The native process shares this adapter's group so the coordinator can reap
    // the complete tree even if the adapter dies unexpectedly.
    try { this.active.kill(signal); } catch { /* already exited */ }
  }
  async prompt(params) {
    if (!this.state || params.sessionId !== this.state.sessionId || this.active || !Array.isArray(params.prompt) || params.prompt.some(p => p.type !== 'text' || typeof p.text !== 'string')) throw new SessionError('protocol_error');
    const text = params.prompt.map(p => p.text).join('\n');
    const server = this.config.mcpServers[0];
    if (this.config.mcpServers.length !== 1 || server.name !== 'audit_docker') throw new SessionError('setup_error');
    const invocation = buildCliInvocation({ agent: this.config.agent, model: this.config.model, prompt: text, workDir: this.config.cwd, bridgeArgs: server.args.slice(1), conversationId: this.state.nativeId });
    invocation.executable = this.config.cli;
    this.state.resuming = true;
    this.save();
    this.cancelled = false;
    this.update({ sessionUpdate: 'plan', entries: [{ content: 'Reviewing the assigned source through the audit bridge', status: 'in_progress', priority: 'high' }] });
    return new Promise((resolve, reject) => {
      const child = spawn(invocation.executable, invocation.args, { cwd: invocation.cwd, env: process.env, stdio: ['pipe', 'pipe', 'pipe'] });
      this.active = child;
      let buffer = '';
      let resultSeen = false;
      let successful = false;
      let invalid = false;
      let resultStatus = 'missing';
      let parseFailure = null;
      // Bounded enum counters only; provider text goes to the adapter log, not the saved state.
      const stepStates = {}, otherEvents = {};
      let resultKeys = [];
      const tally = (counter, name) => { const key = /^[A-Za-z0-9_]{1,64}$/.test(name || '') ? name : 'other'; if (key in counter || Object.keys(counter).length < 32) counter[key] = (counter[key] || 0) + 1; };
      const decoder = new StringDecoder('utf8');
      const fail = () => { invalid = true; this.stop('SIGTERM'); };
      child.stdin.on('error', () => {});
      child.stdin.end(invocation.stdin || '');
      child.stderr.on('data', data => process.stderr.write(data));
      const frame = line => {
        try {
          const value = JSON.parse(line);
          if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
          if (value.event === 'init' && UUID.test(value.conversation_id || '')) {
            if (this.state.nativeId && this.state.nativeId !== value.conversation_id) { parseFailure = 'session_mismatch'; throw new Error(); }
            this.state.nativeId = value.conversation_id; this.save();
          }
          if (value.event === 'step_update') {
            const step = value.step_update;
            tally(stepStates, step?.state);
            if (step?.tool_name) this.update({ sessionUpdate: 'tool_call_update', toolCallId: String(step.step_index), title: step.tool_name, status: step.state === 'STEP_STATE_DONE' ? 'completed' : 'in_progress' });
            else this.update({ sessionUpdate: 'agent_thought_chunk', content: { type: 'text', text: '' } });
          }
          if (!['init', 'step_update', 'result'].includes(value.event)) tally(otherEvents, typeof value.event === 'string' ? value.event : 'missing');
          if (value.event === 'result') {
            if (resultSeen) { parseFailure = 'duplicate_result'; throw new Error(); }
            resultSeen = true;
            successful = value.result?.status === 'SUCCESS';
            resultStatus = successful ? 'success' : value.result?.status === 'ERROR' ? 'error' : 'unrecognized';
            resultKeys = Object.keys(value.result || {}).filter(key => /^[A-Za-z0-9_]{1,64}$/.test(key)).slice(0, 32).sort();
            // A non-success result is otherwise unexplained: keep its fields (not the reply) in the log.
            if (!successful) { const { response, ...detail } = value.result || {}; process.stderr.write(`agy result ${JSON.stringify(detail).slice(0, 8192)}\n`); }
            if (typeof value.result?.response === 'string') this.update({ sessionUpdate: 'agent_message_chunk', content: { type: 'text', text: value.result.response } });
          }
        } catch { parseFailure ||= 'invalid_frame'; fail(); }
      };
      child.stdout.on('data', data => {
        buffer += decoder.write(data);
        for (let at; (at = buffer.indexOf('\n')) >= 0;) {
          const line = buffer.slice(0, at).trim(); buffer = buffer.slice(at + 1);
          if (!line) continue;
          if (line.length > 4 * 1024 * 1024) { parseFailure = 'oversized_frame'; fail(); break; }
          frame(line);
        }
        if (buffer.length > 4 * 1024 * 1024) { parseFailure = 'oversized_frame'; fail(); }
      });
      child.once('error', () => { invalid = true; });
      child.once('close', (code, signal) => {
        buffer += decoder.end();
        // A complete final JSON object need not have a trailing newline.
        if (buffer.trim() && !invalid) frame(buffer.trim());
        this.active = null;
        this.stop('SIGKILL');
        this.state.turns++;
        this.state.lastTurn = { exitCode: code, signal, resultStatus, resultSeen, parseFailure, sessionBound: UUID.test(this.state.nativeId || ''), resultKeys, stepStates, otherEvents };
        this.save();
        if (this.cancelled) resolve({ stopReason: 'cancelled' });
        else if (invalid || code !== 0 || !successful || !resultSeen || !UUID.test(this.state.nativeId || '')) reject(new SessionError('native_turn_failed'));
        else resolve({ stopReason: 'end_turn' });
      });
    });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const configPath = path.resolve(process.argv[2]);
  const config = readReportJson(path.dirname(configPath), path.basename(configPath));
  const agent = new NativeAcpAgent(config);
  let buffer = '';
  process.stdin.on('data', data => {
    buffer += data.toString('utf8');
    if (buffer.length > 4 * 1024 * 1024) { process.exitCode = 2; process.stdin.destroy(); agent.stop('SIGKILL'); return; }
    for (let at; (at = buffer.indexOf('\n')) >= 0;) {
      const line = buffer.slice(0, at); buffer = buffer.slice(at + 1);
      if (!line.trim()) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { process.exitCode = 2; process.stdin.destroy(); continue; }
      // A prompt must not block cancellation or a subsequent RPC control message.
      Promise.resolve().then(() => agent.request(msg.method, msg.params)).then(
        result => { if (msg.id != null) send({ id: msg.id, result }); },
        err => { if (msg.id != null) send({ id: msg.id, error: { code: -32000, message: err.reason || 'native_turn_failed' } }); },
      );
    }
  });
  process.stdin.on('end', () => { agent.stop('SIGTERM'); });
}
