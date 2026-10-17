import fs from 'node:fs';
import { spawn } from 'node:child_process';

export class SessionError extends Error {
  constructor(reason, message = reason) { super(message); this.reason = reason; }
}

// Prompts have no deadline. Only protocol setup/control operations have bounded waits.
export class AgentRpc {
  constructor(invocation, { onNotification = () => {}, onRequest = async () => { throw new SessionError('permission_denied'); }, onActivity = () => {}, logFile } = {}) {
    this.pending = new Map();
    this.sequence = 0;
    this.buffer = Buffer.alloc(0);
    this.stderr = '';
    this.closed = false;
    this.logBytes = 0;
    if (logFile) {
      this.log = fs.openSync(logFile, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o600);
      const stat = fs.fstatSync(this.log);
      if (!stat.isFile() || stat.nlink !== 1) { fs.closeSync(this.log); throw new SessionError('setup_error'); }
      fs.fchmodSync(this.log, 0o600);
      fs.ftruncateSync(this.log, 0);
    }
    this.child = spawn(invocation.executable, invocation.args, { cwd: invocation.cwd, env: invocation.env, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
    this.exited = new Promise(resolve => { this.resolveExit = resolve; });
    this.child.stdin.on('error', () => {});
    this.child.stdout.on('data', chunk => {
      onActivity('transport');
      this.record(chunk);
      this.buffer = Buffer.concat([this.buffer, chunk]);
      for (let at; (at = this.buffer.indexOf(10)) >= 0;) {
        if (at > 4 * 1024 * 1024) { this.fail(new SessionError('protocol_error')); return; }
        const line = this.buffer.subarray(0, at);
        this.buffer = this.buffer.subarray(at + 1);
        if (!line.length) continue;
        try {
          const msg = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(line));
          if (!msg || typeof msg !== 'object' || Array.isArray(msg)) throw new Error('Invalid RPC frame');
          if (msg.method && msg.id != null) {
            Promise.resolve().then(() => onRequest(msg.method, msg.params)).then(
              result => this.send({ jsonrpc: '2.0', id: msg.id, result }),
              () => this.send({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'Client capability unavailable for this audit session.' } }),
            ).catch(() => {});
          } else if (msg.method) onNotification(msg.method, msg.params);
          else if (msg.id != null) {
            const pending = this.pending.get(msg.id);
            if (!pending) continue;
            this.pending.delete(msg.id);
            clearTimeout(pending.timer);
            if (msg.error) pending.reject(new SessionError(msg.error.code === -32000 && msg.error.message === 'native_turn_failed' ? 'native_turn_failed' : 'provider_error', JSON.stringify(msg.error).slice(0, 8192)));
            else if (Object.hasOwn(msg, 'result')) pending.resolve(msg.result);
            else throw new Error('Missing RPC result');
          } else throw new Error('Invalid RPC envelope');
        } catch (err) { this.fail(err instanceof SessionError ? err : new SessionError('protocol_error')); return; }
      }
      if (this.buffer.length > 4 * 1024 * 1024) this.fail(new SessionError('protocol_error'));
    });
    this.child.stderr.on('data', chunk => { onActivity('process'); this.record(chunk); this.stderr = (this.stderr + chunk.toString('utf8')).slice(-64_000); });
    this.child.on('error', () => this.fail(new SessionError('setup_error')));
    this.child.on('close', (code, signal) => {
      this.closed = true;
      this.exitCode = code;
      this.exitSignal = signal;
      this.rejectPending(new SessionError('transport_lost'));
      if (this.log != null) { fs.closeSync(this.log); this.log = null; }
      this.resolveExit({ code, signal });
    });
  }
  record(chunk) {
    if (this.log == null || this.logBytes >= 8 * 1024 * 1024) return;
    const part = chunk.subarray(0, 8 * 1024 * 1024 - this.logBytes);
    try { fs.writeSync(this.log, part); this.logBytes += part.length; } catch { /* preserve process and protocol diagnostics in memory */ }
  }
  send(message) {
    if (this.closed || !this.child.stdin.writable) throw new SessionError('transport_lost');
    this.child.stdin.write(JSON.stringify(message) + '\n');
  }
  request(method, params = {}, timeoutMs = 30_000) {
    if (this.closed) return Promise.reject(new SessionError('transport_lost'));
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const timer = timeoutMs == null ? null : setTimeout(() => {
        this.pending.delete(id);
        reject(new SessionError('control_timeout'));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      try { this.send({ jsonrpc: '2.0', id, method, params }); }
      catch (err) { this.pending.delete(id); clearTimeout(timer); reject(err); }
    });
  }
  notify(method, params = {}) { this.send({ jsonrpc: '2.0', method, params }); }
  rejectPending(error) {
    for (const { reject, timer } of this.pending.values()) { clearTimeout(timer); reject(error); }
    this.pending.clear();
  }
  kill(signal) {
    if (!this.child.pid) return;
    try { process.kill(-this.child.pid, signal); } catch { try { this.child.kill(signal); } catch { /* already exited */ } }
  }
  fail(error) { this.rejectPending(error); this.kill('SIGTERM'); }
  async close() {
    if (this.disposed) return this.exited;
    this.disposed = true;
    this.closing = true;
    this.child.stdin.end();
    if (!this.closed) {
      const graceful = await Promise.race([this.exited.then(() => true), new Promise(resolve => { const t = setTimeout(() => resolve(false), this.graceMs ?? 10_000); t.unref(); })]);
      if (!graceful) this.kill('SIGTERM');
      if (!this.closed) await Promise.race([this.exited, new Promise(resolve => { const t = setTimeout(resolve, 1500); t.unref(); })]);
    }
    // Reap children still in the owned group even when the adapter exited first.
    this.kill('SIGKILL');
    if (!this.closed) await this.exited;
    return { code: this.exitCode, signal: this.exitSignal };
  }
}
