import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import crypto from 'node:crypto';
import { validateReviewRequest, validateSubmission, exactKeys, encodeFrame, readJsonLine } from './terminal-review-contract.mjs';

// Owner-only, single-job data exchange. No execute/read-file/env/fetch methods.
export async function createTerminalRelay(authorized, { deadlineMs = null, signal } = {}) {
  validateReviewRequest(authorized);
  if (deadlineMs != null && (!Number.isSafeInteger(deadlineMs) || deadlineMs < 50 || deadlineMs > 2_147_483_647)) throw new Error('relay deadline rejected');
  const request = structuredClone(authorized);
  const dir = fs.mkdtempSync('/tmp/fc-tr-');
  fs.chmodSync(dir, 0o700);
  const socketPath = path.join(dir, 's');
  const clients = new Set();
  let state = 'awaiting_worker';
  let claimId = null;
  let resolve;
  let reject;
  let closed = false;
  const completion = new Promise((yes, no) => { resolve = yes; reject = no; });
  completion.catch(() => {});
  const events = [];
  const record = (event) => { if (events.length < 100) events.push({ event, at: new Date().toISOString() }); };
  const fail = (reason) => {
    if (['submitted', 'cancelled', 'timed_out', 'closed'].includes(state)) return;
    state = reason === 'deadline' ? 'timed_out' : 'cancelled';
    record(state);
    reject(Object.assign(new Error(`terminal relay ${state}`), { code: state === 'timed_out' ? 'terminal_timeout' : 'terminal_cancelled' }));
  };
  const timer = deadlineMs == null ? null : setTimeout(() => fail('deadline'), deadlineMs);
  const abort = () => fail('cancelled');
  signal?.addEventListener('abort', abort, { once: true });
  const server = net.createServer(async (socket) => {
    if (clients.size >= 4 || closed) { socket.destroy(); return; }
    clients.add(socket);
    socket.on('error', () => {});
    socket.on('close', () => clients.delete(socket));
    try {
      const input = await readJsonLine(socket, { timeoutMs: 5000 });
      if (input?.method === 'review.status') {
        exactKeys(input, ['version', 'method']);
        if (input.version !== 1) throw new Error('version rejected');
        socket.end(encodeFrame({ version: 1, ok: true, data: { state } }));
      } else if (input?.method === 'review.claim') {
        exactKeys(input, ['version', 'method']);
        if (input.version !== 1 || state !== 'pending') throw new Error('review is not available to claim');
        claimId = crypto.randomUUID();
        state = 'claimed';
        record(state);
        socket.end(encodeFrame({ version: 1, ok: true, data: { claimId, request } }));
      } else if (input?.method === 'review.submit') {
        if (state !== 'claimed') throw new Error('review is not awaiting a result');
        validateSubmission(input, request, claimId);
        state = 'submitted';
        record(state);
        socket.end(encodeFrame({ version: 1, ok: true, data: { state } }));
        resolve(structuredClone(input.result));
      } else {
        throw new Error('method rejected');
      }
    } catch {
      record('request_rejected');
      if (!socket.destroyed) socket.end(encodeFrame({ version: 1, ok: false, error: 'terminal relay request rejected' }));
    }
  });
  const close = async () => {
    if (closed) return;
    closed = true;
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
    if (!['submitted', 'cancelled', 'timed_out'].includes(state)) {
      state = 'closed';
      reject(new Error('terminal relay closed'));
    }
    for (const socket of clients) socket.destroy();
    if (server.listening) await new Promise((done) => server.close(done));
    fs.rmSync(dir, { recursive: true, force: true });
    record('socket_removed');
  };
  try {
    await new Promise((yes, no) => { server.once('error', no); server.listen(socketPath, yes); });
    fs.chmodSync(socketPath, 0o600);
    if (signal?.aborted) abort();
    return {
      socketPath, events, completion, close,
      state: () => state,
      activate: (frame) => {
        validateReviewRequest(frame);
        if (JSON.stringify(frame) !== JSON.stringify(request)) throw new Error('unauthorized worker request');
        // Docker setup can consume the relay budget before the worker is ready.
        // Preserve that terminal cause instead of misclassifying it as bad input.
        if (state === 'timed_out' || state === 'cancelled') throw Object.assign(new Error(`terminal relay ${state}`), { code: state === 'timed_out' ? 'terminal_timeout' : 'terminal_cancelled' });
        if (state !== 'awaiting_worker') throw new Error('unauthorized worker request');
        state = 'pending';
        record(state);
        return completion;
      },
    };
  } catch (err) {
    await close();
    throw err;
  }
}

export async function relayCall(socketPath, frame, { signal } = {}) {
  if (signal?.aborted) throw new Error('terminal relay call cancelled');
  const stat = fs.lstatSync(socketPath);
  const parent = fs.lstatSync(path.dirname(socketPath));
  if (!stat.isSocket() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0 || !parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== process.getuid() || (parent.mode & 0o077) !== 0) throw new Error('relay requires an owner-only local socket');
  const socket = net.createConnection(socketPath);
  socket.on('error', () => {});
  const abort = () => socket.destroy(new Error('terminal relay call cancelled'));
  signal?.addEventListener('abort', abort, { once: true });
  socket.setTimeout(6000, () => socket.destroy(new Error('terminal connection deadline exceeded')));
  try {
    const response = readJsonLine(socket, { timeoutMs: 6000, signal });
    response.catch(() => {});
    await new Promise((yes, no) => { socket.once('connect', yes); socket.once('error', no); });
    if (signal?.aborted) throw new Error('terminal relay call cancelled');
    socket.end(encodeFrame(frame));
    const result = await response;
    if (result?.version !== 1 || result.ok !== true) throw new Error('terminal relay rejected the request');
    return result.data;
  } finally { signal?.removeEventListener('abort', abort); socket.destroy(); }
}
