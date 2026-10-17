import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { readReportJson, writeReportFile } from './report-contract.mjs';
import { SessionError } from './agent-rpc.mjs';

export const digest = value => crypto.createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex');

export function openSessionStore(directory, identity) {
  if (!identity || !['claude', 'codex', 'grok', 'agy'].includes(identity.agent) || !/^[a-f0-9]{64}$/.test(identity.sourceDigest) || !/^[a-f0-9]{64}$/.test(identity.assignmentDigest) || !/^[\w.:-]{1,128}$/.test(identity.model)) throw new SessionError('session_identity_rejected');
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077)) throw new SessionError('session_directory_rejected');
  let state;
  if (fs.existsSync(path.join(directory, 'state.json'))) {
    state = readReportJson(directory, 'state.json');
    if (state.version !== 1 || !isDeepStrictEqual(state.identity, identity)) throw new SessionError('session_identity_rejected');
  } else state = { version: 1, identity, sessionId: null, phase: 'new', recoveryAttempts: 0, sequence: 0, events: [] };
  fs.mkdirSync(path.join(directory, 'workspace'), { mode: 0o700, recursive: true });
  const workspace = path.join(directory, 'workspace');
  const workStat = fs.lstatSync(workspace);
  if (!workStat.isDirectory() || workStat.isSymbolicLink() || workStat.uid !== process.getuid() || (workStat.mode & 0o077)) throw new SessionError('session_directory_rejected');
  const save = (phase, details = {}) => {
    state = { ...state, ...details, phase, updatedAt: new Date().toISOString(), sequence: state.sequence + 1 };
    const { event, activity } = details;
    state.events = [...state.events, { sequence: state.sequence, at: state.updatedAt, phase, ...(event ? { event } : {}), ...(activity ? { activity } : {}) }].slice(-200);
    writeReportFile(directory, 'state.next.json', JSON.stringify(state, null, 2) + '\n');
    fs.renameSync(path.join(directory, 'state.next.json'), path.join(directory, 'state.json'));
    return state;
  };
  return { directory, workspace, get state() { return state; }, save };
}
