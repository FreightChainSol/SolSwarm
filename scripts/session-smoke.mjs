import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runReviewSession } from './agent-session.mjs';
import { digest } from './agent-session-store.mjs';
import { readCanonicalSubmission } from './audit-submission.mjs';
import { REVIEW_WORKFLOW } from './review-workflow.mjs';
import { writeReportFile, readReportJson } from './report-contract.mjs';

const MODELS = { claude: 'opus', codex: 'gpt-6.1-sol', grok: 'grok-4.7', agy: 'gemini-4-argon-high' };
const BRIDGE = fileURLToPath(new URL('./docker-mcp-bridge.mjs', import.meta.url));
const IMAGE = 'node@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392';

export async function qualifyAgentSessions({ out, agents = Object.keys(MODELS), models = MODELS, signal }) {
  const root = path.resolve(out);
  if (!agents.length || new Set(agents).size !== agents.length || agents.some(agent => !Object.hasOwn(MODELS, agent))) throw new Error('Unknown or duplicate agent');
  if (fs.existsSync(root) && fs.readdirSync(root).length) throw new Error('Qualification output must be empty');
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const source = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-acp-inert-'));
  fs.chmodSync(source, 0o755);
  const marker = `INERT_BRIDGE_${crypto.randomBytes(16).toString('hex')}`;
  fs.writeFileSync(path.join(source, 'sample.txt'), marker + '\n', { mode: 0o644 });
  const container = `audit-acp-smoke-${crypto.randomUUID()}`;
  const docker = args => {
    const result = spawnSync('docker', args, { encoding: 'utf8', timeout: 20_000, maxBuffer: 1024 * 1024 });
    if (result.status !== 0) throw new Error(`Docker qualification control failed: ${args[0]}`);
    return result.stdout;
  };
  let owned = false;
  const results = [];
  try {
    docker(['image', 'inspect', IMAGE]);
    docker(['run', '--detach', '--pull=never', '--name', container, '--label', `freightchain.audit.smoke=${container}`, '--network', 'none', '--user', '10001:10001', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '128m', '--pids-limit', '64', '--cpus', '1', '--mount', `type=bind,src=${source},dst=/work/src,readonly`, IMAGE, 'node', '-e', 'setInterval(() => {}, 1000)']);
    owned = true;
    for (const agent of agents) {
      const reportDir = path.join(root, agent);
      fs.mkdirSync(path.join(reportDir, 'harness'), { recursive: true, mode: 0o700 });
      const name = `${agent}-s1-auth`;
      const identity = { name, agent, role: 'auditor', workflow: REVIEW_WORKFLOW, model: models[agent], sourceDigest: digest(marker + '\n'), assignmentDigest: digest('inert-transport-qualification'), surface: 'S1' };
      writeReportFile(reportDir, 'identity.json', JSON.stringify(identity));
      const options = {
        directory: path.join(reportDir, 'session'), identity, signal,
        bridgeArgs: ['--container', container, '--report-dir', reportDir, '--role', 'auditor', '--auditor', name, '--agent', agent, '--surface', 'S1', '--identity-file', path.join(reportDir, 'identity.json')],
        logFile: path.join(reportDir, 'first-turn.log'),
        onProgress: event => console.log(`[${agent}] ${event.phase}: ${Math.floor(event.elapsedMs / 1000)}s; agent activity ${event.agentIdleMs == null ? 'none yet' : Math.floor(event.agentIdleMs / 1000) + 's ago'}`),
      };
      console.log(`[${agent}] qualifying native session and Docker MCP access...`);
      const discovery = agent === 'agy' ? `First use view_file to read the exact staged skill ${path.join(options.directory, 'workspace/.agents/skills/security-audit/SKILL.md')} (omit the optional IsSkillFile hint), and the audit MCP schema ${path.join(os.homedir(), '.gemini/antigravity-cli/mcp/audit-docker_audit_docker/read_file.json')}. Those two trusted metadata files are allowed by the hook. After that, use only audit_docker MCP. ` : 'Use only audit_docker MCP. ';
      const first = await runReviewSession({ ...options, prompt: 'This is an inert integration fixture, not a security audit. ' + discovery + 'Call get_audit_context, then read_file for sample.txt line 1. Remember the exact line for the next turn. Reply with a short acknowledgement. Do not submit any report yet. Do not use other host files or tools.' });
      if (first.code !== 0) { results.push({ agent, state: 'incomplete', reason: first.failureReason }); continue; }
      console.log(`[${agent}] loading saved conversation and collecting the remembered fixture line...`);
      const second = await runReviewSession({ ...options, resume: true, logFile: path.join(reportDir, 'resumed-turn.log'), prompt: 'Continue this inert integration fixture. Without reading sample.txt again, submit_audit_report using only report_json: a JSON string of {findings:[],verified_safe:[{control:"Inert transport fixture only",evidence:THE EXACT LINE REMEMBERED FROM THE PREVIOUS TURN,holds:true}],markdown_summary:"Transport qualification only. No security audit was performed."}. After the tool confirms the commit, reply with a short acknowledgement. Use no host tools.' });
      if (second.code !== 0) { results.push({ agent, state: 'incomplete', reason: second.failureReason }); continue; }
      try {
        const submission = readCanonicalSubmission(reportDir, name, identity);
        const events = readReportJson(reportDir, `harness/bridge-${name}.json`);
        const reads = events.filter(event => event.tool === 'read_file').length;
        const remembered = submission.report.payload.at(-1).verified_safe.some(control => control.how_attacked.includes(marker));
        if (!remembered || reads !== 1 || !events.some(event => event.tool === 'get_audit_context') || first.sessionId !== second.sessionId) throw new Error('Live session evidence mismatch');
        results.push({ agent, state: 'qualified', requestedModel: models[agent], sessionId: second.sessionId, submissionHash: submission.hash, transport: second.transport, resume: 'verified', bridgeRead: 'verified' });
      } catch { results.push({ agent, state: 'incomplete', reason: 'qualification_evidence_mismatch' }); }
      writeReportFile(root, 'qualification.json', JSON.stringify({ scope: 'inert_transport_only', results }, null, 2));
    }
  } finally {
    if (owned) {
      const label = docker(['inspect', container, '--format', '{{index .Config.Labels "freightchain.audit.smoke"}}']).trim();
      if (label !== container) throw new Error('Qualification container ownership mismatch');
      docker(['rm', '--force', container]);
    }
    fs.rmSync(source, { recursive: true, force: true });
  }
  writeReportFile(root, 'qualification.json', JSON.stringify({ scope: 'inert_transport_only', results, cleanup: 'removed' }, null, 2));
  return results;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const options = { agents: Object.keys(MODELS), models: { ...MODELS } };
  for (let i = 2; i < process.argv.length; i += 2) {
    const flag = process.argv[i]; const value = process.argv[i + 1];
    if (!value) throw new Error('Missing qualification option');
    if (flag === '--out') options.out = value;
    else if (flag === '--agents') options.agents = value.split(',');
    else if (flag.startsWith('--model-') && Object.hasOwn(MODELS, flag.slice(8))) options.models[flag.slice(8)] = value;
    else throw new Error('Unknown qualification option');
  }
  options.out ||= path.resolve(fileURLToPath(new URL('../reports/', import.meta.url)), `${new Date().toISOString().replace(/[:.]/g, '-')}-session-qualification`);
  const controller = new AbortController();
  const cancel = () => controller.abort();
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
  try {
    const result = await qualifyAgentSessions({ ...options, signal: controller.signal });
    console.log(JSON.stringify({ output: options.out, results: result }, null, 2));
    if (result.some(row => row.state !== 'qualified')) process.exitCode = 2;
  } catch (err) { console.error(err.message); process.exitCode = 2; }
  finally { process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel); }
}
