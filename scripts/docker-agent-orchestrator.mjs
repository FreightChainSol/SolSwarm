#!/usr/bin/env node
/**
 * docker-agent-orchestrator.mjs
 *
 * Host orchestrator that:
 * 1. Starts the one-shot Docker sandbox container (`sandbox.sh --hold-file ...`),
 *    running trusted static scanners inside Docker and then
 *    disconnecting network egress before holding the container open.
 * 2. Launches the local agentic CLIs (`claude`, `codex`, `grok`, `agy`) in isolated
 *    private persistent session directories on the host connected to `docker-mcp-bridge.mjs`.
 * 3. Runs the surface audit pass and peer cross-check pass inside the container.
 * 4. Saves validated source-review reports and schedules owned sandbox cleanup.
 */

import crypto from 'node:crypto';
import { stageTestArtifacts } from './test-artifacts.mjs';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { resolveExecutable } from './agent-launch.mjs';
export { resolveExecutable } from './agent-launch.mjs';
import { fileURLToPath } from 'node:url';
import { renderReviewPlansMarkdown, renderSurfaceSkillGuidance } from './audit-plans.mjs';
import { loadAuditorFindings } from './crosscheck.mjs';
import {
  callBridgeTool,
  normalizeCrosscheckPayload,
  renderMarkdownFromFindings,
  resolveDockerBin,
} from './docker-mcp-bridge.mjs';
import { readReportJson, readReportText, writeReportFile } from './report-contract.mjs';
import { createSnapshot, disposeSnapshot } from './worker-isolation.mjs';
import { classifyAuditFailure, FAILURE_MESSAGES } from './audit-process.mjs';
import { runReviewSession } from './agent-session.mjs';
import { digest } from './agent-session-store.mjs';
import { readCanonicalSubmission, deriveSubmission } from './audit-submission.mjs';
import { commitSubmission } from './audit-submission.mjs';
import { runtimeAdapter, sessionEnvironment } from './agent-session-launch.mjs';
import { REVIEW_WORKFLOW, REVIEW_SCOPE, buildExistingTestCatalog } from './review-workflow.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BRIDGE_SCRIPT = path.join(HERE, 'docker-mcp-bridge.mjs');
const SANDBOX_SCRIPT = path.join(HERE, 'sandbox.sh');

const SURFACES = [
  { id: 's1', code: 'S1', slug: 'auth', name: 'Identity, Scopes & Access Control', focus: 'authentication (HTTP/gRPC/WebSockets/SIWS), session/cookie flags, horizontal IDOR & scope misvalidation, vertical role/admin plane bypass, CSRF/CSWSH, login/register response DTO enumeration oracles, Solana signer/owner/authority checks' },
  { id: 's2', code: 'S2', slug: 'input', name: 'Input Handling, Protocols & Injection', focus: 'HTTP/gRPC/WebSocket input validation, protobuf zero-value traps & stream floods, SQL/NoSQL/Redis/command injection (incl. Python f-string SQL, shell=True, pickle/yaml), deserialization, SSRF, path traversal, batch/rate abuse, Solana instruction data & account cosplay' },
  { id: 's3', code: 'S3', slug: 'logic', name: 'Business Logic, Bot/Economy Integrity & Custody', focus: 'source inspection of server authority, replay uniqueness, economic state transitions, DB transaction boundaries and row locks, Solana/Anchor custody and Merkle proof invariants' },
  { id: 's4', code: 'S4', slug: 'config', name: 'Secrets, Config, Infra & Response DTO Leakage', focus: 'over-broad response DTOs leaking internal fields/seeds/hashes, error/status enumeration oracles, hard-coded secrets, key custody, Docker/CI/nginx/TLS hardening, gRPC reflection exposure' },
  { id: 's5', code: 'S5', slug: 'deps', name: 'Dependencies, Lockfiles & Supply Chain', focus: 'manifests and lockfiles (Cargo, npm, PyPI requirements/pyproject), unpinned or non-index Python requirements, vulnerable crates/packages, install/postinstall scripts, unpinned CI actions, vendored code, verifiable Solana builds' },
  { id: 's6', code: 'S6', slug: 'client', name: 'Client, Web Surface, Realtime & Wallet Flows', focus: 'DOM XSS sinks, postMessage/origin checks, CSP/SRI, CORS, WebSocket room/stream IDOR, Solana Actions/Blinks, wallet signing flows, client-side trust boundaries & exposed DTO fields' },
];

export function checkBridgeAgents(env = process.env) {
  const dockerBin = resolveDockerBin();
  const dockerInfo = spawnSync(dockerBin, ['info', '--format', '{{.ServerVersion}}'], { encoding: 'utf8', timeout: 8000 });
  const dockerReady = dockerInfo.status === 0;
  const agents = ['claude', 'codex', 'grok', 'agy'].map((agent) => {
    const exe = resolveExecutable(agent, env);
    if (!exe) return { agent, state: 'unavailable', executable: null, version: null, bridgeMode: 'docker_mcp_stdio' };
    const ver = spawnSync(exe, ['--version'], { encoding: 'utf8', timeout: 5000, env: sessionEnvironment(env) });
    const text = (ver.stdout || ver.stderr || '').trim().split('\n')[0] || '';
    let runtime = agent === 'grok' ? 'native_acp' : 'native_cli_acp_adapter';
    if (['claude', 'codex'].includes(agent)) {
      try { runtimeAdapter(agent); runtime = 'maintained_acp'; }
      catch { runtime = 'missing_or_invalid'; }
    }
    return {
      agent,
      state: ver.status === 0 && runtime !== 'missing_or_invalid' ? 'ready' : 'error',
      executable: exe,
      version: text,
      bridgeMode: 'docker_mcp_stdio',
      agentTransport: runtime,
    };
  });
  return {
    state: dockerReady && agents.every((a) => a.state === 'ready') ? 'ready' : 'degraded',
    scope: 'docker_cli_and_pinned_runtime_availability_only',
    note: 'Authentication, quotas, MCP attachment and inference were not tested. Use check-agents --live for inert qualification.',
    docker: { ready: dockerReady, binary: dockerBin, version: (dockerInfo.stdout || '').trim() || null },
    bridgeScript: BRIDGE_SCRIPT,
    agents,
  };
}

function previousSessionDirectory(root, name) {
  const pointer = `harness/session-${name}.json`;
  if (!fs.existsSync(path.join(root, pointer))) return path.join(root, 'sessions', name);
  const saved = readReportJson(root, pointer);
  if (typeof saved.directory !== 'string' || !path.isAbsolute(saved.directory)) throw new Error('Invalid saved session directory');
  return saved.directory;
}

// Repair only the historical classifier bug: a committed turn ended normally,
// but replayed prose was mistaken for a provider error. Actual RPC errors stay failed.
export function savedTurnCompleted(root, name, directory) {
  try {
    const state = readReportJson(directory, 'state.json');
    if (state.observedExitCode !== 0 || !['usage_limit', 'provider_policy', 'auth_required', 'mcp_unavailable'].includes(state.failureReason)) return false;
    const log = readReportText(root, `harness/sandbox-run/${name.startsWith('crosscheck-') ? name : `agent-${name}`}.log`, 8 * 1024 * 1024);
    let complete = false;
    for (const line of log.split('\n')) {
      let frame; try { frame = JSON.parse(line); } catch { continue; }
      if (frame?.jsonrpc !== '2.0' || frame.id == null) continue;
      if (frame.error) return false;
      if (frame.result?.stopReason) complete = frame.result.stopReason === 'end_turn';
    }
    return complete;
  } catch { return false; }
}

function readHarnessContext(reportDir, surfaceCode) {
  const hDir = path.join(reportDir, 'harness');
  const read = (name, max = 3500) => {
    try { return fs.readFileSync(path.join(hDir, name), 'utf8').slice(0, max); } catch { return ''; }
  };
  let stackProfile;
  try { stackProfile = JSON.parse(fs.readFileSync(path.join(hDir, 'stack-profile.json'), 'utf8')); } catch { /* guidance falls back to every stack */ }
  const blocks = [renderSurfaceSkillGuidance(surfaceCode, stackProfile)];
  const summary = read('summary.md', 4000);
  if (summary) blocks.push('### Harness & Sandbox Summary\n' + summary);
  try {
    const profilePath = path.join(hDir, 'stack-profile.json');
    if (fs.existsSync(profilePath)) {
      const profile = JSON.parse(fs.readFileSync(profilePath, 'utf8'));
      blocks.push('### Tailored Stack & Domain Source Review Plans\n' + renderReviewPlansMarkdown(profile, surfaceCode).slice(0, 7500));
    } else {
      const plans = read('review-plans.md', 7500);
      if (plans) blocks.push('### Tailored Stack & Domain Source Review Plans\n' + plans);
    }
  } catch { /* ignore */ }
  const solana = read('solana.md', 3000);
  if (solana && !solana.includes('Solana surface absent')) blocks.push('### Solana Leads\n' + solana);
  const python = read('python.md', 4000);
  if (python && !python.includes('Python surface absent') && ['S1', 'S2', 'S3', 'S4'].includes(surfaceCode)) blocks.push('### Python Leads\n' + python);
  const nodeLeads = read('node.md', 4000);
  if (nodeLeads && !nodeLeads.includes('Node surface absent') && ['S1', 'S2', 'S4', 'S6'].includes(surfaceCode)) blocks.push('### Node Leads\n' + nodeLeads);
  if (['S1', 'S2', 'S6'].includes(surfaceCode)) {
    const web = read('web.md', 2500);
    if (web && !web.includes('Web surface absent')) blocks.push('### Web Leads\n' + web);
  }
  if (surfaceCode === 'S4') {
    const cfg = read('config.md', 2500);
    if (cfg) blocks.push('### Config Leads\n' + cfg);
  }
  if (surfaceCode === 'S5') {
    const deps = read('deps.md', 2500);
    if (deps) blocks.push('### Dependency Leads\n' + deps);
  }
  return blocks.join('\n\n');
}

export function buildAuditorPrompt({ targetName, auditorName, surface, reportDir }) {
  return [
    `You are security auditor "${auditorName}" performing an authorized source security review of "${targetName}" inside a one-shot Docker container using the \`security-audit\` skill.`,
    `Assigned Surface: ${surface.code} — ${surface.name}`,
    `Focus Areas: ${surface.focus}`,
    'There is no runner time limit. Take the time needed to inspect this surface and submit a supported report. Runner heartbeats keep the session observable during long reasoning; they are not requests to rush or finish.',
    '',
    REVIEW_SCOPE,
    'CRITICAL RULES:',
    '1. All target files and build/test tools live inside the one-shot Docker container at `/work/src` (and harness leads/review plans at `/out/harness`).',
    '2. Use ONLY the `audit_docker` MCP tools (`get_audit_context`, `get_review_plan`, `list_files`, `read_file`, `search_code`, `list_existing_tests`, `run_existing_tests`, `submit_audit_report`) to inspect code, run checks inside the container, and submit your report.',
    '3. Follow the `security-audit` skill methodology: inspect source using the detected protocol plans (`http`, `grpc`, `websockets`, `databases`, `crypto`) and mandatory cross-cutting checks (`scopes_roles` IDOR/RBAC misvalidation, `bots_economy` headless bot/prize-pool resistance, and `api_dto_abuse` response DTO leakage & enumeration oracles such as `"user already registered"`).',
    '4. Every finding MUST cite exact relative `file:line` locations (e.g. `programs/escrow/src/lib.rs:42`) verified by `read_file` or `search_code`.',
    `5. Every finding's "surface" field MUST be "${surface.code}". Severity: critical|high|medium|low|info. Confidence: confirmed|probable.`,
    '6. When finished, call `submit_audit_report` with `findings`, `verified_safe`, and `markdown_summary`. If this surface is absent, submit an empty findings array and explain the absent surface in the markdown; a report is still required.',
    'For CLIs with nested-argument serialization problems (especially AGY), call submit_audit_report with only report_json: a JSON-encoded string of that complete object. Each finding requires title, surface, severity, confidence, location (array of file:line strings), impact, preconditions, analysis (source-based explanation), validation (source or existing-test evidence and limits), and fix. Each control requires control, evidence, and holds (boolean). Do not submit empty arrays to bypass serialization errors. Use the complete structured report, then finish with an acknowledgement.',
    '7. After successful MCP report submission, finish with a short acknowledgement. The committed MCP report is authoritative; the coordinator generates JSON, markdown and HTML from it.',
    '8. If the audit_docker tools are unavailable, stop and explain the MCP connection failure. Do not search the host for tools, recreate a container, or substitute host commands.',
    '',
    readHarnessContext(reportDir, surface.code),
  ].filter(Boolean).join('\n');
}

function buildCrosscheckPrompt({ targetName, agent, claims }) {
  return [
    `You are peer security reviewer "${agent}" performing a cross-check of findings reported by other models on "${targetName}" inside the one-shot Docker container using the \`security-audit\` skill.`,
    REVIEW_SCOPE,
    'There is no runner time limit. Take the time needed to review every assigned claim; disclose coverage gaps and never invent missing verdicts.',
    '1. Use `audit_docker` MCP tools (`get_review_plan`, `read_file`, `search_code`, `list_existing_tests`, `run_existing_tests`) to inspect the cited `file:line` locations under `/work/src`.',
    '2. Double-check scope/role guards, DB locks, bot/economy invariants, and API response DTOs (for example, if a claim states an API returns an enumeration oracle like "user already registered" or leaks fields, verify the exact DTO/error in source).',
    '3. For EVERY assigned claim ID below, decide a verdict: "upheld", "partial", or "refuted", with `reason` and relative `file:line` `evidence` citations.',
    '4. Call `submit_crosscheck_report` with `verdicts: [...]` covering every assigned claim ID, then finish with a short acknowledgement; the committed MCP report is authoritative.',
    'If nested object arrays fail to serialize, pass only report_json: a JSON-encoded string of the object containing verdicts. Never drop claims to work around argument errors.',
    '5. If the audit_docker tools are unavailable, stop and explain the connection failure. Do not use host commands or recreate containers.',
    '',
    'Assigned Claims:\n```json\n' + JSON.stringify(claims, null, 2) + '\n```',
  ].join('\n');
}

export async function startOneShotDocker({ target, out }) {
  const holdDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-hold-'));
  const holdFile = path.join(holdDir, 'hold.lock');
  const readyFile = path.join(holdDir, 'ready.json');
  fs.writeFileSync(holdFile, 'hold\n');
  const args = [SANDBOX_SCRIPT, '--review-only', '--target', target, '--out', out, '--hold-file', holdFile, '--ready-file', readyFile];
  const child = spawn('bash', args, { stdio: ['ignore', 'inherit', 'inherit'], env: process.env });
  let closed = false;
  let stopping = false;
  let exitCode = null;
  const closePromise = new Promise((resolve) => {
    child.on('close', (code) => { closed = true; exitCode = code ?? 1; resolve(exitCode); });
  });
  const deadline = Date.now() + Number(process.env.AUDIT_SANDBOX_BUDGET_MS || 45 * 60 * 1000);
  while (!closed && Date.now() < deadline) {
    if (fs.existsSync(readyFile)) {
      try {
        const info = JSON.parse(fs.readFileSync(readyFile, 'utf8'));
        if (info.container) {
          let reportLoss;
          const lost = new Promise(resolve => { reportLoss = resolve; });
          const lifecycleFile = path.join(info.hostRunDir, 'lifecycle.json');
          const monitor = setInterval(() => {
            try { if (JSON.parse(fs.readFileSync(lifecycleFile, 'utf8')).state === 'lost') reportLoss(new Error('Docker sandbox was lost; inspect harness/sandbox-run/lifecycle.json.')); }
            catch { /* the lifecycle writer may not have published its first probe */ }
          }, 1000);
          closePromise.then(() => { clearInterval(monitor); if (!stopping) reportLoss(new Error('One-shot Docker sandbox exited before review completion; inspect harness/sandbox-run/lifecycle.json.')); });
          return {
            container: info.container,
            hostRunDir: info.hostRunDir,
            lost,
            stop: async () => {
              stopping = true;
              clearInterval(monitor);
              try { fs.rmSync(holdFile, { force: true }); } catch {}
              await Promise.race([closePromise, new Promise((r) => setTimeout(r, 15_000))]);
              spawnSync(resolveDockerBin(), ['rm', '-f', info.container], { stdio: 'ignore' });
              try { fs.rmSync(holdDir, { recursive: true, force: true }); } catch {}
            },
          };
        }
      } catch { /* wait for write */ }
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  try { fs.rmSync(holdFile, { force: true }); } catch {}
  await closePromise;
  try { fs.rmSync(holdDir, { recursive: true, force: true }); } catch {}
  throw new Error(`One-shot Docker sandbox exited before becoming ready (exit ${exitCode})`);
}

async function runProviderQueues(agents, jobs, execute) {
  // Drain every provider before reporting an unexpected error or removing the sandbox.
  const results = await Promise.allSettled(agents.map(async agent => {
    for (const job of jobs.filter(job => job.adapter === agent)) await execute(job);
  }));
  const failure = results.find(result => result.status === 'rejected');
  if (failure) throw failure.reason;
}

export async function runOrchestratedAudit(request, { review = runReviewSession, startSandbox = startOneShotDocker } = {}) {
  if (request.rpc || request.resume) throw new Error('Source security review excludes deployed RPC comparisons and legacy adversarial-session finalization');
  if (request.restartFailed && !request.resumeFrom) throw new Error('--restart-failed requires --resume-from');
  const output = path.resolve(request.out);
  if (output === fs.realpathSync(request.target)) throw new Error('output cannot be the source root');
  if (fs.existsSync(output) && fs.readdirSync(output).length) throw new Error('output directory must be empty');
  fs.mkdirSync(path.join(output, 'auditors'), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(output, 'harness'), { recursive: true, mode: 0o700 });

  const snapshot = createSnapshot(request.target, { exclude: [output] });
  const sourceDigest = snapshot.manifest.digest;
  writeReportFile(output, 'source-manifest.json', `${JSON.stringify(snapshot.manifest, null, 2)}\n`);
  writeReportFile(output, 'harness/existing-tests.json', JSON.stringify(buildExistingTestCatalog(snapshot.snapshot, snapshot.manifest), null, 2));
  disposeSnapshot(snapshot);
  if (request.testArtifacts) stageTestArtifacts(request.testArtifacts, output, sourceDigest);

  const surfaceArg = String(request.surface || 'all').toLowerCase();
  const selectedSurfaces = surfaceArg === 'all' ? SURFACES : SURFACES.filter((s) => s.id === surfaceArg || s.slug === surfaceArg);
  if (!selectedSurfaces.length) throw new Error(`Unknown surface: ${request.surface}`);

  const jobs = selectedSurfaces.flatMap((s, idx) => {
    const agents = surfaceArg === 'all' ? [request.agents[idx % request.agents.length]] : request.agents;
    return agents.map((agent) => ({
      id: crypto.randomUUID(), name: `${agent}-${s.id}-${s.slug}`,
      adapter: agent, requestedModel: request.models[agent], surface: s, state: 'pending',
    }));
  });


  const stageFailures = [];
  const providerFailures = {};
  const workerExits = Object.fromEntries(jobs.map((j) => [j.name, null]));
  const crosscheckExits = {};
  const dockerBin = resolveDockerBin();
  const resumeRoot = request.resumeFrom ? fs.realpathSync(request.resumeFrom) : null;
  const neverStarted = new Set();
  if (resumeRoot) {
    const previous = readReportJson(resumeRoot, 'meta.json');
    if (readReportJson(resumeRoot, 'source-manifest.json').digest !== sourceDigest || previous.workflow !== REVIEW_WORKFLOW || previous.surface !== surfaceArg || JSON.stringify(previous.agents) !== JSON.stringify(request.agents) || request.agents.some(agent => previous.models?.[agent] !== request.models[agent])) throw new Error('Resume requires the same source digest, surfaces, reviewers and requested models');
    for (const job of jobs) {
      const priorDirectory = previousSessionDirectory(resumeRoot, job.name);
      if (!fs.existsSync(path.join(priorDirectory, 'state.json'))) {
        const priorJob = readReportJson(resumeRoot, 'workers.json').jobs?.find(row => row.name === job.name);
        if (priorJob?.state !== 'pending' && !(priorJob?.state === 'cancelled' && priorJob.turnCode == null && !priorJob.sessionId)) throw new Error('Missing saved state for a previously started reviewer');
        neverStarted.add(job.name);
        continue;
      }
      const saved = readReportJson(priorDirectory, 'state.json');
      if (saved.identity?.workflow !== REVIEW_WORKFLOW || saved.identity?.agent !== job.adapter || saved.identity?.model !== job.requestedModel || saved.identity?.sourceDigest !== sourceDigest || saved.identity?.assignmentDigest !== digest(job.surface)) throw new Error('Saved session does not match the resumed assignment');
    }
  }
  fs.mkdirSync(path.join(output, 'sessions'), { mode: 0o700 });
  fs.mkdirSync(path.join(output, 'harness', 'identities'), { mode: 0o700 });
  fs.mkdirSync(path.join(output, 'harness', 'assignments'), { mode: 0o700 });

  let session = null;
  let sandboxFailure = null;
  const cancellation = new AbortController();
  const cleanupSignal = () => { cancellation.abort(); };
  const initialMeta = { name: request.name || path.basename(request.target), mode: request.mode || 'local', source: request.source || request.target, surface: surfaceArg, agents: request.agents, models: request.models, auditors: jobs.map(job => job.name), workerExits, crosscheckExits, stageFailures, finalized: false, workflow: REVIEW_WORKFLOW, agentTransport: 'acp_v1', submissionAuthority: 'mcp_commit' };
  writeReportFile(output, 'meta.json', JSON.stringify(initialMeta, null, 2));
  const saveWorkers = () => writeReportFile(output, 'workers.json', JSON.stringify({ version: 1, policy: 'docker_mcp_bridge', sourceDigest, jobs }, null, 2));
  saveWorkers();
  const processOptions = (name) => ({
    signal: cancellation.signal,
    onProgress: status => {
      const idle = status.agentIdleMs == null ? 'none yet' : `${Math.floor(status.agentIdleMs / 1000)}s ago`;
      console.log(`     [${name}] heartbeat: ${status.phase}; running ${Math.floor(status.elapsedMs / 1000)}s; last agent activity ${idle}; no time limit.`);
      try { writeReportFile(output, `harness/heartbeat-${name}.json`, `${JSON.stringify({ state: 'running', at: new Date().toISOString(), ...status })}\n`); }
      catch { console.error(`     [${name}] heartbeat record could not be saved; review continues.`); }
    },
  });
  const execute = async ({ name, agent, role, surface, prompt, assignment, logFile }) => {
    if (sandboxFailure) throw sandboxFailure;
    const identity = { name, agent, role, workflow: REVIEW_WORKFLOW, model: request.models[agent], sourceDigest, assignmentDigest: digest(assignment), ...(surface ? { surface } : {}) };
    const identityFile = path.join(output, 'harness', 'identities', `${name}.json`);
    writeReportFile(output, `harness/identities/${name}.json`, JSON.stringify(identity));
    writeReportFile(output, `harness/assignments/${name}.json`, JSON.stringify(assignment));
    let directory = path.join(output, 'sessions', name);
    let resuming = false;
    let restartedFrom;
    if (resumeRoot) {
      const priorDirectory = previousSessionDirectory(resumeRoot, name);
      if (fs.existsSync(path.join(priorDirectory, 'state.json'))) {
        const saved = readReportJson(priorDirectory, 'state.json');
        const priorMeta = readReportJson(resumeRoot, 'meta.json');
        const priorExit = role === 'auditor' ? priorMeta.workerExits?.[name] : priorMeta.crosscheckExits?.[agent];
        if (request.restartFailed && priorExit !== 0) {
          const failure = role === 'auditor' ? readReportJson(resumeRoot, 'workers.json').jobs.find(job => job.name === name)?.failure?.reason : priorMeta.providerFailures?.[agent];
          const rel = `harness/sandbox-run/${role === 'auditor' ? 'agent-' : ''}${name}.log`;
          let log = ''; try { log = readReportText(resumeRoot, rel, 8 * 1024 * 1024); } catch { /* saved structured failures still apply */ }
          const classified = classifyAuditFailure({ code: 1, stdout: log }).reason;
          const blocked = [failure, saved.failureReason, priorMeta.providerFailures?.[agent], classified].find(reason => ['provider_policy', 'usage_limit', 'auth_required', 'provider_error'].includes(reason));
          if (blocked) { const error = new Error('A provider refusal, quota, login or unresolved provider error cannot be restarted in a new conversation'); error.reason = blocked; throw error; }
          restartedFrom = priorDirectory;
          if (role === 'auditor' && fs.existsSync(path.join(resumeRoot, 'submissions', `${name}.json`))) {
            const prior = readCanonicalSubmission(resumeRoot, name, identity);
            const file = `prior-${name}.json`, notes = JSON.stringify(prior.report.payload);
            writeReportFile(output, `harness/${file}`, notes);
            const directory = path.join(session.hostRunDir, 'harness');
            fs.mkdirSync(directory, { recursive: true }); fs.chmodSync(directory, 0o755);
            fs.writeFileSync(path.join(directory, file), notes, { mode: 0o644 }); fs.chmodSync(path.join(directory, file), 0o644);
            prompt += `\n\nThe failed session left untrusted candidate notes at /out/harness/${file}. They are leads only: validate them against the captured source during the full assigned review, add omissions and discard unsupported claims. Submit a new complete report; the old notes are not an accepted review.`;
          }
        } else if (saved.identity?.assignmentDigest === identity.assignmentDigest) { directory = priorDirectory; resuming = true; }
      }
      if (role === 'auditor' && !resuming && !restartedFrom && !neverStarted.has(name)) throw new Error(`No matching saved session for ${name}`);
      if (resuming && fs.existsSync(path.join(resumeRoot, 'submissions', `${name}.json`))) {
        const previous = readCanonicalSubmission(resumeRoot, name, identity);
        const priorMeta = readReportJson(resumeRoot, 'meta.json');
        const priorExit = role === 'auditor' ? priorMeta.workerExits?.[name] : priorMeta.crosscheckExits?.[agent];
        const recoveredCompletion = priorExit !== 0 && savedTurnCompleted(resumeRoot, name, directory);
        if (priorExit === 0 || recoveredCompletion) {
          commitSubmission(output, name, identity, previous.report.payload, previous.report.summary);
          writeReportFile(output, `harness/session-${name}.json`, JSON.stringify({ directory, identity }));
          const saved = readReportJson(directory, 'state.json');
          return { code: 0, observedExitCode: 0, elapsedMs: 0, sessionId: saved.sessionId, directory, transport: recoveredCompletion ? 'recovered_protocol_completion' : 'reused_committed_submission', stopReason: 'reused', identity, reusedFrom: resumeRoot, recoveredCompletion };
        }
        // Keep committed evidence while requiring a fresh successful turn. The
        // saved conversation is explicitly told not to submit it a second time.
        commitSubmission(output, name, identity, previous.report.payload, previous.report.summary);
      }
    }
    const bridgeArgs = ['--docker-bin', dockerBin, '--container', session.container, '--report-dir', output, '--role', role, '--agent', agent, '--identity-file', identityFile];
    if (role === 'auditor') bridgeArgs.push('--auditor', name, '--surface', surface);
    writeReportFile(output, `harness/session-${name}.json`, JSON.stringify({ directory, identity }));
    const result = await review({ directory, identity, bridgeArgs, prompt, logFile, resume: resuming, ...processOptions(name) });
    writeReportFile(output, `harness/heartbeat-${name}.json`, `${JSON.stringify({ state: 'exited', at: new Date().toISOString(), elapsedMs: result.elapsedMs, turnCode: result.code, observedExitCode: result.observedExitCode ?? null, sessionId: result.sessionId, timeLimitMs: null })}\n`);
    if (result.code !== 0) {
      const reason = Object.hasOwn(FAILURE_MESSAGES, result.failureReason) ? result.failureReason : 'process_error';
      result.failure = { reason, message: FAILURE_MESSAGES[reason] };
    }
    return { ...result, identity, ...(restartedFrom ? { restartedFrom } : {}) };
  };
  process.on('SIGINT', cleanupSignal);
  process.on('SIGTERM', cleanupSignal);

  try {
    console.log('[1/4] Starting one-shot Docker sandbox and source scanners...');
    const sealed = createSnapshot(request.target, { exclude: [output] });
    try {
      if (sealed.manifest.digest !== sourceDigest) throw new Error('Source changed before sandbox creation; start a new review');
      session = await startSandbox({ target: sealed.snapshot, out: output });
      session.lost?.then(error => {
        if (!error) return;
        sandboxFailure = error;
        stageFailures.push('sandbox_unavailable');
        cancellation.abort();
      });
    } finally { disposeSnapshot(sealed); }
    console.log(`      Container ${session.container} is ready and airgapped (network disconnected).`);

    const catalog = readReportJson(output, 'harness/existing-tests.json');
    for (const entry of catalog.tests) {
      if (cancellation.signal.aborted) break;
      console.log(`      Verifying existing suite: ${entry.description}`);
      await callBridgeTool({ dockerBin, container: session.container, reportDir: output, auditor: 'verification' }, 'run_existing_tests', { test_id: entry.id });
    }

    console.log(`[2/4] Running ${jobs.length} surface audit job(s) in parallel across [${request.agents.join(', ')}] via MCP bridge (one active job per provider)...`);
    await runProviderQueues(request.agents, jobs, async job => {
      if (cancellation.signal.aborted) { job.state = sandboxFailure ? 'pending' : 'cancelled'; workerExits[job.name] = sandboxFailure ? 1 : 130; job.failure = sandboxFailure ? { reason: 'sandbox_unavailable', message: FAILURE_MESSAGES.sandbox_unavailable } : undefined; stageFailures.push(`auditor_cancelled:${job.name}`); saveWorkers(); return; }
      if (providerFailures[job.adapter]) {
        job.state = 'pending';
        job.failure = { reason: providerFailures[job.adapter], message: FAILURE_MESSAGES[providerFailures[job.adapter]] };
        workerExits[job.name] = 1;
        stageFailures.push(`auditor_deferred:${job.name}`);
        saveWorkers();
        return;
      }
      const logFile = path.join(output, 'harness', 'sandbox-run', `agent-${job.name}.log`);
      try {
        job.state = 'running';
        saveWorkers();
        console.log(`  -> [${job.name}] (${job.adapter} @ ${job.requestedModel}) auditing ${job.surface.code} (${job.surface.name})...`);
        let prompt = buildAuditorPrompt({ targetName: request.name, auditorName: job.name, surface: job.surface, reportDir: output });
        const res = await execute({ name: job.name, agent: job.adapter, role: 'auditor', surface: job.surface.code, prompt, assignment: job.surface, logFile });
        if (sandboxFailure) res.failure = { reason: 'sandbox_unavailable', message: FAILURE_MESSAGES.sandbox_unavailable };
        job.sessionId = res.sessionId;
        job.sessionDirectory = res.directory;
        job.transport = res.transport;
        job.turnStopReason = res.stopReason;
        job.failure = res.failure;
        job.observedExitCode = res.observedExitCode ?? null;
        job.turnCode = res.code;
        job.elapsedMs = res.elapsedMs;
        job.logFile = path.relative(output, logFile);
        if (res.reusedFrom) job.reusedFrom = res.reusedFrom;
        if (res.restartedFrom) job.restartedFrom = res.restartedFrom;
        if (res.code !== 0) {
          job.failure = res.failure || classifyAuditFailure(res);
          throw new Error(job.failure.message);
        }
        let submission;
        try {
          submission = readCanonicalSubmission(output, job.name, res.identity);
          deriveSubmission(output, submission, renderMarkdownFromFindings);
        } catch (err) {
          job.failure = { reason: fs.existsSync(path.join(output, 'submissions', `${job.name}.json`)) ? 'invalid_report' : 'missing_report', message: FAILURE_MESSAGES[fs.existsSync(path.join(output, 'submissions', `${job.name}.json`)) ? 'invalid_report' : 'missing_report'] };
          throw err;
        }
        if (submission) {
          job.submissionHash = submission.hash;
          workerExits[job.name] = 0;
          job.state = 'collected';
          console.log(`  <- [${job.name}] completed and validated.`);
        } else {
          workerExits[job.name] = 1;
          job.state = 'failed';
          job.failure = classifyAuditFailure(res);
          stageFailures.push(`auditor_failed:${job.name}`);
          console.error(`  <- [${job.name}] ${job.failure.message} See ${job.logFile}.`);
        }
      } catch (err) {
        workerExits[job.name] = job.turnCode || 1;
        job.state = 'failed';
        job.failure ||= Object.hasOwn(FAILURE_MESSAGES, err.reason) ? { reason: err.reason, message: FAILURE_MESSAGES[err.reason] } : classifyAuditFailure({ code: 0 }, job.observedExitCode == null ? 'setup_error' : 'invalid_report');
        if (['usage_limit', 'auth_required', 'provider_policy'].includes(job.failure.reason)) providerFailures[job.adapter] = job.failure.reason;
        stageFailures.push(`auditor_error:${job.name}`);
        console.error(`  <- [${job.name}] ${job.failure.message} See ${path.relative(output, logFile)}.`);
      } finally { saveWorkers(); }
    });

    const baseMeta = {
      name: request.name || path.basename(request.target), mode: request.mode || 'local',
      source: request.source || request.target, ref: request.ref || null, commit: request.commit || null,
      date: new Date().toISOString(), surface: surfaceArg, agents: request.agents, models: request.models,
      auditors: jobs.map((j) => j.name), workerExits, crosscheckExits, stageFailures, finalized: true,
    };
    writeReportFile(output, 'meta.json', `${JSON.stringify(baseMeta, null, 2)}\n`);

    const allClaims = loadAuditorFindings(path.join(output, 'auditors'));
    fs.mkdirSync(path.join(output, 'crosscheck'), { recursive: true });
    const containerCrosscheckDir = path.join(session.hostRunDir, 'crosscheck');
    fs.mkdirSync(containerCrosscheckDir, { recursive: true });

    console.log('[3/4] Running peer cross-checks in parallel via MCP bridge...');
    await runProviderQueues(request.agents, request.agents.map(adapter => ({ adapter })), async ({ adapter: agent }) => {
      if (cancellation.signal.aborted) return;
      if (providerFailures[agent]) {
        crosscheckExits[agent] = 1;
        stageFailures.push(`crosscheck_deferred:${agent}`);
        return;
      }
      const peerClaims = allClaims.filter((c) => c.model && c.model !== agent);
      if (!peerClaims.length) return;
      const claimsJson = `${JSON.stringify(peerClaims, null, 2)}\n`;
      writeReportFile(output, `crosscheck/${agent}.json`, claimsJson);
      fs.writeFileSync(path.join(containerCrosscheckDir, `${agent}.json`), claimsJson);

      const logFile = path.join(output, 'harness', 'sandbox-run', `crosscheck-${agent}.log`);
      try {
        console.log(`  -> [crosscheck-${agent}] reviewing ${peerClaims.length} peer claim(s)...`);
        const prompt = buildCrosscheckPrompt({ targetName: request.name, agent, claims: peerClaims });
        const res = await execute({ name: `crosscheck-${agent}`, agent, role: 'crosscheck', prompt, assignment: peerClaims, logFile });
        crosscheckExits[agent] = res.code || 1;
        if (res.code !== 0) throw new Error(res.failure.message);
        const submission = readCanonicalSubmission(output, `crosscheck-${agent}`, res.identity);
        normalizeCrosscheckPayload(submission.report.payload, peerClaims);
        deriveSubmission(output, submission, renderMarkdownFromFindings);
        if (submission) {
          crosscheckExits[agent] = 0;
          console.log(`  <- [crosscheck-${agent}] completed and validated.`);
        } else {
          crosscheckExits[agent] = res.code || 1;
          stageFailures.push(`crosscheck_failed:${agent}`);
          console.error(`  <- [crosscheck-${agent}] failed (exit ${res.code}).`);
        }
      } catch (err) {
        crosscheckExits[agent] ||= 1;
        stageFailures.push(`crosscheck_error:${agent}`);
        console.error(`  <- [crosscheck-${agent}] error: ${err.message}`);
      }
    });
  } catch (err) {
    stageFailures.push(`sandbox_or_orchestrator:${err.message}`);
    console.error(`Orchestrator error: ${err.message}`);
  } finally {
    process.removeListener('SIGINT', cleanupSignal);
    process.removeListener('SIGTERM', cleanupSignal);
    if (session) {
      console.log('[4/4] Stopping and removing one-shot Docker container and volumes...');
      await session.stop();
    }
  }

  writeReportFile(output, 'workers.json', `${JSON.stringify({ version: 1, runId: crypto.randomUUID(), policy: 'docker_mcp_bridge', sourceDigest, jobs }, null, 2)}\n`);
  const finalMeta = {
    name: request.name || path.basename(request.target), mode: request.mode || 'local',
    source: request.source || request.target, ref: request.ref || null, commit: request.commit || null,
    date: new Date().toISOString(), surface: surfaceArg, agents: request.agents, models: request.models,
    auditors: jobs.map((j) => j.name), workerExits, crosscheckExits, stageFailures, finalized: true,
    providerFailures,
    ...(resumeRoot ? { resumedFrom: resumeRoot } : {}),
    workflow: REVIEW_WORKFLOW, agentTransport: 'acp_v1', submissionAuthority: 'mcp_commit',
    isolation: { policy: 'docker_mcp_bridge', sourceDigest, liveTransport: 'docker_mcp_stdio', privateOutputs: 'validated', workerManifest: 'workers.json' },
  };
  writeReportFile(output, 'meta.json', `${JSON.stringify(finalMeta, null, 2)}\n`);
  return { stageFailures, output, cancelled: cancellation.signal.aborted && !sandboxFailure };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [arg1] = process.argv.slice(2);
  if (arg1 === '--check') {
    const status = checkBridgeAgents();
    console.log(JSON.stringify(status, null, 2));
    process.exit(status.state === 'ready' ? 0 : 2);
  }
  if (!arg1 || !fs.existsSync(arg1)) {
    console.error('usage: docker-agent-orchestrator.mjs <request.json> | --check');
    process.exit(2);
  }
  const request = JSON.parse(fs.readFileSync(arg1, 'utf8'));
  runOrchestratedAudit(request).then(
    ({ stageFailures, cancelled }) => { if (cancelled) process.exitCode = 130; else if (stageFailures.length) process.exitCode = 2; },
    (err) => { console.error(err.message || err); process.exitCode = 2; },
  );
}
