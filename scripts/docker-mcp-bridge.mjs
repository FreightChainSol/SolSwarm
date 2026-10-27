#!/usr/bin/env node
import crypto from 'node:crypto';
import { testCounts, missingTestArtifact } from './scanner-evidence.mjs';
/**
 * docker-mcp-bridge.mjs
 *
 * Model Context Protocol (MCP) stdio bridge between host agentic CLIs
 * (claude, codex, grok, agy) and the one-shot Docker audit container.
 *
 * All repository browsing, code search, command execution, PoC execution,
 * and report artifacts happen inside the isolated one-shot Docker container
 * (`docker exec --user 10001:10001`), never on the host filesystem.
 */

import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderReviewPlansMarkdown, renderSurfaceSkillGuidance } from './audit-plans.mjs';
import { citation, validCrosscheckRow, validateAuditor, readReportJson, writeReportFile } from './report-contract.mjs';
import { commitSubmission, deriveSubmission, validateSubmissionIdentity } from './audit-submission.mjs';
import { REVIEW_WORKFLOW, REVIEW_SCOPE, REVIEW_TOOLS, selectExistingTest, EXISTING_TEST_RUNNER } from './review-workflow.mjs';
import { withExistingTestLock } from './existing-test-lock.mjs';
import { selectTestArtifacts } from './test-artifacts.mjs';

const CONTAINER_ROOTS = ['/work/src', '/out/harness', '/out/crosscheck', '/out/auditors'];
const SAFE_ANNOTATIONS = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };

export function resolveDockerBin(explicit) {
  if (explicit && fs.existsSync(explicit)) return explicit;
  for (const c of ['/usr/local/bin/docker', '/opt/homebrew/bin/docker', '/usr/bin/docker']) {
    if (fs.existsSync(c)) return c;
  }
  const r = spawnSync('which', ['docker'], { encoding: 'utf8' });
  return r.status === 0 && r.stdout.trim() ? r.stdout.trim() : 'docker';
}

export function parseBridgeArgs(argv) {
  const opts = {
    dockerBin: '',
    container: process.env.AUDIT_CONTAINER || '',
    reportDir: process.env.AUDIT_REPORT_DIR || '',
    role: process.env.AUDIT_ROLE || 'auditor',
    auditor: process.env.SECURITY_AUDITOR || '',
    agent: process.env.AUDIT_AGENT || '',
    surface: (process.env.AUDIT_SURFACE || 'S1').toUpperCase(),
    finalizeOnly: false,
    identityFile: '',
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--docker-bin') opts.dockerBin = argv[++i] || '';
    else if (a === '--container') opts.container = argv[++i] || '';
    else if (a === '--report-dir') opts.reportDir = argv[++i] || '';
    else if (a === '--role') opts.role = argv[++i] || 'auditor';
    else if (a === '--auditor') opts.auditor = argv[++i] || '';
    else if (a === '--agent') opts.agent = argv[++i] || '';
    else if (a === '--surface') opts.surface = (argv[++i] || 'S1').toUpperCase();
    else if (a === '--finalize-only') opts.finalizeOnly = true;
    else if (a === '--identity-file') opts.identityFile = argv[++i] || '';
  }
  opts.dockerBin = resolveDockerBin(opts.dockerBin);
  if (opts.identityFile) {
    const rel = path.relative(opts.reportDir, opts.identityFile);
    opts.submissionIdentity = readReportJson(opts.reportDir, rel);
    const name = opts.role === 'crosscheck' ? `crosscheck-${opts.agent}` : opts.auditor;
    validateSubmissionIdentity(opts.submissionIdentity, name);
    if (opts.submissionIdentity.agent !== opts.agent || opts.submissionIdentity.role !== opts.role) throw new Error('Bridge submission identity mismatch');
  }
  return opts;
}

export function normalizeCitation(raw) {
  if (typeof raw !== 'string') throw new Error('Expected a file:line citation');
  let s = raw.trim().replace(/^\/work\/src\//, '').replace(/^\.\//, '');
  const m = s.match(/^([^:\n]+):([1-9]\d*)(?:-\d+)?$/);
  if (m) s = `${m[1]}:${m[2]}`;
  if (!citation(s)) throw new Error('Expected a relative file:line citation');
  return s;
}

export function renderMarkdownFromFindings(auditor, surface, findings, verifiedSafe, summaryText) {
  if (typeof summaryText === 'string' && summaryText.trim().length > 20) return `${summaryText.trim()}\n`;
  const lines = [`# Security Audit Report — ${auditor} (${surface})`, '', `## Findings (${findings.length})`, ''];
  if (!findings.length) {
    lines.push('No supported findings were reported for the reviewed scope.', '');
  } else {
    for (const [i, f] of findings.entries()) {
      lines.push(`### ${i + 1}. [${String(f.severity).toUpperCase()}] ${f.title}`);
      lines.push(`- **Surface**: ${f.surface}`, `- **Confidence**: ${f.confidence}`, `- **Locations**: ${(f.location || []).join(', ')}`, `- **Impact**: ${f.impact}`);
      if (f.analysis) lines.push(`- **Source analysis**: ${f.analysis}`);
      if (f.validation) lines.push(`- **Validation and limits**: ${f.validation}`);
      if (f.preconditions) lines.push(`- **Preconditions**: ${f.preconditions}`);
      if (Array.isArray(f.attack) && f.attack.length) {
        lines.push('- **Attack Path**:', ...f.attack.map((step) => `  1. ${step}`));
      }
      if (f.poc) lines.push('', '```', f.poc, '```', '');
      lines.push(`- **Fix**: ${f.fix}`, '');
    }
  }
  lines.push(`## Reviewed Control Assertions (${verifiedSafe.length})`, '');
  if (!verifiedSafe.length) lines.push('- No additional safe controls recorded.');
  else for (const c of verifiedSafe) lines.push(`- **${c.control}** (${c.holds ? 'holds' : 'broke'}): ${c.how_attacked}`);
  lines.push('');
  return lines.join('\n');
}

export function normalizeFindingsPayload(input, auditor, surfaceCode) {
  const surface = String(surfaceCode || 'S1').toUpperCase();
  const rawFindings = Array.isArray(input) ? input.slice(0, -1) : input?.findings;
  const verifiedSafe = Array.isArray(input) ? input.at(-1)?.verified_safe : input?.verified_safe;
  if (!Array.isArray(rawFindings) || !Array.isArray(verifiedSafe)) throw new Error('Expected findings and explicit verified_safe controls');
  const findings = rawFindings.map((f) => {
    if (!f || typeof f !== 'object' || Array.isArray(f) || !Array.isArray(f.location)) throw new Error('Invalid finding object');
    if (typeof f.surface !== 'string' || f.surface.toUpperCase() !== surface) throw new Error('Finding surface mismatch');
    return { ...f, surface, severity: f.severity?.toLowerCase(), confidence: f.confidence?.toLowerCase(), location: f.location.map(normalizeCitation) };
  });
  const payload = [...findings, Array.isArray(input) ? input.at(-1) : { verified_safe: verifiedSafe }];
  validateAuditor(payload, auditor);
  return { payload, findings, verifiedSafe };
}

export function normalizeCrosscheckPayload(rawVerdicts, assignedClaims) {
  const list = Array.isArray(rawVerdicts)
    ? rawVerdicts
    : rawVerdicts?.verdicts;
  if (!Array.isArray(list) || list.length !== assignedClaims.length) throw new Error('Cross-check must cover every assigned claim');
  const assigned = new Set(assignedClaims.map((claim) => claim.id));
  const byId = new Map();
  for (const row of list) {
    if (!row || !assigned.has(row.id) || byId.has(row.id) || !Array.isArray(row.evidence)) throw new Error('Unexpected, duplicate or invalid cross-check claim');
    const entry = { ...row, verdict: row.verdict?.toLowerCase(), evidence: row.evidence.map(normalizeCitation) };
    if (row.severity != null) entry.severity = row.severity.toLowerCase();
    if (!validCrosscheckRow(entry)) throw new Error(`Invalid cross-check row for ${row.id}`);
    byId.set(row.id, entry);
  }
  return assignedClaims.map((claim) => byId.get(claim.id));
}

function resolveContainerPath(inputPath, defaultRoot = '/work/src') {
  const raw = String(inputPath || '').trim();
  if (!raw || raw === '.') return defaultRoot;
  const resolved = raw.startsWith('/') ? path.posix.normalize(raw) : path.posix.normalize(path.posix.join(defaultRoot, raw));
  if (!CONTAINER_ROOTS.some((root) => resolved === root || resolved.startsWith(`${root}/`))) {
    throw new Error(`Path outside allowed container directories: ${raw}`);
  }
  return resolved;
}

// With keepTail, an oversized stream keeps its first quarter and last three
// quarters: test runners print their summary last, so a head-only cap loses the counts.
export function boundedCapture(maxBytes, keepTail = false) {
  const headMax = keepTail ? Math.floor(maxBytes / 4) : maxBytes, tailMax = maxBytes - headMax;
  let head = Buffer.alloc(0), tail = Buffer.alloc(0), omitted = 0;
  return {
    push(chunk) {
      if (head.length < headMax) {
        const take = Math.min(headMax - head.length, chunk.length);
        head = Buffer.concat([head, chunk.subarray(0, take)]);
        chunk = chunk.subarray(take);
      }
      if (!chunk.length) return;
      if (!tailMax) { omitted += chunk.length; return; }
      tail = Buffer.concat([tail, chunk]);
      if (tail.length > tailMax) { omitted += tail.length - tailMax; tail = tail.subarray(tail.length - tailMax); }
    },
    get omitted() { return omitted; },
    text() { return head.toString('utf8') + (omitted && tailMax ? `\n[... ${omitted} bytes omitted ...]\n` : '') + tail.toString('utf8'); },
  };
}

const TEST_OUTPUT_BYTES = 2 * 1024 * 1024;
const TEST_RESPONSE_CHARS = 48 * 1024;

function clipForModel(text) {
  if (!text || text.length <= TEST_RESPONSE_CHARS) return text || '(empty)';
  const head = Math.floor(TEST_RESPONSE_CHARS / 4);
  return `${text.slice(0, head)}\n[... ${text.length - TEST_RESPONSE_CHARS} characters omitted; full output is retained as evidence ...]\n${text.slice(text.length - (TEST_RESPONSE_CHARS - head))}`;
}

function existingTestResponse(id, code, failureDetail, output, provenance) {
  return `Existing test ${id}; exit code: ${code}${provenance ? ` (${provenance})` : ''}${failureDetail ? `\n${failureDetail}` : ''}\nSTDOUT:\n${clipForModel(output.stdout)}\nSTDERR:\n${clipForModel(output.stderr)}`;
}

// Only a hash-matched coordinator run for the same suite and source is reused.
function recordedVerificationRun(reportDir, testId, sourceDigest) {
  try {
    const row = readReportJson(reportDir, 'harness/existing-test-results-verification.json').findLast(item => item?.testId === testId && item.sourceDigest === sourceDigest);
    if (!row || !Number.isSafeInteger(row.exitCode) || !/^harness\/existing-test-output-verification-\d+\.json$/.test(row.evidenceFile)) return null;
    const evidence = readReportJson(reportDir, row.evidenceFile, 40 * 1024 * 1024);
    if (crypto.createHash('sha256').update(JSON.stringify(evidence)).digest('hex') !== row.evidenceHash || typeof evidence.stdout !== 'string' || typeof evidence.stderr !== 'string') return null;
    return { row, evidence };
  } catch { return null; }
}

export function execInContainer(dockerBin, container, args, { cwd = '/work/src', timeoutMs = 30_000, input = '', maxBytes = 64 * 1024, keepTail = false } = {}) {
  return new Promise((resolve) => {
    const dockerArgs = [
      'exec', '-i', '--user', '10001:10001', '-w', cwd,
      '-e', 'HOME=/home/sandbox', '-e', 'CARGO_HOME=/work/cargo', '-e', 'CARGO_TARGET_DIR=/work/target',
      '-e', 'PATH=/work/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin',
      container, ...args,
    ];
    const child = spawn(dockerBin, dockerArgs, { stdio: ['pipe', 'pipe', 'pipe'] });
    const stdout = boundedCapture(maxBytes, keepTail);
    const stderr = boundedCapture(maxBytes, keepTail);
    const done = (code, stderrText = stderr.text()) => resolve({ code, stdout: stdout.text(), stderr: stderrText, omittedBytes: stdout.omitted + stderr.omitted });
    const timer = setTimeout(() => { child.kill('SIGKILL'); }, Math.min(Math.max(1000, timeoutMs), 910_000));
    child.stdout.on('data', (c) => stdout.push(c));
    child.stderr.on('data', (c) => stderr.push(c));
    child.on('error', (err) => { clearTimeout(timer); done(127, err.message); });
    child.on('close', (code, sig) => { clearTimeout(timer); done(sig === 'SIGKILL' ? 124 : (code ?? 1)); });
    child.stdin.on('error', () => {});
    child.stdin.end(input);
  });
}

export function toolDefinitions(role = 'auditor') {
  const objSchema = (properties, required = []) => ({
    type: 'object', properties, ...(required.length ? { required } : {}), additionalProperties: false,
  });
  const strProp = (description) => ({ type: 'string', ...(description ? { description } : {}) });
  const intProp = (description) => ({ type: 'integer', ...(description ? { description } : {}) });
  const boolProp = (description) => ({ type: 'boolean', ...(description ? { description } : {}) });
  const strArr = (description) => ({ type: 'array', items: { type: 'string' }, ...(description ? { description } : {}) });

  const tools = [
    {
      name: 'get_audit_context',
      description: 'Read the audit scope, detected stacks (http, grpc, websockets, databases, crypto), skill guidance, harness lead summary, and (for crosscheck) assigned peer claims from the one-shot Docker container.',
      annotations: SAFE_ANNOTATIONS,
      inputSchema: objSchema({}),
    },
    {
      name: 'get_review_plan',
      description: 'Read the source security review plan and codebase entry-point leads for a protocol or risk domain (http, grpc, websockets, databases, crypto, scopes_roles, bots_economy, api_dto_abuse, or all).',
      annotations: SAFE_ANNOTATIONS,
      inputSchema: objSchema({
        domain: strProp('Domain filter: http | grpc | websockets | databases | crypto | scopes_roles | bots_economy | api_dto_abuse | all (default: surface-relevant plans)'),
      }),
    },
    {
      name: 'list_files',
      description: 'List files inside the one-shot Docker container (/work/src, /out/harness, /out/crosscheck).',
      annotations: SAFE_ANNOTATIONS,
      inputSchema: objSchema({ path: strProp('Directory path (default: /work/src)'), max_depth: intProp('Max recursion depth (1..6, default 3)') }),
    },
    {
      name: 'read_file',
      description: 'Read a file with 1-based line numbers inside the one-shot Docker container (/work/src or /out/harness). Relative paths resolve under /work/src.',
      annotations: SAFE_ANNOTATIONS,
      inputSchema: objSchema({
        path: strProp('Relative path under /work/src or absolute path under /out/harness'),
        start_line: intProp('1-based start line (default 1)'),
        end_line: intProp('1-based inclusive end line (default start_line + 200)'),
      }, ['path']),
    },
    {
      name: 'search_code',
      description: 'Search source files inside the one-shot Docker container (/work/src or /out/harness) by regex or literal string. Returns relative file:line citations.',
      annotations: SAFE_ANNOTATIONS,
      inputSchema: objSchema({
        pattern: strProp('Regex or literal pattern to search for'),
        path: strProp('Directory or file inside container (default: /work/src)'),
        case_insensitive: boolProp('Case-insensitive search (default: false)'),
        max_results: intProp('Max matches (default 80, max 200)'),
      }, ['pattern']),
    },
    {
      name: 'list_existing_tests',
      description: 'List fixed test IDs discovered in the captured source before review. No commands or test code can be supplied.',
      annotations: SAFE_ANNOTATIONS,
      inputSchema: objSchema({}),
    },
    {
      name: 'run_existing_tests',
      description: 'Run one catalogued existing test suite inside the verified network-disconnected Docker container. Dependencies must already be available; failures remain coverage gaps.',
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
      inputSchema: objSchema({ test_id: strProp('An ID returned by list_existing_tests; no additional arguments are accepted') }, ['test_id']),
    },
  ];

  if (role === 'crosscheck') {
    tools.push({
      name: 'submit_crosscheck_report',
      description: 'Validate and save the cross-check verdicts for all assigned peer claims. Call this tool before finishing.',
      annotations: SAFE_ANNOTATIONS,
      inputSchema: objSchema({
        report_json: strProp('JSON-encoded object containing verdicts. Use this instead of nested arguments when the CLI cannot serialize object arrays.'),
        verdicts: {
          type: 'array',
          items: objSchema({
            id: strProp(),
            verdict: { type: 'string', enum: ['upheld', 'partial', 'refuted'] },
            severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
            reason: strProp(),
            evidence: strArr(),
          }, ['id', 'verdict', 'reason', 'evidence']),
        },
      }, []),
    });
  } else {
    tools.push({
      name: 'submit_audit_report',
      description: 'Validate and save the final audit report (.json and .md) for your assigned surface. Call this tool before finishing.',
      annotations: SAFE_ANNOTATIONS,
      inputSchema: objSchema({
        report_json: strProp('JSON-encoded object containing findings, verified_safe and markdown_summary. Use this instead of nested arguments when the CLI cannot serialize object arrays.'),
        findings: {
          type: 'array',
          items: objSchema({
            title: strProp(), surface: strProp(),
            severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
            confidence: { type: 'string', enum: ['confirmed', 'probable'] },
            location: strArr(), impact: strProp(), preconditions: strProp(),
            analysis: strProp('Source-based explanation of the missing or incorrect control; no exploit instructions'), validation: strProp('Source inspection or existing test evidence, including limitations'), fix: strProp(),
          }, ['title', 'surface', 'severity', 'confidence', 'location', 'impact', 'preconditions', 'analysis', 'validation', 'fix']),
        },
        verified_safe: {
          type: 'array',
          items: objSchema({ control: strProp(), evidence: strProp('Source inspection or existing test evidence'), holds: boolProp() }, ['control', 'evidence', 'holds']),
        },
        markdown_summary: strProp(),
      }, []),
    });
  }
  for (const tool of tools) {
    if (tool.name === 'submit_audit_report') tool.inputSchema.oneOf = [{ required: ['report_json'] }, { required: ['findings', 'verified_safe'] }];
    if (tool.name === 'submit_crosscheck_report') tool.inputSchema.oneOf = [{ required: ['report_json'] }, { required: ['verdicts'] }];
  }
  return tools;
}

export async function callBridgeTool(ctx, name, args = {}) {
  const { dockerBin, container, reportDir, role, auditor, agent, surface } = ctx;
  if (!REVIEW_TOOLS.has(name)) throw new Error('Tool unavailable in source security review: ' + name);

  if (ctx.submissionIdentity) {
    const file = `harness/bridge-${ctx.submissionIdentity.name}.json`;
    let events = [];
    try { events = readReportJson(reportDir, file); } catch { /* first tool call */ }
    writeReportFile(reportDir, file, JSON.stringify([...events, { tool: name, at: new Date().toISOString() }].slice(-200)));
  }
  if (['submit_audit_report', 'submit_crosscheck_report'].includes(name) && Object.hasOwn(args, 'report_json')) {
    if (Object.keys(args).length !== 1 || typeof args.report_json !== 'string' || Buffer.byteLength(args.report_json) > 2 * 1024 * 1024) throw new Error('Supply only report_json, containing the complete JSON report (maximum 2 MiB).');
    args = JSON.parse(args.report_json);
    if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('report_json must encode a report object');
  }

  const readProfile = () => {
    try { return reportDir ? JSON.parse(fs.readFileSync(path.join(reportDir, 'harness', 'stack-profile.json'), 'utf8')) : undefined; } catch { return undefined; }
  };
  if (name === 'get_audit_context') {
    const parts = [
      '# Docker Security Review Context', REVIEW_SCOPE, `- Container: ${container}`, `- Role: ${role}`, `- Agent: ${agent || 'unknown'}`,
      `- Auditor ID: ${auditor || 'n/a'}`, `- Assigned Surface: ${surface}`, `- Target Source Root (in container): /work/src`,
      `- Harness Leads Root (in container): /out/harness`, '',
      renderSurfaceSkillGuidance(surface, readProfile()), '',
    ];
    if (reportDir && fs.existsSync(path.join(reportDir, 'harness', 'summary.md'))) {
      parts.push('## Harness Summary', fs.readFileSync(path.join(reportDir, 'harness', 'summary.md'), 'utf8'));
    }
    if (reportDir && fs.existsSync(path.join(reportDir, 'harness', 'stack-profile.json'))) {
      try {
        const profile = JSON.parse(fs.readFileSync(path.join(reportDir, 'harness', 'stack-profile.json'), 'utf8'));
        parts.push('## Surface Source Security Review Plans', renderReviewPlansMarkdown(profile, surface).slice(0, 12_000));
      } catch { /* ignore malformed profile */ }
    } else if (reportDir && fs.existsSync(path.join(reportDir, 'harness', 'review-plans.md'))) {
      parts.push('## Source Security Review Plans', fs.readFileSync(path.join(reportDir, 'harness', 'review-plans.md'), 'utf8').slice(0, 12_000));
    }
    for (const [file, title, absent, limit] of [['solana.md', 'Solana Leads', 'Solana surface absent', 6000], ['python.md', 'Python Leads', 'Python surface absent', 6000], ['node.md', 'Node Leads', 'Node surface absent', 6000]]) {
      if (!reportDir || !fs.existsSync(path.join(reportDir, 'harness', file))) continue;
      const text = fs.readFileSync(path.join(reportDir, 'harness', file), 'utf8');
      if (!text.includes(absent)) parts.push(`## ${title}`, text.slice(0, limit));
    }
    if (role === 'crosscheck' && reportDir) {
      const inboxFile = path.join(reportDir, 'crosscheck', `${agent}.json`);
      if (fs.existsSync(inboxFile)) parts.push('## Assigned Peer Claims to Cross-Check', fs.readFileSync(inboxFile, 'utf8'));
    }
    return parts.join('\n');
  }

  if (name === 'get_review_plan') {
    const reqDomain = String(args.domain || '').trim().toLowerCase();
    if (reportDir && fs.existsSync(path.join(reportDir, 'harness', 'stack-profile.json'))) {
      const profile = JSON.parse(fs.readFileSync(path.join(reportDir, 'harness', 'stack-profile.json'), 'utf8'));
      if (reqDomain && reqDomain !== 'all') {
        const match = (profile.domains || []).find((d) => d.id === reqDomain);
        if (match) {
          return renderReviewPlansMarkdown({ ...profile, domains: [match] }, '');
        }
      }
      return renderReviewPlansMarkdown(profile, reqDomain === 'all' ? '' : surface);
    }
    if (reportDir && fs.existsSync(path.join(reportDir, 'harness', 'review-plans.md'))) {
      return fs.readFileSync(path.join(reportDir, 'harness', 'review-plans.md'), 'utf8');
    }
    return renderSurfaceSkillGuidance(surface, readProfile());
  }

  if (name === 'list_files') {
    const targetPath = resolveContainerPath(args.path || '/work/src');
    const maxDepth = Math.min(Math.max(Number(args.max_depth) || 3, 1), 6);
    const script = `
      const fs = require('node:fs'), path = require('node:path');
      const root = process.argv[1], maxDepth = Number(process.argv[2]);
      const skip = new Set(['node_modules', '.git', 'target', 'dist', '.cargo', 'coverage']);
      const out = [];
      (function walk(dir, depth) {
        if (depth > maxDepth || out.length >= 400) return;
        let ents = []; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
        for (const e of ents.sort((a, b) => a.name.localeCompare(b.name))) {
          if (e.isSymbolicLink()) continue;
          const full = path.join(dir, e.name), rel = path.relative(root, full) || e.name;
          if (e.isDirectory()) { if (!skip.has(e.name)) { out.push(rel + '/'); walk(full, depth + 1); } }
          else if (e.isFile()) { let sz = 0; try { sz = fs.statSync(full).size; } catch {} out.push(rel + ' (' + sz + 'B)'); }
          if (out.length >= 400) break;
        }
      })(root, 1);
      process.stdout.write(out.join('\\n') || '(empty)');
    `;
    const res = await execInContainer(dockerBin, container, ['node', '-e', script, targetPath, String(maxDepth)]);
    if (res.code !== 0) throw new Error(res.stderr || `list_files exited with ${res.code}`);
    return `Files under ${targetPath}:\n${res.stdout}`;
  }

  if (name === 'read_file') {
    const targetPath = resolveContainerPath(args.path);
    const startLine = Math.max(1, Number(args.start_line) || 1);
    const endLine = Math.min(startLine + 399, Math.max(startLine, Number(args.end_line) || (startLine + 200)));
    const script = `
      const fs = require('node:fs');
      const file = process.argv[1], s = Number(process.argv[2]), e = Number(process.argv[3]);
      if (!fs.lstatSync(file).isFile()) throw new Error('Not a regular file: ' + file);
      const lines = fs.readFileSync(file, 'utf8').split('\\n');
      const rel = file.startsWith('/work/src/') ? file.slice('/work/src/'.length) : file;
      const slice = lines.slice(s - 1, e).map((l, idx) => (s + idx) + ': ' + l);
      process.stdout.write('File: ' + rel + ' (lines ' + s + '..' + Math.min(e, lines.length) + ' of ' + lines.length + ')\\n' + slice.join('\\n'));
    `;
    const res = await execInContainer(dockerBin, container, ['node', '-e', script, targetPath, String(startLine), String(endLine)]);
    if (res.code !== 0) throw new Error(res.stderr || `read_file failed for ${targetPath}`);
    return res.stdout;
  }

  if (name === 'search_code') {
    const targetPath = resolveContainerPath(args.path || '/work/src');
    const pattern = String(args.pattern || '');
    if (!pattern) throw new Error('pattern is required');
    const maxResults = Math.min(Math.max(Number(args.max_results) || 80, 1), 200);
    const flags = args.case_insensitive ? 'i' : '';
    const script = `
      const fs = require('node:fs'), path = require('node:path');
      const [root, pat, flags, limStr] = process.argv.slice(1);
      const limit = Number(limStr);
      let re; try { re = new RegExp(pat, flags); } catch { re = new RegExp(pat.replace(/[.*+?^\${}()|[\\]\\\\]/g, '\\\\$&'), flags); }
      const skip = new Set(['node_modules', '.git', 'target', 'dist', '.cargo', 'coverage']);
      const hits = [];
      function scanFile(file) {
        if (hits.length >= limit) return;
        let st; try { st = fs.lstatSync(file); } catch { return; }
        if (!st.isFile() || st.size > 1048576) return;
        let text; try { text = fs.readFileSync(file, 'utf8'); } catch { return; }
        if (text.includes('\\0')) return;
        const rel = file.startsWith('/work/src/') ? file.slice('/work/src/'.length) : file;
        const lines = text.split('\\n');
        for (let i = 0; i < lines.length && hits.length < limit; i++) {
          if (re.test(lines[i])) hits.push(rel + ':' + (i + 1) + ': ' + lines[i].trim().slice(0, 220));
        }
      }
      (function walk(p) {
        if (hits.length >= limit) return;
        let st; try { st = fs.lstatSync(p); } catch { return; }
        if (st.isFile()) return scanFile(p);
        if (!st.isDirectory()) return;
        let ents = []; try { ents = fs.readdirSync(p, { withFileTypes: true }); } catch { return; }
        for (const e of ents) if (!e.isSymbolicLink() && !skip.has(e.name)) walk(path.join(p, e.name));
      })(root);
      process.stdout.write(hits.length ? hits.join('\\n') : 'No matches found.');
    `;
    const res = await execInContainer(dockerBin, container, ['node', '-e', script, targetPath, pattern, flags, String(maxResults)]);
    if (res.code !== 0) throw new Error(res.stderr || 'search_code failed');
    return res.stdout;
  }

  if (name === 'list_existing_tests' || name === 'run_existing_tests') {
    if (Object.keys(args).some(key => name === 'list_existing_tests' || key !== 'test_id')) throw new Error('Existing test tools accept only a catalogued test_id');
    const catalog = readReportJson(reportDir, 'harness/existing-tests.json');
    const sourceDigest = ctx.submissionIdentity?.sourceDigest;
    // Validate every catalog row before advertising it; commands are reconstructed.
    const entries = catalog.tests?.map(entry => selectExistingTest(catalog, entry.id, sourceDigest));
    if (!entries || catalog.workflow !== REVIEW_WORKFLOW) throw new Error('Existing test catalog unavailable');
    if (name === 'list_existing_tests') return JSON.stringify({ scope: 'existing_offline_tests_only', tests: entries.map(({ id, kind, cwd, description }) => ({ id, kind, cwd, description })) });
    const entry = selectExistingTest(catalog, args.test_id, sourceDigest);
    if (fs.existsSync(path.join(reportDir, 'harness/test-artifacts.json'))) entry.artifacts = selectTestArtifacts(readReportJson(reportDir, 'harness/test-artifacts.json'), catalog.sourceDigest);
    const key = ctx.submissionIdentity?.name || auditor || agent;
    // The coordinator runs every catalogued suite before reviewers start. Reviewers get
    // that recorded run instead of a rerun of the same source: a long suite outlives
    // some CLIs' MCP call deadlines and holds the shared test lock against other reviewers.
    if (key !== 'verification') {
      const recorded = recordedVerificationRun(reportDir, entry.id, catalog.sourceDigest);
      if (recorded) return existingTestResponse(entry.id, recorded.row.exitCode, recorded.row.failureDetail, recorded.evidence, `recorded by the coordinator at ${recorded.row.at} before review; not re-executed`);
    }
    return withExistingTestLock(reportDir, async () => {
      const inspected = spawnSync(dockerBin, ['inspect', '--format', '{"running":{{json .State.Running}},"mode":{{json .HostConfig.NetworkMode}},"networks":{{json .NetworkSettings.Networks}}}', container], { encoding: 'utf8', timeout: 8000, maxBuffer: 64 * 1024 });
      let network;
      try { network = JSON.parse(inspected.stdout); } catch { throw new Error('Cannot verify offline test containment'); }
      if (inspected.status !== 0 || network.running !== true || typeof network.mode !== 'string' || network.mode === 'host' || network.mode.startsWith('container:') || !network.networks || Object.keys(network.networks).some(key => key !== 'none')) throw new Error('Tests require a network-disconnected container');
      const result = await execInContainer(dockerBin, container, ['node', '-e', EXISTING_TEST_RUNNER], { input: JSON.stringify(entry), timeoutMs: entry.timeoutMs + 10_000, maxBytes: TEST_OUTPUT_BYTES, keepTail: true });
      const failureDetail = result.code !== 0 ? missingTestArtifact(result.stderr) : null;
      if (key) {
        const file = `harness/existing-test-results-${key}.json`;
        let prior = []; try { prior = readReportJson(reportDir, file); } catch { /* first test */ }
        const counts = testCounts(result.stdout);
        const sequence = Math.max(-1, ...prior.map(row => Number(row.evidenceFile?.match(/-(\d+)\.json$/)?.[1] ?? -1))) + 1;
        if (!Number.isSafeInteger(sequence)) throw new Error('Invalid existing test evidence sequence');
        const evidenceFile = `harness/existing-test-output-${key}-${sequence}.json`;
        const evidence = JSON.stringify({ stdout: result.stdout, stderr: result.stderr, ...(result.omittedBytes ? { omittedBytes: result.omittedBytes } : {}) });
        writeReportFile(reportDir, evidenceFile, evidence);
        writeReportFile(reportDir, file, JSON.stringify([...prior, { testId: entry.id, sourceDigest: catalog.sourceDigest, kind: entry.kind, cwd: entry.cwd, exitCode: result.code, counts, ...(failureDetail ? { failureDetail } : {}), evidenceFile, evidenceHash: crypto.createHash('sha256').update(evidence).digest('hex'), at: new Date().toISOString(), scope: 'existing_offline_test_only' }].slice(-200)));
      }
      return existingTestResponse(entry.id, result.code, failureDetail, result);
    });
  }

  if (name === 'submit_audit_report') {
    if (role !== 'auditor') throw new Error('Audit submission is unavailable in this bridge role');
    if (!auditor) throw new Error('Bridge was not configured with an --auditor identity');
    const reviewMode = ctx.submissionIdentity?.workflow === REVIEW_WORKFLOW;
    if (reviewMode) {
      if (!Array.isArray(args.findings) || !Array.isArray(args.verified_safe)) throw new Error('Expected security review findings and control evidence');
      args = { ...args, findings: args.findings.map(finding => {
        if (typeof finding.analysis !== 'string' || !finding.analysis.trim() || typeof finding.validation !== 'string' || !finding.validation.trim() || finding.attack?.length || finding.poc) throw new Error('Security review requires source analysis and validation, not exploit steps or PoCs');
        return { ...finding, attack: [], poc: '' };
      }), verified_safe: args.verified_safe.map(control => {
        if (typeof control.evidence !== 'string' || !control.evidence.trim()) throw new Error('Security review control requires evidence');
        return { ...control, how_attacked: control.evidence };
      }) };
    }
    const { payload, findings, verifiedSafe } = normalizeFindingsPayload(args, auditor, surface);
    const md = renderMarkdownFromFindings(auditor, surface, findings, verifiedSafe, args.markdown_summary);
    const jsonText = `${JSON.stringify(payload, null, 2)}\n`;
    if (ctx.submissionIdentity) {
      const submission = commitSubmission(reportDir, auditor, ctx.submissionIdentity, payload, args.markdown_summary || '');
      deriveSubmission(reportDir, submission, renderMarkdownFromFindings);
      return `Report committed for ${auditor}: ${findings.length} findings, ${verifiedSafe.length} control assertions. Submission hash: ${submission.hash}. Finish with a short acknowledgement; the coordinator generates the report files.`;
    }
    if (reportDir) {
      fs.mkdirSync(path.join(reportDir, 'auditors'), { recursive: true });
      writeReportFile(reportDir, `auditors/${auditor}.json`, jsonText);
      writeReportFile(reportDir, `auditors/${auditor}.md`, md);
    }
    if (container) {
      await execInContainer(dockerBin, container, ['node', '-e', `
        const fs = require('node:fs');
        fs.mkdirSync('/out/auditors', { recursive: true });
        fs.writeFileSync('/out/auditors/' + process.argv[1] + '.json', process.argv[2]);
        fs.writeFileSync('/out/auditors/' + process.argv[1] + '.md', process.argv[3]);
      `, auditor, jsonText, md]);
    }
    return `Audit report validated and saved for ${auditor} (${findings.length} findings, ${verifiedSafe.length} verified_safe controls). You may now conclude your response.`;
  }

  if (name === 'submit_crosscheck_report') {
    if (role !== 'crosscheck') throw new Error('Peer submission is unavailable in this bridge role');
    if (!agent) throw new Error('Bridge was not configured with an --agent identity');
    let assignedClaims = [];
    if (reportDir) {
      const inbox = path.join(reportDir, 'crosscheck', `${agent}.json`);
      if (fs.existsSync(inbox)) assignedClaims = JSON.parse(fs.readFileSync(inbox, 'utf8'));
    }
    const normalized = normalizeCrosscheckPayload(args.verdicts || args, assignedClaims);
    const jsonText = `${JSON.stringify(normalized, null, 2)}\n`;
    if (ctx.submissionIdentity) {
      const submission = commitSubmission(reportDir, `crosscheck-${agent}`, ctx.submissionIdentity, normalized);
      deriveSubmission(reportDir, submission, renderMarkdownFromFindings);
      return `Peer report committed for ${agent}: ${normalized.length} verdicts. Submission hash: ${submission.hash}. Finish with a short acknowledgement.`;
    }
    if (reportDir) {
      fs.mkdirSync(path.join(reportDir, 'auditors'), { recursive: true });
      writeReportFile(reportDir, `auditors/crosscheck-${agent}.json`, jsonText);
    }
    if (container) {
      await execInContainer(dockerBin, container, ['node', '-e', `
        const fs = require('node:fs');
        fs.mkdirSync('/out/auditors', { recursive: true });
        fs.writeFileSync('/out/auditors/crosscheck-' + process.argv[1] + '.json', process.argv[2]);
      `, agent, jsonText]);
    }
    return `Cross-check report validated and saved for ${agent} (${normalized.length} verdicts). You may now conclude your response.`;
  }

  throw new Error(`Unknown tool: ${name}`);
}

export async function handleRpcMessage(ctx, msg) {
  if (!msg || typeof msg !== 'object') return null;
  const { id, method, params } = msg;
  if (id === undefined || id === null) return null;

  try {
    if (method === 'initialize') {
      const clientVer = typeof params?.protocolVersion === 'string' ? params.protocolVersion : '2024-11-05';
      return {
        jsonrpc: '2.0', id,
        result: {
          protocolVersion: clientVer,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'audit-docker-bridge', version: '1.0.0' },
        },
      };
    }
    if (method === 'ping') return { jsonrpc: '2.0', id, result: {} };
    if (method === 'resources/list') return { jsonrpc: '2.0', id, result: { resources: [] } };
    if (method === 'resources/templates/list') return { jsonrpc: '2.0', id, result: { resourceTemplates: [] } };
    if (method === 'prompts/list') return { jsonrpc: '2.0', id, result: { prompts: [] } };
    if (method === 'tools/list') return { jsonrpc: '2.0', id, result: { tools: toolDefinitions(ctx.role) } };
    if (method === 'tools/call') {
      try {
        if (ctx.finalizeOnly && !['submit_audit_report', 'submit_crosscheck_report'].includes(params?.name)) {
          throw new Error('Report finalization only: inspection is disabled. Submit supported findings and disclose coverage gaps.');
        }
        const text = await callBridgeTool(ctx, params?.name, params?.arguments || {});
        return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: String(text) }], isError: false } };
      } catch (toolErr) {
        const hint = ['submit_audit_report', 'submit_crosscheck_report'].includes(params?.name) ? ' If the CLI corrupts nested object arrays, send only report_json: a JSON-encoded string containing the complete report object with all required fields.' : '';
        return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: `Tool error: ${toolErr.message || String(toolErr)}${hint}` }], isError: true } };
      }
    }
    return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
  } catch (err) {
    return { jsonrpc: '2.0', id, error: { code: -32603, message: err.message || 'Internal error' } };
  }
}

function startStdioServer(ctx) {
  let buffer = Buffer.alloc(0);
  let useContentLength = false;
  const send = (obj) => {
    if (!obj) return;
    const payload = JSON.stringify(obj);
    if (useContentLength) process.stdout.write(`Content-Length: ${Buffer.byteLength(payload, 'utf8')}\r\n\r\n${payload}`);
    else process.stdout.write(`${payload}\n`);
  };

  const processBuffer = async () => {
    while (buffer.length > 0) {
      const headerMatch = buffer.toString('utf8', 0, Math.min(buffer.length, 64)).match(/^Content-Length:\s*(\d+)\r?\n/i);
      if (headerMatch) {
        useContentLength = true;
        const sepIdx = buffer.indexOf('\r\n\r\n');
        const altSepIdx = buffer.indexOf('\n\n');
        const headerEnd = sepIdx !== -1 ? sepIdx + 4 : (altSepIdx !== -1 ? altSepIdx + 2 : -1);
        if (headerEnd === -1) break;
        const len = Number(headerMatch[1]);
        if (buffer.length < headerEnd + len) break;
        const body = buffer.subarray(headerEnd, headerEnd + len).toString('utf8');
        buffer = buffer.subarray(headerEnd + len);
        try { send(await handleRpcMessage(ctx, JSON.parse(body))); } catch {}
        continue;
      }
      const nlIdx = buffer.indexOf(0x0a);
      if (nlIdx === -1) break;
      const line = buffer.subarray(0, nlIdx).toString('utf8').trim();
      buffer = buffer.subarray(nlIdx + 1);
      if (!line) continue;
      try { send(await handleRpcMessage(ctx, JSON.parse(line))); } catch {}
    }
  };

  let chain = Promise.resolve();
  process.stdin.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    chain = chain.then(processBuffer).catch(() => {});
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  startStdioServer(parseBridgeArgs(process.argv.slice(2)));
}
