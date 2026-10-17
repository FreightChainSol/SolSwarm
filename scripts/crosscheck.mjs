#!/usr/bin/env node
/**
 * crosscheck.mjs prepare <report-dir> <agent,agent,...>
 *
 * Writes crosscheck/<agent>.json: the other models' claims (id, title, location, impact).
 * The argument and the other model's write-up are left out on purpose.
 * Prints the agents that have something to review, one per line.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadAuditors, adapterOf, writeReportFile } from './report-contract.mjs';

export const KNOWN_MODELS = ['claude', 'gpt', 'codex', 'grok', 'agy', 'gemini'];

export function modelOfName(name) {
  const parts = String(name).toLowerCase().replace(/\.json$/, '').split(/[^a-z0-9.]+/).filter(Boolean);
  return parts.find((p) => KNOWN_MODELS.includes(p)) || null;
}

export function loadAuditorFindings(auditorsDir) {
  const claims = [];
  const { reports } = loadAuditors(path.dirname(auditorsDir));
  for (const { name: stem, data } of reports) {
    const model = adapterOf(stem);
    const findings = data.filter((x) => x && x.title && !x.verified_safe);
    findings.forEach((x, i) => {
      claims.push({
        id: `${stem}#${i}`,
        auditor: stem,
        model,
        surface: String(x.surface || ''),
        severity: String(x.severity || ''),
        title: String(x.title),
        location: Array.isArray(x.location) ? x.location.slice(0, 8).map(String) : [],
        impact: String(x.impact || '').slice(0, 600),
      });
    });
  }
  return claims;
}

function prepare(reportDir, agents) {
  if (!agents.every((a) => ['claude', 'grok', 'agy', 'codex'].includes(a)) || new Set(agents).size !== agents.length) {
    throw new Error('crosscheck: expected distinct known adapter names');
  }
  const claims = loadAuditorFindings(path.join(reportDir, 'auditors'));
  const outDir = path.join(reportDir, 'crosscheck');
  fs.mkdirSync(outDir, { recursive: true });
  const launched = [];
  for (const agent of agents) {
    const mine = modelOfName(agent);
    const inbox = claims.filter((c) => c.model && c.model !== mine);
    const dest = path.join(outDir, `${agent}.json`);
    if (!inbox.length) {
      if (fs.existsSync(dest)) fs.unlinkSync(dest);
      continue;
    }
    writeReportFile(reportDir, `crosscheck/${agent}.json`, JSON.stringify(inbox, null, 2) + '\n');
    launched.push(agent);
  }
  return launched;
}

function main() {
  const [cmd, reportDir, agentCsv] = process.argv.slice(2);
  if (cmd !== 'prepare' || !reportDir) {
    console.error('usage: crosscheck.mjs prepare <report-dir> <agent,agent>');
    process.exit(1);
  }
  const agents = String(agentCsv || '').split(',').map((s) => s.trim()).filter(Boolean);
  const launched = prepare(reportDir, agents);
  if (launched.length) process.stdout.write(`${launched.join('\n')}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
