import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

import { REVIEW_TOOLS as MCP_TOOLS } from './review-workflow.mjs';

export function auditToolDecision(input, readFiles = [], schemaRoot = path.join(os.homedir(), '.gemini/antigravity-cli/mcp')) {
  const name = input?.toolCall?.name;
  const args = input?.toolCall?.args;
  const server = args?.ServerName;
  const ownMcp = name === 'call_mcp_tool' && ['audit_docker', 'audit-docker_audit_docker'].includes(server) && MCP_TOOLS.has(args?.ToolName);
  // The path allowlist owns authority; IsSkillFile is an optional UI hint.
  const schemas = ['audit_docker', 'audit-docker_audit_docker'].flatMap(server => [...MCP_TOOLS].map(tool => path.join(schemaRoot, server, `${tool}.json`)));
  const allowedRead = name === 'view_file' && typeof args?.AbsolutePath === 'string' && path.isAbsolute(args.AbsolutePath) && [...readFiles, ...schemas].includes(path.normalize(args.AbsolutePath));
  if (ownMcp || allowedRead || name === 'finish') return { decision: 'allow' };
  return { decision: 'deny', reason: 'Only the audit Docker MCP server, its exact tool schemas and the staged audit skill are available. Other host tools and integrations are disabled.' };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let input;
  try {
    const text = fs.readFileSync(0, 'utf8');
    if (text.length <= 1024 * 1024) input = JSON.parse(text);
  } catch { /* malformed hook requests fail closed */ }
  process.stdout.write(JSON.stringify(auditToolDecision(input, process.argv.slice(2))));
}
