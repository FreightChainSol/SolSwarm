import assert from 'node:assert/strict';
import test from 'node:test';
import { auditToolDecision } from './audit-tool-policy.mjs';

const call = (name, args = {}) => ({ toolCall: { name, args } });
test('AGY allows only its audit MCP server, staged skill reads and completion', () => {
  assert.equal(auditToolDecision(call('call_mcp_tool', { ServerName: 'audit-docker_audit_docker', ToolName: 'read_file' })).decision, 'allow');
  assert.equal(auditToolDecision(call('call_mcp_tool', { ServerName: 'other-server', ToolName: 'read_file' })).decision, 'deny');
  assert.equal(auditToolDecision(call('call_mcp_tool', { ServerName: 'audit_docker', ToolName: 'unknown' })).decision, 'deny');
  assert.equal(auditToolDecision(call('view_file', { IsSkillFile: true, AbsolutePath: '/tmp/own-skill.md' }), ['/tmp/own-skill.md']).decision, 'allow');
  assert.equal(auditToolDecision(call('view_file', { AbsolutePath: '/tmp/own-skill.md' }), ['/tmp/own-skill.md']).decision, 'allow');
  const schema = '/tmp/home/.gemini/antigravity-cli/mcp/audit-docker_audit_docker/read_file.json';
  assert.equal(auditToolDecision(call('view_file', { AbsolutePath: schema }), [schema]).decision, 'allow');
  const schemaRoot = '/tmp/home/.gemini/antigravity-cli/mcp';
  assert.equal(auditToolDecision(call('view_file', { AbsolutePath: schema }), [], schemaRoot).decision, 'allow');
  assert.equal(auditToolDecision(call('view_file', { AbsolutePath: schemaRoot + '/audit_docker/unknown.json' }), [], schemaRoot).decision, 'deny');
  assert.equal(auditToolDecision(call('view_file', { AbsolutePath: schemaRoot + '/audit_docker/../auth.json' }), [], schemaRoot).decision, 'deny');
  assert.equal(auditToolDecision(call('view_file', { AbsolutePath: '/tmp/home/.gemini/antigravity-cli/mcp/other_server/read_file.json' }), [schema]).decision, 'deny');
  assert.equal(auditToolDecision(call('view_file', { AbsolutePath: '/tmp/home/.gemini/antigravity-cli/auth.json' }), [schema]).decision, 'deny');
  assert.equal(auditToolDecision(call('view_file', { IsSkillFile: true, AbsolutePath: '/tmp/other-file' }), ['/tmp/own-skill.md']).decision, 'deny');
  assert.equal(auditToolDecision(call('finish')).decision, 'allow');
  for (const name of ['run_command', 'sed_file', 'browser_subagent', 'read_resource', 'run_workflow', 'send_command_input', 'notebook_execution', 'invoke_subagent', 'send_message', 'unknown']) assert.equal(auditToolDecision(call(name)).decision, 'deny', name);
  assert.equal(auditToolDecision(null).decision, 'deny');
});
