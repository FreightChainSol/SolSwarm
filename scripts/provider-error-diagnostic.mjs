// Diagnostic enums only. Never return provider messages, headers, IDs or bodies.
export const DIAGNOSTIC_CATEGORIES=Object.freeze([
  'invalid_parameter','parameter_hint','ambiguous_parameter_hint','unclassified',
  'malformed_json','oversized_body','body_timeout','body_unavailable',
]);
export const DIAGNOSTIC_PARAMETERS=Object.freeze([
  'tool_choice','tools','model','max_tokens','max_completion_tokens',
  'messages','stream_options','response_format','client_version',
  'x-grok-conv-id','x-grok-req-id','x-grok-session-id','x-grok-agent-id',
  'conversation_id','conv_id','request_id','req_id','session_id','agent_id',
]);
export function providerDiagnostic(value){
  if(!value||typeof value!=='object'||Array.isArray(value)
    ||Object.keys(value).length!==2||!Object.hasOwn(value,'category')||!Object.hasOwn(value,'parameter'))return undefined;
  if(!DIAGNOSTIC_CATEGORIES.includes(value.category)
    ||value.parameter!==null&&!DIAGNOSTIC_PARAMETERS.includes(value.parameter))return undefined;
  if(['invalid_parameter','parameter_hint'].includes(value.category)!==(value.parameter!==null))return undefined;
  return {category:value.category,parameter:value.parameter};
}
