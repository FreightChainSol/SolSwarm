import { createClaudeAdapter, ConnectorError } from './model-cli-claude.mjs';
import { createCodexNativeAdapter } from './model-cli-codex-native.mjs';
import { createGrokNativeAdapter } from './model-cli-grok-native.mjs';
import { createGrokDockerAdapter } from './model-cli-grok-docker.mjs';

export const REVIEW_PROFILES = Object.freeze(['claude', 'codex-native', 'grok-native', 'grok-docker']);
export function createReviewAdapter(provider, model, checkOnly = false) {
  if (provider === 'claude') return createClaudeAdapter();
  if (provider === 'codex-native') return createCodexNativeAdapter({ model, checkOnly });
  if (provider === 'grok-native') return createGrokNativeAdapter({ model, checkOnly });
  if (provider === 'grok-docker') return createGrokDockerAdapter({ model, checkOnly });
  throw new ConnectorError('provider_tool_free_mode_unverified');
}
