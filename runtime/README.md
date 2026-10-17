# SolSwarm ACP runtime

Run `./bin/audit setup-agents` (or `npm run setup`) from the repository root. This installs exact lockfile dependencies locally with lifecycle scripts disabled; it does not install global CLIs or change authentication.

- [`codex-acp` 2.2.2](https://github.com/zed-industries/codex-acp): maintained ACP adapter over the installed Codex app-server, selected through `CODEX_PATH`.
- [`claude-agent-acp` 0.92.0](https://github.com/zed-industries/claude-agent-acp): maintained ACP adapter using the installed official Claude CLI through `CLAUDE_CODE_EXECUTABLE`.
- [Grok native ACP](https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-pager/docs/user-guide/15-agent-mode.md): no adapter package. The private profile restricts tools; private configuration uses the existing login via the upstream `GROK_AUTH_PATH` mechanism without copying it.
- AGY: repository adapter around structured JSONL and saved conversations, with a generated default-deny tool hook.

The coordinator verifies adapter package versions against its pins. CLI versions/capabilities are recorded when available; a new upstream CLI may require renewed live qualification. Requested model/provider remain fixed. Package readiness is not proof of authentication, quota, MCP attachment or audit coverage; `check-agents --live` explicitly checks transport against an inert fixture.

Sessions and model output are private local artifacts. Preserve the original session directory when using `run --resume-from`; deleting it removes the local recovery state. A heartbeat cannot keep a provider session alive beyond the provider's own limits.

All four reviewer profiles share the `source_security_review_v1` MCP allowlist: source inspection, fixed catalogued existing tests in offline Docker and validated submissions. Policy refusals do not cause retries or model substitution; older adversarial sessions cannot resume into this workflow.
