use codex_core::StartThreadOptions;
use codex_core::config::Config;
use codex_extension_api::SessionIsolation;
use codex_extension_api::ToolPolicy;
use codex_features::Feature;

use crate::GateError;
pub const STARTUP_DISABLED: &[Feature] = &[
    Feature::CodexHooks,
    Feature::Plugins,
    Feature::RecommendedPlugins,
    Feature::RemotePlugin,
    Feature::MemoryTool,
    Feature::ExternalAgentMemoryImport,
    Feature::Chronicle,
    Feature::Worktrees,
    Feature::CodeModePrewarm,
    Feature::ShellSnapshot,
    Feature::ShellSnapshotV2,
    Feature::DaemonAutoStart,
    Feature::ExecutorCapabilityDiscovery,
    Feature::SkillMcpDependencyInstall,
    Feature::Collab,
    Feature::MultiAgentV2,
    Feature::UseAgentIdentity,
    Feature::Apps,
];

pub fn empty_tool_policy() -> ToolPolicy {
    ToolPolicy {
        allowed_tools: Some(Vec::new()),
        expose_additional_permissions: false,
        ..Default::default()
    }
}

/// Restrictive construction only. Native auth/config loading is a separate gate.
pub fn review_start_options(mut config: Config) -> Result<StartThreadOptions, GateError> {
    // Required managed startup actions are incompatible, not silently discarded.
    if !config.mcp_servers.get().is_empty() || config.notify.is_some() {
        return Err(GateError::StartupPolicy);
    }
    for &feature in STARTUP_DISABLED {
        config
            .features
            .disable(feature)
            .map_err(|_| GateError::StartupPolicy)?;
    }
    config.project_doc_max_bytes = 0;
    config.project_doc_fallback_filenames.clear();
    config.include_skill_instructions = false;
    config.include_apps_instructions = false;
    config.include_environment_context = false;
    config.cloud_skill_enabled = false;
    config.orchestrator_mcp_enabled = false;
    config.agents_enabled = false;
    config.agent_roles.clear();
    config.check_for_update_on_startup = false;
    config.analytics_enabled = Some(false);
    config.feedback_enabled = false;
    config.ephemeral = true;
    let mut options = StartThreadOptions::new(config);
    options.environments = Some(Vec::new());
    options.dynamic_tools.clear();
    options
        .thread_extension_init
        .insert(SessionIsolation::Isolated);
    options.thread_extension_init.insert(empty_tool_policy());
    Ok(options)
}

#[cfg(test)]
mod tests {
    use codex_extension_api::ToolName;

    use super::*;

    #[test]
    fn empty_ceiling_denies_every_tool_namespace_without_granting_permissions() {
        let policy = empty_tool_policy();
        assert_eq!(policy.allowed_tools.as_ref().unwrap().len(), 0);
        assert!(!policy.expose_additional_permissions);
        for namespace in ["functions", "mcp", "extension", "dynamic", "hosted"] {
            for name in [
                "exec_command",
                "update_plan",
                "web_search",
                "view_image",
                "exec",
                "wait",
            ] {
                assert!(!policy.allows(&ToolName::namespaced(namespace, name)));
            }
        }
    }
}
