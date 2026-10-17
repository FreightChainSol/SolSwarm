use std::path::Path;
use std::sync::Arc;

use codex_config::ConfigLoadOptions;
use codex_config::LoaderOverrides;
use codex_core::config::Config;
use codex_core::config::ConfigBuilder;
use codex_core::config::ConfigOverrides;
use codex_core::config::ThreadStoreConfig;
use codex_core::config::bootstrap_auth_config;
use codex_core::config::load_config_toml_with_layer_stack;
use codex_login::AuthConfig;
use codex_login::AuthManager;
use codex_protocol::auth::AuthMode;
use codex_protocol::config_types::ForcedLoginMethod;
use codex_state::SqliteConfig;
use codex_utils_absolute_path::AbsolutePathBuf;

use crate::GateError;
use crate::REVIEW_INSTRUCTION;
use crate::policy::STARTUP_DISABLED;

pub fn valid_model(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= 128
        && model.as_bytes()[0].is_ascii_alphanumeric()
        && model
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
}

fn runtime_loader(mut loader: LoaderOverrides) -> Result<LoaderOverrides, GateError> {
    if loader.ignore_managed_requirements || loader.ignore_login_requirements {
        return Err(GateError::Configuration);
    }
    loader.ignore_user_config = true;
    loader.ignore_project_config = true;
    loader.ignore_user_and_project_exec_policy_rules = true;
    Ok(loader)
}

/// The caller supplies operator-owned startup paths, never model-controlled paths.
pub async fn load_configuration(
    credential_home: &Path,
    runtime_home: &Path,
    model: &str,
) -> Result<(Config, AuthConfig), GateError> {
    load_with_loader(
        credential_home,
        runtime_home,
        model,
        LoaderOverrides::default(),
    )
    .await
}

async fn load_with_loader(
    credential_home: &Path,
    runtime_home: &Path,
    model: &str,
    loader: LoaderOverrides,
) -> Result<(Config, AuthConfig), GateError> {
    if !valid_model(model) || !credential_home.is_absolute() || !runtime_home.is_absolute() {
        return Err(GateError::Configuration);
    }
    let cwd =
        AbsolutePathBuf::from_absolute_path(runtime_home).map_err(|_| GateError::Configuration)?;
    // Native bootstrap interprets only authentication settings; this code never
    // opens an auth payload, extracts a token or constructs authorization headers.
    let mut bootstrap_loader = loader.clone();
    bootstrap_loader.ignore_project_config = true;
    bootstrap_loader.ignore_user_and_project_exec_policy_rules = true;
    let bootstrap = load_config_toml_with_layer_stack(
        credential_home,
        Some(&cwd),
        Vec::new(),
        ConfigLoadOptions::from(bootstrap_loader),
    )
    .await
    .map_err(|_| GateError::Configuration)?;
    let mut auth = bootstrap_auth_config(credential_home, &bootstrap)
        .map_err(|_| GateError::Authentication)?;
    if !auth.is_login_method_allowed(ForcedLoginMethod::Chatgpt) {
        return Err(GateError::Authentication);
    }
    auth.forced_login_method = Some(ForcedLoginMethod::Chatgpt);
    auth.validate().map_err(|_| GateError::Authentication)?;

    let overrides = STARTUP_DISABLED
        .iter()
        .map(|feature| {
            (
                format!("features.{}", feature.key()),
                toml::Value::Boolean(false),
            )
        })
        .collect();
    // Load managed requirements against their original owner/home. Relocate
    // runtime state only after the native loader has applied those constraints.
    let mut config = ConfigBuilder::default()
        .codex_home(credential_home.to_path_buf())
        .loader_overrides(runtime_loader(loader)?)
        .cli_overrides(overrides)
        .harness_overrides(ConfigOverrides {
            cwd: Some(runtime_home.to_path_buf()),
            model: Some(model.to_owned()),
            model_provider: Some("openai".to_owned()),
            developer_instructions: Some(REVIEW_INSTRUCTION.trim_end_matches('\n').to_owned()),
            ephemeral: Some(true),
            workspace_roots: Some(Vec::new()),
            ..Default::default()
        })
        .build()
        .await
        .map_err(|_| GateError::Configuration)?;
    if config.model_provider_id != "openai" || config.model.as_deref() != Some(model) {
        return Err(GateError::Configuration);
    }
    config.codex_home = cwd.clone();
    config.sqlite = SqliteConfig::from_sqlite_home(cwd);
    config.log_dir = runtime_home.join("log");
    config.experimental_thread_store = ThreadStoreConfig::InMemory {
        id: runtime_home.to_string_lossy().into_owned(),
    };
    config.forced_login_method = auth.forced_login_method;
    config.forced_chatgpt_workspace_id = auth.forced_chatgpt_workspace_id.clone();
    config.application_auth_route_config = Some(auth.auth_route_config.clone());
    if let Some(base) = &auth.chatgpt_base_url {
        config.chatgpt_base_url = base.clone();
    }
    Ok((config, auth))
}

pub fn accept_auth_kind(
    mode: AuthMode,
    external: bool,
    workload: bool,
    api_env_enabled: bool,
) -> Result<(), GateError> {
    if mode != AuthMode::Chatgpt || external || workload || api_env_enabled {
        return Err(GateError::Authentication);
    }
    Ok(())
}

pub async fn load_native_auth(config: AuthConfig) -> Result<Arc<AuthManager>, GateError> {
    let manager = AuthManager::shared_from_auth_config(config, false)
        .await
        .map_err(|_| GateError::Authentication)?;
    let auth = manager.auth_cached().ok_or(GateError::Authentication)?;
    accept_auth_kind(
        auth.api_auth_mode(),
        manager.has_external_auth(),
        manager.is_workload_identity_selected(),
        manager.codex_api_key_env_enabled(),
    )?;
    Ok(manager)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_login_and_workspace_restrictions_are_not_relaxed() -> anyhow::Result<()> {
        core_test_support::test_codex::run_test_with_large_stack(
            "native-managed-auth-gate",
            || async {
                let home = tempfile::TempDir::new()?;
                let runtime = tempfile::TempDir::new()?;
                let managed = tempfile::TempDir::new()?;
                let policy = managed.path().join("managed_config.toml");
                std::fs::write(&policy, "")?;
                std::fs::write(
                    managed.path().join("requirements.toml"),
                    "allowed_login_methods = [\"api\"]\n",
                )?;
                let loader = LoaderOverrides::with_managed_config_path_for_tests(policy.clone());
                let result =
                    load_with_loader(home.path(), runtime.path(), "fixture-model", loader).await;
                assert!(matches!(result, Err(GateError::Authentication)));
                std::fs::write(
                    managed.path().join("requirements.toml"),
                    "allowed_login_methods = [\"chatgpt\"]\nallowed_chatgpt_workspaces = [\"fixture-workspace\"]\n",
                )?;
                let loader = LoaderOverrides::with_managed_config_path_for_tests(policy);
                let (config, auth) =
                    load_with_loader(home.path(), runtime.path(), "fixture-model", loader)
                        .await
                        .map_err(|error| anyhow::anyhow!(error.code()))?;
                assert_eq!(
                    auth.effective_chatgpt_workspaces(),
                    Some(vec!["fixture-workspace".to_owned()])
                );
                assert_eq!(
                    config.auth_config().effective_chatgpt_workspaces(),
                    Some(vec!["fixture-workspace".to_owned()])
                );
                Ok(())
            },
        )
    }

    #[test]
    fn rejects_every_non_native_subscription_auth_kind() {
        assert!(accept_auth_kind(AuthMode::Chatgpt, false, false, false).is_ok());
        for mode in [
            AuthMode::ApiKey,
            AuthMode::ChatgptAuthTokens,
            AuthMode::Headers,
            AuthMode::AgentIdentity,
            AuthMode::PersonalAccessToken,
            AuthMode::BedrockApiKey,
            AuthMode::BedrockAccessKeys,
        ] {
            assert_eq!(
                accept_auth_kind(mode, false, false, false),
                Err(GateError::Authentication)
            );
        }
        for (external, workload, env) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            assert!(accept_auth_kind(AuthMode::Chatgpt, external, workload, env).is_err());
        }
    }

    #[test]
    fn loader_cannot_drop_managed_or_login_requirements() {
        let loader = runtime_loader(LoaderOverrides::default()).unwrap();
        assert!(loader.ignore_user_config && loader.ignore_project_config);
        assert!(!loader.ignore_managed_requirements && !loader.ignore_login_requirements);
        assert!(
            runtime_loader(LoaderOverrides {
                ignore_managed_requirements: true,
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn runtime_config_keeps_auth_owner_but_ignores_user_execution_context() -> anyhow::Result<()> {
        core_test_support::test_codex::run_test_with_large_stack("native-config-gate", || async {
            let home = tempfile::TempDir::new()?;
            let runtime = tempfile::TempDir::new()?;
            std::fs::write(
                home.path().join("config.toml"),
                "cli_auth_credentials_store = \"file\"\nmodel_provider = \"untrusted\"\n[features]\nhooks = true\nplugins = true\n",
            )?;
            let loader = LoaderOverrides::without_managed_config_for_tests();
            let (config, auth) =
                load_with_loader(home.path(), runtime.path(), "fixture-model", loader)
                    .await
                    .map_err(|error| anyhow::anyhow!(error.code()))?;
            assert_eq!(auth.codex_home, home.path());
            assert_eq!(config.codex_home.as_path(), runtime.path());
            assert_eq!(config.model_provider_id, "openai");
            assert!(config.mcp_servers.get().is_empty());
            for &feature in STARTUP_DISABLED {
                assert!(!config.features.enabled(feature));
            }
            assert_eq!(auth.forced_login_method, Some(ForcedLoginMethod::Chatgpt));
            Ok(())
        })
    }
}
