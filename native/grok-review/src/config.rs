use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::sync::Arc;
use std::time::Duration;

use xai_grok_login::credential_provider::WireValidBearerResolver;
use xai_grok_login::{AuthManager, GrokComConfig, PreferredAuthMethod, XAI_OAUTH2_ISSUER};
use xai_grok_sampler::{ApiBackend, OriginClientInfo, SamplerConfig};

use crate::GateError;
use crate::runtime::{valid_model, validate_sampler_config};

pub fn auth_config(value: &toml::Value) -> Result<GrokComConfig, GateError> {
    if value.get("version_overrides").is_some() || value.get("campaigns").is_some() {
        return Err(GateError::Configuration);
    }
    if value.get("auth").is_some() && value.get("grok_com_config").is_some() {
        return Err(GateError::Configuration);
    }
    for name in [
        "hooks",
        "mcp_servers",
        "plugins",
        "auth_providers",
        "endpoints",
    ] {
        if value
            .get(name)
            .is_some_and(|value| !value.as_table().is_some_and(|table| table.is_empty()))
        {
            return Err(GateError::Configuration);
        }
    }
    for section in ["auth", "grok_com_config"] {
        if let Some(table) = value.get(section) {
            let table = table.as_table().ok_or(GateError::Configuration)?;
            if table.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "preferred_method" | "disable_api_key_auth" | "force_login_team_uuid"
                )
            }) {
                return Err(GateError::Configuration);
            }
        }
    }
    let config =
        GrokComConfig::from_text_review_snapshot(value).map_err(|_| GateError::Configuration)?;
    let default = GrokComConfig::default();
    let oauth = config.oauth2.as_ref().ok_or(GateError::Authentication)?;
    if config.oidc.is_some()
        || config.auth_provider_command.is_some()
        || config.preferred_method == Some(PreferredAuthMethod::ApiKey)
        || oauth.issuer != XAI_OAUTH2_ISSUER
        || Some(oauth.client_id.as_str())
            != default
                .oauth2
                .as_ref()
                .map(|oauth| oauth.client_id.as_str())
    {
        return Err(GateError::Authentication);
    }
    Ok(config)
}

pub fn read_config(path: &std::path::Path) -> Result<toml::Value, GateError> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(toml::Value::Table(Default::default()));
        }
        Err(_) => return Err(GateError::Configuration),
    };
    let metadata = file.metadata().map_err(|_| GateError::Configuration)?;
    // SAFETY: geteuid has no preconditions or external side effects.
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() > 1024 * 1024
        || metadata.mode() & 0o022 != 0
        || (metadata.uid() != 0 && metadata.uid() != unsafe { libc::geteuid() })
    {
        return Err(GateError::Configuration);
    }
    let mut text = String::new();
    file.take(1024 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|_| GateError::Configuration)?;
    if text.len() > 1024 * 1024 {
        return Err(GateError::Configuration);
    }
    toml::from_str(&text).map_err(|_| GateError::Configuration)
}

pub fn required_snapshot(value: &toml::Value) -> Result<(), GateError> {
    let table = value.as_table().ok_or(GateError::Configuration)?;
    if table
        .keys()
        .any(|key| !matches!(key.as_str(), "auth" | "grok_com_config"))
    {
        return Err(GateError::Configuration);
    }
    auth_config(value)?;
    Ok(())
}

/// No create-on-resolve, env expansion, campaigns or repeated policy-file reads.
pub fn load_auth() -> Result<Arc<AuthManager>, GateError> {
    let home = xai_dirs::resolve_grok_home().ok_or(GateError::Configuration)?;
    let metadata = std::fs::symlink_metadata(&home).map_err(|_| GateError::Configuration)?;
    if !home.is_absolute()
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o022 != 0
    {
        return Err(GateError::Configuration);
    }
    if xai_grok_config::freightchain_text_review_mdm_present() {
        return Err(GateError::Configuration);
    }
    let mut merged = toml::Value::Table(Default::default());
    if let Some(system) = xai_grok_config::system_config_dir() {
        xai_grok_config::deep_merge_toml(
            &mut merged,
            &read_config(&system.join("managed_config.toml"))?,
        );
    }
    for name in ["managed_config.toml", "config.toml"] {
        xai_grok_config::deep_merge_toml(&mut merged, &read_config(&home.join(name))?);
    }
    let mut requirements = vec![read_config(&home.join("requirements.toml"))?];
    if let Some(system) = xai_grok_config::system_config_dir() {
        requirements.push(read_config(&system.join("requirements.toml"))?);
    }
    for required in &requirements {
        required_snapshot(required)?;
        xai_grok_config::deep_merge_toml(&mut merged, required);
    }
    let mut config = auth_config(&merged)?;
    let pin = requirements
        .iter()
        .filter_map(xai_grok_login::force_login_team_from_requirements_value)
        .last();
    config.force_login_team_uuid = xai_grok_login::resolve_force_login_team(
        pin,
        xai_grok_login::force_login_team_from_env(),
        config.force_login_team_uuid.take(),
    );
    AuthManager::load_text_review_cached(&home, config).map_err(|_| GateError::Authentication)
}

pub fn sampler_config(model: &str, auth: Arc<AuthManager>) -> Result<SamplerConfig, GateError> {
    if !valid_model(model) {
        return Err(GateError::Configuration);
    }
    auth.require_text_review_lifetime(Duration::from_secs(75))
        .map_err(|_| GateError::Authentication)?;
    let config = SamplerConfig {
        base_url: xai_grok_login::CLI_CHAT_PROXY_BASE_URL_DEFAULT.to_owned(),
        model: model.to_owned(),
        api_backend: ApiBackend::ChatCompletions,
        bearer_resolver: Some(WireValidBearerResolver::shared(auth)),
        extra_headers: crate::routing::fixed_route_headers(),
        max_retries: Some(0),
        max_completion_tokens: Some(8192),
        max_request_bytes: std::num::NonZeroU64::new(1024 * 1024),
        client_version: Some(xai_grok_version::VERSION.to_owned()),
        client_identifier: Some("freightchain-grok-review".to_owned()),
        origin_client: Some(OriginClientInfo {
            product: "freightchain-grok-review".to_owned(),
            version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        }),
        ..Default::default()
    };
    validate_sampler_config(&config)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_native_routing_has_no_bearer_or_caller_selected_destination() {
        let headers = crate::routing::fixed_route_headers();
        assert_eq!(headers.len(), 3);
        assert_eq!(headers.get("X-XAI-Token-Auth").map(String::as_str), Some("xai-grok-cli"));
        assert_eq!(headers.get("x-authenticateresponse").map(String::as_str), Some("authenticate-response"));
        assert_eq!(headers.get(xai_grok_http::CLIENT_MODE_HEADER).map(String::as_str), Some(xai_grok_http::process_client_mode()));
        assert!(!headers.contains_key("Authorization"));
    }

    #[test]
    fn unsupported_startup_actions_and_auth_routes_fail_closed() {
        for text in [
            "[hooks]\nstartup = 'must-not-run'\n",
            "[mcp_servers.fixture]\ncommand = 'must-not-run'\n",
            "[endpoints]\ncli_chat_proxy_base_url = 'https://invalid.test'\n",
            "[auth]\npreferred_method = 'api_key'\n",
            "[auth]\nauth_provider_command = 'must-not-run'\n",
            "[auth.oauth2]\nissuer = 'http://localhost:22255'\n",
        ] {
            let value: toml::Value = toml::from_str(text).unwrap();
            assert!(auth_config(&value).is_err());
        }
        assert!(auth_config(&toml::from_str::<toml::Value>("").unwrap()).is_ok());
    }

    #[test]
    fn mandatory_campaigns_version_overrides_and_unknown_auth_policies_are_not_dropped() {
        for text in [
            "[[campaigns]]\nid = 'required'\n",
            "[[version_overrides]]\nversion = 'unsupported'\n",
            "[auth]\nunknown_enforcement = true\n",
            "[auth]\npreferred_method = 'oidc'\n[grok_com_config]\npreferred_method = 'api_key'\n",
        ] {
            assert!(required_snapshot(&toml::from_str::<toml::Value>(text).unwrap()).is_err());
        }
    }

    #[test]
    fn config_links_special_files_and_size_overflows_are_refused_without_repair() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let file = home.path().join("config.toml");
        std::fs::write(&file, "[auth]\npreferred_method = 'oidc'\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_config(&file).is_ok());
        let linked = home.path().join("linked.toml");
        std::os::unix::fs::symlink(&file, &linked).unwrap();
        assert!(read_config(&linked).is_err());
        let hard = home.path().join("hard.toml");
        std::fs::hard_link(&file, &hard).unwrap();
        assert!(read_config(&file).is_err());
        std::fs::remove_file(&hard).unwrap();
        std::fs::write(&file, vec![b' '; 1024 * 1024 + 1]).unwrap();
        assert!(read_config(&file).is_err());
        assert!(read_config(home.path()).is_err());
        let fifo = home.path().join("fifo.toml");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid terminated path and ordinary owner-only FIFO mode.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_config(&fifo).is_err());
    }
}
