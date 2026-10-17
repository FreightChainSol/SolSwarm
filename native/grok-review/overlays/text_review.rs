//! Freight Chain review-only adaptation of the pinned native auth manager.
//! Only cached first-party login is supported; normal CLI owns refresh/login.
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::AuthManager;
use crate::{AuthMode, GrokComConfig, PreferredAuthMethod, XAI_OAUTH2_ISSUER};

impl AuthManager {
    pub fn load_text_review_cached(home: &Path, config: GrokComConfig) -> Result<Arc<Self>, ()> {
        if !home.is_absolute()
            || config.oidc.is_some()
            || config.auth_provider_command.is_some()
            || config.preferred_method == Some(PreferredAuthMethod::ApiKey)
        {
            return Err(());
        }
        let oauth = config.oauth2.as_ref().ok_or(())?;
        if oauth.issuer != XAI_OAUTH2_ISSUER || oauth.client_id.is_empty() {
            return Err(());
        }
        let expected_client = oauth.client_id.clone();
        let scope = config.auth_scope();
        // No inherited-scope pruning, permission repair, backup, lock or logging.
        let file_path = home.join("auth.json");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&file_path)
            .map_err(|_| ())?;
        let metadata = file.metadata().map_err(|_| ())?;
        // SAFETY: geteuid has no preconditions or external side effects.
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.len() > 1024 * 1024
        {
            return Err(());
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ())?;
        if bytes.len() > 1024 * 1024 {
            return Err(());
        }
        // Native AuthStore schema and scope lookup; no broker token parsing.
        let store: crate::model::AuthStore = serde_json::from_slice(&bytes).map_err(|_| ())?;
        let auth = crate::lookup_auth(&store, &scope).ok_or(())?;
        if auth.auth_mode != AuthMode::Oidc
            || auth.oidc_issuer.as_deref() != Some(XAI_OAUTH2_ISSUER)
            || auth.oidc_client_id.as_deref() != Some(expected_client.as_str())
            || auth.expires_at.is_none()
        {
            return Err(());
        }
        let mut manager = Self::assemble(
            Some(auth.clone()),
            file_path,
            scope,
            config,
            crate::CLI_CHAT_PROXY_BASE_URL_DEFAULT.to_owned(),
            None,
        );
        manager.text_review_cached_only = true;
        if manager.cached_token_policy_error(&auth).is_some() {
            return Err(());
        }
        let manager = Arc::new(manager);
        manager.require_text_review_lifetime(Duration::from_secs(240))?;
        Ok(manager)
    }

    /// A pure in-memory check. Never adopts a sibling token or changes a store.
    pub fn require_text_review_lifetime(&self, lifetime: Duration) -> Result<(), ()> {
        if !self.text_review_cached_only
            || self.refresher.read().is_some()
            || !self
                .remaining_wire_life()
                .is_some_and(|remaining| remaining >= lifetime)
        {
            return Err(());
        }
        Ok(())
    }

    pub(crate) fn is_text_review_cached_only(&self) -> bool {
        self.text_review_cached_only
    }
}
