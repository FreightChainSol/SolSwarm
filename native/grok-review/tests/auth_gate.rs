use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use xai_grok_login::credential_provider::WireValidBearerResolver;
use xai_grok_login::{
    AuthManager, AuthMode, ForceLoginTeam, GrokAuth, GrokComConfig, XAI_OAUTH2_ISSUER,
};

fn fixture(home: &Path, mode: AuthMode) -> (GrokComConfig, GrokAuth) {
    let config = GrokComConfig::default();
    let auth = GrokAuth {
        key: "dummy-fixture-not-a-provider-credential".to_owned(),
        auth_mode: mode,
        create_time: Utc::now(),
        expires_at: Some(Utc::now() + ChronoDuration::hours(1)),
        user_id: "inert-fixture".to_owned(),
        oidc_issuer: Some(XAI_OAUTH2_ISSUER.to_owned()),
        oidc_client_id: config.oauth2.as_ref().map(|oauth| oauth.client_id.clone()),
        ..Default::default()
    };
    save(home, &config, &auth);
    (config, auth)
}

fn save(home: &Path, config: &GrokComConfig, auth: &GrokAuth) {
    let mut store = BTreeMap::new();
    store.insert(config.auth_scope(), auth);
    std::fs::write(home.join("auth.json"), serde_json::to_vec(&store).unwrap()).unwrap();
    std::fs::set_permissions(
        home.join("auth.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
}

fn state(home: &Path) -> (Vec<u8>, u32, i64, i64, Vec<String>) {
    let path = home.join("auth.json");
    let metadata = std::fs::metadata(&path).unwrap();
    let mut names: Vec<_> = std::fs::read_dir(home)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    (
        std::fs::read(path).unwrap(),
        metadata.mode(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        names,
    )
}

#[tokio::test]
async fn native_cached_auth_preflight_and_resolver_never_modify_the_store() {
    let home = tempfile::tempdir().unwrap();
    let (config, _) = fixture(home.path(), AuthMode::Oidc);
    let before = state(home.path());
    let manager = AuthManager::load_text_review_cached(home.path(), config).unwrap();
    let resolver = WireValidBearerResolver::shared(manager.clone());
    for _ in 0..3 {
        resolver.prepare_for_send().await;
        assert!(
            manager
                .require_text_review_lifetime(Duration::from_secs(75))
                .is_ok()
        );
    }
    assert!(
        manager
            .require_text_review_lifetime(Duration::from_secs(7200))
            .is_err()
    );
    assert_eq!(before, state(home.path()));
}

#[test]
fn unsupported_auth_issuer_expiry_client_and_team_pins_are_refused_without_mutation() {
    for mode in [AuthMode::ApiKey, AuthMode::External, AuthMode::WebLogin] {
        let home = tempfile::tempdir().unwrap();
        let (config, _) = fixture(home.path(), mode);
        let before = state(home.path());
        assert!(AuthManager::load_text_review_cached(home.path(), config).is_err());
        assert_eq!(before, state(home.path()));
    }
    for case in 0..6 {
        let home = tempfile::tempdir().unwrap();
        let (mut config, mut auth) = fixture(home.path(), AuthMode::Oidc);
        match case {
            0 => auth.oidc_issuer = Some("https://untrusted.invalid".to_owned()),
            1 => auth.oidc_issuer = Some("http://localhost:22255".to_owned()),
            2 => auth.oidc_client_id = Some("other-client".to_owned()),
            3 => auth.expires_at = None,
            4 => auth.expires_at = Some(Utc::now() - ChronoDuration::seconds(1)),
            _ => config.force_login_team_uuid = Some(ForceLoginTeam::AnyOf(Vec::new())),
        }
        save(home.path(), &config, &auth);
        let before = state(home.path());
        assert!(AuthManager::load_text_review_cached(home.path(), config).is_err());
        assert_eq!(before, state(home.path()));
    }
}

#[test]
fn unsafe_or_corrupt_native_stores_are_refused_not_repaired() {
    let home = tempfile::tempdir().unwrap();
    let (config, _) = fixture(home.path(), AuthMode::Oidc);
    std::fs::set_permissions(
        home.path().join("auth.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let before = state(home.path());
    assert!(AuthManager::load_text_review_cached(home.path(), config.clone()).is_err());
    assert_eq!(before, state(home.path()));
    std::fs::write(home.path().join("auth.json"), b"not JSON").unwrap();
    std::fs::set_permissions(
        home.path().join("auth.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let before = state(home.path());
    assert!(AuthManager::load_text_review_cached(home.path(), config).is_err());
    assert_eq!(before, state(home.path()));
}
