use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::Command;

use chrono::{Duration, Utc};
use xai_grok_login::{AuthMode, GrokAuth, GrokComConfig, XAI_OAUTH2_ISSUER};

fn fixture(home: &std::path::Path) {
    let config = GrokComConfig::default();
    let auth = GrokAuth {
        key: "dummy-native-cli-fixture".to_owned(),
        auth_mode: AuthMode::Oidc,
        create_time: Utc::now(),
        expires_at: Some(Utc::now() + Duration::hours(1)),
        user_id: "fixture-only".to_owned(),
        oidc_issuer: Some(XAI_OAUTH2_ISSUER.to_owned()),
        oidc_client_id: config.oauth2.as_ref().map(|oauth| oauth.client_id.clone()),
        ..Default::default()
    };
    let mut store = BTreeMap::new();
    store.insert(config.auth_scope(), auth);
    std::fs::write(home.join("auth.json"), serde_json::to_vec(&store).unwrap()).unwrap();
    std::fs::set_permissions(
        home.join("auth.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
}

#[test]
fn native_cli_check_reads_only_the_dummy_store_and_emits_no_diagnostics() {
    let home = tempfile::tempdir().unwrap();
    fixture(home.path());
    let file = home.path().join("auth.json");
    let before = std::fs::read(&file).unwrap();
    let metadata = std::fs::metadata(&file).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_freightchain-grok-review"))
        .args(["--check", "--model", "fixture-model"])
        .env_clear()
        .env("HOME", home.path())
        .env("GROK_HOME", home.path())
        .env("PATH", "/usr/bin:/bin")
        .current_dir(home.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "native fixture preflight failed");
    assert!(output.stderr.is_empty());
    let frame: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(frame["state"], "preflight_ready");
    assert_eq!(frame["authMethod"], "oidc_cached");
    assert_eq!(frame["tools"], serde_json::json!([]));
    assert_eq!(frame["hostedTools"], serde_json::json!([]));
    assert_eq!(before, std::fs::read(&file).unwrap());
    let after = std::fs::metadata(&file).unwrap();
    assert_eq!(
        (metadata.mode(), metadata.mtime(), metadata.mtime_nsec()),
        (after.mode(), after.mtime(), after.mtime_nsec())
    );
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 1);
}

#[test]
fn native_cli_rejects_execution_and_environment_overrides_without_auth_side_effects() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_freightchain-grok-review"))
        .args(["--check", "--model", "fixture-model"])
        .env_clear()
        .env("HOME", home.path())
        .env("GROK_HOME", home.path())
        .env("XAI_API_KEY", "dummy-fixture-only")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let frame: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(frame["reason"], "grok_subscription_auth_required");
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn missing_grok_home_is_not_created_during_preflight() {
    let home = tempfile::tempdir().unwrap();
    let missing = home.path().join("missing");
    let output = Command::new(env!("CARGO_BIN_EXE_freightchain-grok-review"))
        .args(["--check", "--model", "fixture-model"])
        .env_clear()
        .env("HOME", home.path())
        .env("GROK_HOME", &missing)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    assert!(!missing.exists());
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}
