use codex_login::AuthManager;
use codex_login::CodexAuth;
use core_test_support::responses;
use core_test_support::test_codex::run_test_with_large_stack;
use core_test_support::test_codex::test_codex;
use freightchain_codex_review::GateError;
use freightchain_codex_review::REVIEW_INSTRUCTION;
use freightchain_codex_review::contract::ReviewRequest;
use freightchain_codex_review::contract::parse_request;
use freightchain_codex_review::runtime::ReviewRuntime;
use serde_json::json;
use sha2::Digest;
use sha2::Sha256;

fn inert_request() -> ReviewRequest {
    let code = "export const label = 'inert';\n";
    parse_request(
        &serde_json::to_vec(&json!({
            "version":1,"instruction":REVIEW_INSTRUCTION.trim_end_matches('\n'),
            "files":[{"path":"sample.mjs","sha256":format!("{:x}",Sha256::digest(code.as_bytes())),
                "lineCount":2,"code":code}]
        }))
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn startup_actions_are_refused_before_a_native_model_request() -> anyhow::Result<()> {
    run_test_with_large_stack("native-startup-refusal-gate", || async {
        let server = responses::start_mock_server().await;
        let fixture = test_codex().build_with_auto_env(&server).await?;
        let mut config = fixture.config.clone();
        config.notify = Some(vec!["fixture-must-not-start".to_owned()]);
        let auth =
            AuthManager::from_auth_for_testing(CodexAuth::from_api_key("dummy-fixture-only"));
        assert!(matches!(
            ReviewRuntime::start(config, auth).await,
            Err(GateError::StartupPolicy)
        ));
        let mut config = fixture.config.clone();
        let mut servers = config.mcp_servers.get().clone();
        servers.insert(
            "fixture-must-not-start".to_owned(),
            serde_json::from_value(json!({
                "command":"fixture-must-not-start","args":[]
            }))?,
        );
        config.mcp_servers.set(servers)?;
        let auth =
            AuthManager::from_auth_for_testing(CodexAuth::from_api_key("dummy-fixture-only"));
        assert!(matches!(
            ReviewRuntime::start(config, auth).await,
            Err(GateError::StartupPolicy)
        ));
        assert!(server.received_requests().await.unwrap().is_empty());
        fixture.codex.shutdown_and_wait().await?;
        Ok(())
    })
}

#[test]
fn actual_runtime_refuses_a_fabricated_tool_request() -> anyhow::Result<()> {
    run_test_with_large_stack("native-runtime-tool-gate", || async {
        let server = responses::start_mock_server().await;
        let fixture = test_codex().build_with_auto_env(&server).await?;
        let auth =
            AuthManager::from_auth_for_testing(CodexAuth::from_api_key("dummy-fixture-only"));
        let mut runtime = ReviewRuntime::start(fixture.config.clone(), auth)
            .await
            .map_err(|error| anyhow::anyhow!(error.code()))?;
        let response = responses::mount_sse_once(
            &server,
            responses::sse(vec![
                responses::ev_response_created("inert-response"),
                responses::ev_function_call(
                    "forbidden",
                    "exec_command",
                    r#"{"cmd":"printf inert"}"#,
                ),
                responses::ev_completed("inert-response"),
            ]),
        )
        .await;
        let result = runtime.review(&inert_request()).await;
        assert!(matches!(result, Err(GateError::ExecutionEvent)));
        assert_eq!(
            response.single_request().body_json()["tools"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        runtime
            .shutdown()
            .await
            .map_err(|error| anyhow::anyhow!(error.code()))?;
        fixture.codex.shutdown_and_wait().await?;
        Ok(())
    })
}

#[test]
fn actual_runtime_accepts_one_bounded_review_and_rejects_reuse() -> anyhow::Result<()> {
    run_test_with_large_stack("native-runtime-gate", || async {
        let server = responses::start_mock_server().await;
        let fixture = test_codex().build_with_auto_env(&server).await?;
        let auth =
            AuthManager::from_auth_for_testing(CodexAuth::from_api_key("dummy-fixture-only"));
        let mut runtime = ReviewRuntime::start(fixture.config.clone(), auth)
            .await
            .map_err(|error| anyhow::anyhow!(error.code()))?;
        let response = responses::mount_sse_once(
            &server,
            responses::sse(vec![
                responses::ev_response_created("inert-response"),
                responses::ev_assistant_message(
                    "inert-answer",
                    r#"{"summary":"Inert static review.","notes":[]}"#,
                ),
                responses::ev_completed("inert-response"),
            ]),
        )
        .await;
        let request = inert_request();
        let result = runtime.review(&request).await;
        let event_kind = runtime.last_event_kind().unwrap_or("unknown").to_owned();
        if result.is_ok() {
            assert!(matches!(
                runtime.review(&request).await,
                Err(GateError::InputContract)
            ));
        }
        runtime
            .shutdown()
            .await
            .map_err(|error| anyhow::anyhow!(error.code()))?;
        let result =
            result.map_err(|error| anyhow::anyhow!("{} event={}", error.code(), event_kind))?;
        assert_eq!(result.summary, "Inert static review.");
        assert_eq!(
            response.single_request().body_json()["tools"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        fixture.codex.shutdown_and_wait().await?;
        Ok(())
    })
}

#[test]
fn actual_runtime_does_not_publish_malformed_review_text() -> anyhow::Result<()> {
    run_test_with_large_stack("native-runtime-output-gate", || async {
        let server = responses::start_mock_server().await;
        let fixture = test_codex().build_with_auto_env(&server).await?;
        let auth =
            AuthManager::from_auth_for_testing(CodexAuth::from_api_key("dummy-fixture-only"));
        let mut runtime = ReviewRuntime::start(fixture.config.clone(), auth)
            .await
            .map_err(|error| anyhow::anyhow!(error.code()))?;
        responses::mount_sse_once(
            &server,
            responses::sse(vec![
                responses::ev_response_created("inert-response"),
                responses::ev_assistant_message("inert-answer", "not a review JSON object"),
                responses::ev_completed("inert-response"),
            ]),
        )
        .await;
        let result = runtime.review(&inert_request()).await;
        assert!(
            matches!(result, Err(GateError::OutputContract)),
            "event={:?}",
            runtime.last_event_kind()
        );
        runtime
            .shutdown()
            .await
            .map_err(|error| anyhow::anyhow!(error.code()))?;
        fixture.codex.shutdown_and_wait().await?;
        Ok(())
    })
}
