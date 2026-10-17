use codex_core::TurnInputRequest;
use codex_extension_api::ToolName;
use codex_extension_api::ToolPolicy;
use codex_protocol::protocol::EventMsg;
use codex_protocol::user_input::UserInput;
use core_test_support::responses;
use core_test_support::test_codex::run_test_with_large_stack;
use core_test_support::test_codex::test_codex;
use core_test_support::wait_for_event;
use freightchain_codex_review::policy::review_start_options;

#[test]
fn real_native_runtime_advertises_no_tools_and_rejects_a_fabricated_call() -> anyhow::Result<()> {
    run_test_with_large_stack("native-review-startup-gate", || async {
        let server = responses::start_mock_server().await;
        let fixture = test_codex().build_with_auto_env(&server).await?;
        let mut config = fixture.config.clone();
        std::fs::write(config.cwd.join("AGENTS.md"), "PRIVATE_CONTEXT_SENTINEL")?;
        config.update_plan_enabled = true;
        let options =
            review_start_options(config).map_err(|error| anyhow::anyhow!(error.code()))?;
        let agent = fixture.thread_manager.start_thread(options).await?;
        // The native startup ceiling must remain captured even if later state changes.
        agent.thread.thread_extension_data().insert(ToolPolicy {
            allowed_tools: Some(vec![ToolName::plain("exec_command")]),
            ..Default::default()
        });
        let response = responses::mount_sse_sequence(
            &server,
            vec![
                responses::sse(vec![
                    responses::ev_function_call(
                        "excluded",
                        "exec_command",
                        r#"{"cmd":"printf inert"}"#,
                    ),
                    responses::ev_completed("inert-call"),
                ]),
                responses::sse(vec![
                    responses::ev_assistant_message(
                        "inert-answer",
                        r#"{"summary":"Inert static fixture.","notes":[]}"#,
                    ),
                    responses::ev_completed("inert-result"),
                ]),
            ],
        )
        .await;
        agent
            .thread
            .start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
                text: "Review the supplied inert text only.".to_owned(),
                text_elements: Vec::new(),
            }]))
            .await?;
        wait_for_event(&agent.thread, |event| {
            matches!(event, EventMsg::TurnComplete(_))
        })
        .await;
        let requests = response.requests();
        assert_eq!(requests.len(), 2);
        for request in &requests {
            assert_eq!(request.body_json()["tools"].as_array().unwrap().len(), 0);
            assert!(!request.body_contains_text("PRIVATE_CONTEXT_SENTINEL"));
        }
        assert_eq!(
            requests[1].function_call_output("excluded")["output"],
            "unsupported call: exec_command"
        );
        agent.thread.shutdown_and_wait().await?;
        fixture.codex.shutdown_and_wait().await?;
        Ok(())
    })
}
