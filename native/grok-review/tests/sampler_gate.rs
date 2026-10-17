use freightchain_grok_review::contract::parse_request;
use freightchain_grok_review::runtime::{ReviewRuntime, conversation};
use freightchain_grok_review::{GateError, REVIEW_INSTRUCTION};
use serde_json::json;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use xai_grok_sampler::{ApiBackend, SamplerConfig};

fn input() -> freightchain_grok_review::contract::ReviewRequest {
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

fn frame(delta: serde_json::Value, finish: serde_json::Value) -> String {
    format!(
        "data: {}\n\n",
        json!({"id":"fixture","object":"chat.completion.chunk","created":1,
            "model":"fixture-model","choices":[{"index":0,"delta":delta,"finish_reason":finish}]})
    )
}

async fn runtime(server: &MockServer, body: String) -> ReviewRuntime {
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(|request: &wiremock::Request| {
            let body: serde_json::Value = request.body_json().unwrap();
            body.get("tools").is_none()
                && body.get("tool_choice").is_none()
                && body.get("search_parameters").is_none()
        })
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .expect(1)
        .mount(server)
        .await;
    ReviewRuntime::new(SamplerConfig {
        base_url: server.uri(),
        model: "fixture-model".to_owned(),
        api_backend: ApiBackend::ChatCompletions,
        max_retries: Some(0),
        ..Default::default()
    })
    .unwrap()
}

#[tokio::test]
async fn actual_sampler_sends_no_local_or_hosted_tools_and_refuses_reuse() {
    let server = MockServer::start().await;
    let body = frame(
        json!({"role":"assistant","content":"{\"summary\":\"Inert review.\",\"notes\":[]}"}),
        json!(null),
    ) + frame(json!({}), json!("stop")).as_str()
        + "data: [DONE]\n\n";
    let mut runtime = runtime(&server, body).await;
    let input = input();
    let request = conversation(&input).unwrap();
    assert!(request.tools.is_empty() && request.hosted_tools.is_empty());
    let (result, model) = runtime.review(&input).await.unwrap();
    assert_eq!(result.summary, "Inert review.");
    assert_eq!(model.as_deref(), Some("fixture-model"));
    assert!(matches!(
        runtime.review(&input).await,
        Err(GateError::InputContract)
    ));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = requests[0].body_json().unwrap();
    assert!(body.get("tools").is_none());
    assert!(body.get("tool_choice").is_none());
    assert!(body.get("search_parameters").is_none());
    assert!(!body.to_string().contains("web_search"));
}

#[tokio::test]
async fn fabricated_tool_calls_never_enter_an_execution_loop() {
    let server = MockServer::start().await;
    let body = frame(
        json!({"tool_calls":[{"index":0,"id":"forbidden","type":"function",
            "function":{"name":"run_terminal_cmd","arguments":"{}"}}]}),
        json!(null),
    ) + frame(json!({}), json!("tool_calls")).as_str()
        + "data: [DONE]\n\n";
    let mut runtime = runtime(&server, body).await;
    assert!(matches!(
        runtime.review(&input()).await,
        Err(GateError::ExecutionEvent)
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn empty_tool_call_metadata_is_not_an_execution_request() {
    let server = MockServer::start().await;
    let body = frame(
        json!({"content":"{\"summary\":\"Inert review.\",\"notes\":[]}","tool_calls":[]}),
        json!(null),
    ) + frame(json!({}), json!("stop")).as_str()
        + "data: [DONE]\n\n";
    let mut runtime = runtime(&server, body).await;
    assert!(runtime.review(&input()).await.is_ok());
}

#[tokio::test]
async fn provider_error_body_is_classified_without_reflecting_message_text() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error":{"param":"tool_choice","message":"dummy-private-provider-payload"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut runtime = ReviewRuntime::new(SamplerConfig {
        base_url: server.uri(),
        model: "fixture-model".to_owned(),
        api_backend: ApiBackend::ChatCompletions,
        max_retries: Some(0),
        ..Default::default()
    })
    .unwrap();
    let error = match runtime.review(&input()).await {
        Err(error) => error,
        Ok(_) => panic!("must refuse"),
    };
    assert_eq!(error.code(), "grok_provider_http_400");
    let diagnostic = error.diagnostic().unwrap();
    assert_eq!(diagnostic.category, "invalid_parameter");
    assert_eq!(diagnostic.parameter, Some("tool_choice"));
    assert!(!format!("{error:?}").contains("dummy"));
}

#[tokio::test]
async fn oversized_provider_error_body_is_refused_before_parsing() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_string("x".repeat(16 * 1024 + 1)))
        .expect(1)
        .mount(&server)
        .await;
    let mut runtime = ReviewRuntime::new(SamplerConfig {
        base_url: server.uri(),
        model: "fixture-model".to_owned(),
        api_backend: ApiBackend::ChatCompletions,
        max_retries: Some(0),
        ..Default::default()
    })
    .unwrap();
    let error = match runtime.review(&input()).await {
        Err(error) => error,
        Ok(_) => panic!("must refuse"),
    };
    assert_eq!(error.diagnostic().unwrap().category, "oversized_body");
}

#[tokio::test]
async fn stalled_provider_error_body_has_an_independent_read_deadline() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 8192];
        let _ = stream.read(&mut buffer).await.unwrap();
        stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{",
            )
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    });
    let mut runtime = ReviewRuntime::new(SamplerConfig {
        base_url: format!("http://{address}"),
        model: "fixture-model".to_owned(),
        api_backend: ApiBackend::ChatCompletions,
        max_retries: Some(0),
        ..Default::default()
    })
    .unwrap();
    let result = runtime.review(&input()).await;
    server.abort();
    let _ = server.await;
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("must refuse"),
    };
    assert_eq!(error.diagnostic().unwrap().category, "body_timeout");
}

#[tokio::test]
async fn malformed_or_truncated_results_are_not_accepted() {
    for (content, finish) in [
        ("not review JSON", "stop"),
        ("{\"summary\":\"Inert\",\"notes\":[]}", "length"),
    ] {
        let server = MockServer::start().await;
        let body = frame(json!({"content":content}), json!(null))
            + frame(json!({}), json!(finish)).as_str()
            + "data: [DONE]\n\n";
        let mut runtime = runtime(&server, body).await;
        assert!(matches!(
            runtime.review(&input()).await,
            Err(GateError::OutputContract)
        ));
    }
}
#[derive(Debug)]
struct UnavailableCredential;
impl xai_grok_sampler::BearerResolver for UnavailableCredential {
    fn current_bearer(&self) -> Option<String> {
        None
    }
}

#[tokio::test]
async fn unavailable_native_credential_sends_no_anonymous_request() {
    let server = MockServer::start().await;
    let mut runtime = ReviewRuntime::new(SamplerConfig {
        base_url: server.uri(),
        model: "fixture-model".to_owned(),
        api_backend: ApiBackend::ChatCompletions,
        bearer_resolver: Some(std::sync::Arc::new(UnavailableCredential)),
        max_retries: Some(0),
        ..Default::default()
    })
    .unwrap();
    assert!(matches!(
        runtime.review(&input()).await,
        Err(GateError::Authentication)
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn oversized_raw_sse_is_refused_before_accepting_a_result() {
    let server = MockServer::start().await;
    let body = frame(json!({"content":"x".repeat(2 * 1024 * 1024)}), json!(null))
        + frame(json!({}), json!("stop")).as_str()
        + "data: [DONE]\n\n";
    let mut runtime = runtime(&server, body).await;
    assert!(runtime.review(&input()).await.is_err());
}

#[tokio::test]
async fn provider_refusal_emits_only_a_fixed_status_category_without_retry() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(400).set_body_string("dummy provider payload must not appear"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let mut runtime = ReviewRuntime::new(SamplerConfig {
        base_url: server.uri(),
        model: "fixture-model".to_owned(),
        api_backend: ApiBackend::ChatCompletions,
        max_retries: Some(0),
        ..Default::default()
    })
    .unwrap();
    let error = match runtime.review(&input()).await {
        Err(error) => error,
        Ok(_) => panic!("must reject"),
    };
    assert_eq!(error.code(), "grok_provider_http_400");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
