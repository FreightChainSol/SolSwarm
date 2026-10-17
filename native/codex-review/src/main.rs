use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use codex_core::config::find_codex_home;
use freightchain_codex_review::FRAME_BYTES;
use freightchain_codex_review::GateError;
use freightchain_codex_review::SOURCE_COMMIT;
use freightchain_codex_review::contract::parse_request;
use freightchain_codex_review::runtime::ReviewRuntime;
use freightchain_codex_review::runtime_config::load_configuration;
use freightchain_codex_review::runtime_config::load_native_auth;
use freightchain_codex_review::runtime_config::valid_model;
use serde_json::json;
use tokio::io::AsyncBufReadExt;

fn emit(value: serde_json::Value) -> Result<(), GateError> {
    let bytes = serde_json::to_vec(&value).map_err(|_| GateError::Runtime)?;
    if bytes.len() > FRAME_BYTES {
        return Err(GateError::OutputContract);
    }
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&bytes).map_err(|_| GateError::Runtime)?;
    stdout.write_all(b"\n").map_err(|_| GateError::Runtime)?;
    stdout.flush().map_err(|_| GateError::Runtime)
}

fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| eprintln!("native_broker_internal_failure")));
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--version"] {
        return if emit(
            json!({"version":1,"sourceCommit":SOURCE_COMMIT,"broker":"codex-native-review"}),
        )
        .is_ok()
        {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        };
    }
    let result = std::thread::Builder::new()
        .name("native-review-owner".to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .map_err(|_| GateError::Runtime)?;
            runtime.block_on(Box::pin(run(args)))
        });
    let outcome = result
        .ok()
        .and_then(|handle| handle.join().ok())
        .unwrap_or(Err(GateError::Runtime));
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ =
                emit(json!({"version":1,"state":"blocked_or_incomplete","reason":error.code()}));
            ExitCode::from(2)
        }
    }
}

async fn run(args: Vec<String>) -> Result<(), GateError> {
    if args.len() != 3
        || !matches!(args[0].as_str(), "--check" | "--review")
        || args[1] != "--model"
        || !valid_model(&args[2])
    {
        return Err(GateError::InputContract);
    }
    // Only inspect names; never display or export environment credential values.
    if std::env::vars_os().any(|(key, _)| {
        let name = key.to_string_lossy();
        name.starts_with("OPENAI_")
            || name.starts_with("AZURE_")
            || name.starts_with("AWS_")
            || name.starts_with("GOOGLE_")
            || (name.starts_with("CODEX_") && name != "CODEX_HOME")
    }) {
        return Err(GateError::Authentication);
    }
    let private = tempfile::Builder::new()
        .prefix("fc-codex-runtime-")
        .tempdir()
        .map_err(|_| GateError::Runtime)?;
    let credential_home = find_codex_home().map_err(|_| GateError::Authentication)?;
    let (config, auth) = tokio::time::timeout(
        Duration::from_secs(15),
        load_configuration(credential_home.as_path(), private.path(), &args[2]),
    )
    .await
    .map_err(|_| GateError::Deadline)??;
    let auth = tokio::time::timeout(Duration::from_secs(15), load_native_auth(auth))
        .await
        .map_err(|_| GateError::Deadline)??;
    let mut runtime =
        tokio::time::timeout(Duration::from_secs(20), ReviewRuntime::start(config, auth))
            .await
            .map_err(|_| GateError::Deadline)??;
    let outcome = async {
        emit(
            json!({"version":1,"state":"preflight_ready","provider":"codex",
            "authMethod":"chatgpt","sourceCommit":SOURCE_COMMIT,"tools":[],"mcpServers":[],
            "clientReportedModel":runtime.client_reported_model}),
        )?;
        if args[0] == "--check" {
            return Ok(());
        }
        let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
        let mut bytes = Vec::new();
        let read = async {
            loop {
                let available = reader
                    .fill_buf()
                    .await
                    .map_err(|_| GateError::InputContract)?;
                if available.is_empty() {
                    return Err(GateError::InputContract);
                }
                let take = available
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(available.len(), |at| at + 1);
                if bytes.len() + take > FRAME_BYTES {
                    return Err(GateError::InputContract);
                }
                let done = available[take - 1] == b'\n';
                bytes.extend_from_slice(&available[..take]);
                reader.consume(take);
                if done {
                    return Ok(());
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(120), read)
            .await
            .map_err(|_| GateError::Deadline)??;
        let request = parse_request(&bytes)?;
        let result = runtime.review(&request).await?;
        emit(json!({"version":1,"state":"result","provider":"codex",
            "clientReportedModel":runtime.client_reported_model,"result":result}))
    }
    .await;
    runtime.shutdown().await?;
    outcome
}
