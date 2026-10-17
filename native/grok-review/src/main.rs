use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use freightchain_grok_review::config::{load_auth, sampler_config};
use freightchain_grok_review::contract::parse_request;
use freightchain_grok_review::runtime::{ReviewRuntime, valid_model};
use freightchain_grok_review::{FRAME_BYTES, GateError, SOURCE_COMMIT, SOURCE_REVISION};
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
    std::panic::set_hook(Box::new(|_| eprintln!("grok_broker_internal_failure")));
    if tracing::subscriber::set_global_default(tracing::subscriber::NoSubscriber::default())
        .is_err()
    {
        return ExitCode::from(2);
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--version"] {
        return if emit(json!({"version":1,"broker":"grok-native-review",
            "sourceCommit":SOURCE_COMMIT,"sourceRevision":SOURCE_REVISION}))
        .is_ok()
        {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        };
    }
    let outcome = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()
        .map_err(|_| GateError::Runtime)
        .and_then(|runtime| runtime.block_on(run(args)));
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let mut frame =
                json!({"version":1,"state":"blocked_or_incomplete","reason":error.code()});
            if let Some(diagnostic) = error.diagnostic() {
                frame["diagnostic"] =
                    serde_json::to_value(diagnostic).unwrap_or(serde_json::Value::Null);
            }
            let _ = emit(frame);
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
    if std::env::vars_os().any(|(key, _)| {
        let name = key.to_string_lossy();
        (name.starts_with("GROK_")
            && !matches!(
                name.as_ref(),
                "GROK_HOME" | "GROK_FORCE_LOGIN_TEAM_ID" | "GROK_DISABLE_API_KEY_AUTH"
            ))
            || name.starts_with("XAI_")
            || name.starts_with("OPENAI_")
            || name.starts_with("OTEL_")
    }) {
        return Err(GateError::Authentication);
    }
    let auth = load_auth()?;
    emit(
        json!({"version":1,"state":"preflight_ready","provider":"grok",
        "authMethod":"oidc_cached","sourceCommit":SOURCE_COMMIT,"sourceRevision":SOURCE_REVISION,
        "tools":[],"hostedTools":[],"mcpServers":[],"clientReportedModel":args[2]}),
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
    let mut runtime = ReviewRuntime::new(sampler_config(&args[2], auth)?)?;
    let (result, model) = runtime.review(&request).await?;
    emit(
        json!({"version":1,"state":"result","provider":"grok","clientReportedModel":model,"result":result}),
    )
}
