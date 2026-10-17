use futures_util::StreamExt;
use xai_grok_sampler::{ApiBackend, SamplerConfig, SamplingClient};
use xai_grok_sampling_types::types::ChatCompletionRequest;
use xai_grok_sampling_types::{ConversationItem, ConversationRequest, ConversationToolChoice};

use crate::contract::{ReviewRequest, ReviewResult, parse_result, validate_request};
use crate::{FRAME_BYTES, GateError, REVIEW_INSTRUCTION};

fn sampling_error(error: xai_grok_sampling_types::SamplingError) -> GateError {
    use xai_grok_sampling_types::SamplingError;
    match error {
        SamplingError::Api {
            status, error_code, ..
        } => {
            match error_code
                .as_ref()
                .and_then(|code| crate::ProviderDiagnostic::from_tag(code.as_str()))
            {
                Some(diagnostic) => GateError::ProviderClassified(status.as_u16(), diagnostic),
                None => GateError::ProviderStatus(status.as_u16()),
            }
        }
        SamplingError::Auth { .. } => GateError::Authentication,
        SamplingError::Http(_) => GateError::ProviderTransport,
        SamplingError::Serialization(_) | SamplingError::EventStreamError(_) => {
            GateError::ProviderProtocol
        }
        SamplingError::StreamError { .. } => GateError::ProviderStream,
        SamplingError::IdleTimeout { .. } => GateError::Deadline,
        _ => GateError::Runtime,
    }
}

pub fn validate_sampler_config(config: &SamplerConfig) -> Result<(), GateError> {
    if config.api_backend != ApiBackend::ChatCompletions
        || config.api_key.is_some()
        || config.supports_backend_search
        || !config.env_http_headers.is_empty()
        || !config.query_params.is_empty()
        || config.mtls_cert_dir.is_some()
        || config.doom_loop_recovery.is_some()
        || config.compaction_at_tokens.is_some()
        || config.compactions_remaining.is_some()
        || config.header_injector.is_some()
        || config.attribution_callback.is_some()
        || config.max_retries != Some(0)
    {
        return Err(GateError::Configuration);
    }
    Ok(())
}

pub fn conversation(request: &ReviewRequest) -> Result<ConversationRequest, GateError> {
    validate_request(request)?;
    let prompt = serde_json::to_string(request).map_err(|_| GateError::InputContract)?;
    let mut request = ConversationRequest::from_items(vec![
        ConversationItem::system(REVIEW_INSTRUCTION.trim_end_matches('\n')),
        ConversationItem::user(prompt),
    ])
    .with_tool_choice(ConversationToolChoice::None)
    .with_max_output_tokens(8192);
    request.tools.clear();
    request.hosted_tools.clear();
    Ok(request)
}

pub struct ReviewRuntime {
    client: SamplingClient,
    used: bool,
}

impl ReviewRuntime {
    /// The production constructor must independently establish native subscription auth.
    pub fn new(config: SamplerConfig) -> Result<Self, GateError> {
        validate_sampler_config(&config)?;
        let client = SamplingClient::new(config).map_err(|_| GateError::Configuration)?;
        Ok(Self {
            client,
            used: false,
        })
    }

    pub async fn review(
        &mut self,
        input: &ReviewRequest,
    ) -> Result<(ReviewResult, Option<String>), GateError> {
        let request = conversation(input)?;
        if self.used {
            return Err(GateError::InputContract);
        }
        self.used = true;
        self.collect(input, request).await
    }

    async fn collect(
        &self,
        input: &ReviewRequest,
        request: ConversationRequest,
    ) -> Result<(ReviewResult, Option<String>), GateError> {
        // Keep upstream's empty-tool encoding rather than reintroducing the
        // explicit tool_choice implicated by the provider diagnostic.
        // This is serialization, not permission: no tool runtime is constructed.
        if !request.tools.is_empty()
            || !request.hosted_tools.is_empty()
            || !matches!(request.tool_choice, Some(ConversationToolChoice::None))
        {
            return Err(GateError::ExecutionEvent);
        }
        let wire: ChatCompletionRequest = request.into();
        if wire.tools.is_some() || wire.tool_choice.is_some() || wire.search_parameters.is_some() {
            return Err(GateError::Configuration);
        }
        let (mut stream, _) = self
            .client
            .chat_completion_stream(wire)
            .await
            .map_err(sampling_error)?;
        let mut bytes = 0_usize;
        let mut count = 0_usize;
        let mut text = String::new();
        let mut finished = false;
        let mut model = None;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(sampling_error)?;
            let value = serde_json::to_value(chunk).map_err(|_| GateError::Runtime)?;
            bytes = bytes
                .checked_add(
                    serde_json::to_vec(&value)
                        .map_err(|_| GateError::Runtime)?
                        .len(),
                )
                .ok_or(GateError::OutputContract)?;
            count += 1;
            if bytes > 2 * 1024 * 1024 || count > 10_000 {
                return Err(GateError::OutputContract);
            }
            if let Some(name) = value.get("model").and_then(|value| value.as_str()) {
                if !valid_model(name) {
                    return Err(GateError::OutputContract);
                }
                model = Some(name.to_owned());
            }
            let choices = value["choices"]
                .as_array()
                .ok_or(GateError::OutputContract)?;
            if choices.is_empty() && finished && value["usage"].is_object() {
                continue;
            }
            if choices.len() != 1 || finished {
                return Err(GateError::OutputContract);
            }
            let choice = &choices[0];
            let delta = &choice["delta"];
            if choice["index"] != 0
                || !delta.is_object()
                || delta.get("tool_calls").is_some_and(|value| {
                    !value.is_null() && !value.as_array().is_some_and(Vec::is_empty)
                })
                || delta
                    .get("function_call")
                    .is_some_and(|value| !value.is_null())
                || delta
                    .get("role")
                    .is_some_and(|value| !value.is_null() && value != "assistant")
            {
                return Err(GateError::ExecutionEvent);
            }
            if let Some(content) = delta.get("content").filter(|value| !value.is_null()) {
                text.push_str(content.as_str().ok_or(GateError::OutputContract)?);
                if text.len() > FRAME_BYTES {
                    return Err(GateError::OutputContract);
                }
            }
            if let Some(reason) = choice.get("finish_reason").filter(|value| !value.is_null()) {
                if reason != "stop" {
                    return Err(GateError::OutputContract);
                }
                finished = true;
            }
        }
        if !finished {
            return Err(GateError::OutputContract);
        }
        Ok((parse_result(text.as_bytes(), input)?, model))
    }
}

pub fn valid_model(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}
