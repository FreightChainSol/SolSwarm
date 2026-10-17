use std::sync::Arc;
use std::time::Duration;

use codex_core::CodexAppsToolsCache;
use codex_core::CodexThread;
use codex_core::StartIfIdleSubmission;
use codex_core::ThreadManager;
use codex_core::TurnInputRequest;
use codex_core::build_models_manager;
use codex_core::config::Config;
use codex_core::passthrough_image_store;
use codex_core::thread_store_from_config;
use codex_exec_server::EnvironmentManager;
use codex_extension_api::LoadInstructionsFuture;
use codex_extension_api::LoadedUserInstructions;
use codex_extension_api::UserInstructionsProvider;
use codex_extension_api::empty_extension_registry;
use codex_login::AuthManager;
use codex_protocol::ThreadId;
use codex_protocol::items::TurnItem;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::SessionSource;
use codex_protocol::user_input::UserInput;

use crate::FRAME_BYTES;
use crate::GateError;
use crate::contract::ReviewRequest;
use crate::contract::ReviewResult;
use crate::contract::parse_result;
use crate::contract::validate_request;
use crate::policy::review_start_options;

struct NoUserInstructions;
impl UserInstructionsProvider for NoUserInstructions {
    fn load_user_instructions(&self) -> LoadInstructionsFuture<'_> {
        Box::pin(async { LoadedUserInstructions::default() })
    }
}

pub struct ReviewRuntime {
    manager: ThreadManager,
    thread: Arc<CodexThread>,
    thread_id: ThreadId,
    used: bool,
    last_event_kind: Option<String>,
    pub client_reported_model: String,
}

impl ReviewRuntime {
    /// The production caller must validate native subscription auth first.
    pub async fn start(config: Config, auth: Arc<AuthManager>) -> Result<Self, GateError> {
        let options = review_start_options(config)?;
        let config = &options.config;
        let manager = ThreadManager::new(
            config,
            Arc::clone(&auth),
            build_models_manager(config, auth),
            CodexAppsToolsCache::default(),
            SessionSource::Exec,
            Arc::new(EnvironmentManager::without_environments(
                config.http_client_factory(),
            )),
            empty_extension_registry(),
            Arc::new(NoUserInstructions),
            None,
            passthrough_image_store(),
            thread_store_from_config(config, None),
            None,
            "freightchain-native-review".to_owned(),
            None,
            None,
        );
        let created = manager
            .start_thread(options)
            .await
            .map_err(|_| GateError::Runtime)?;
        Ok(Self {
            manager,
            thread: created.thread,
            thread_id: created.thread_id,
            used: false,
            last_event_kind: None,
            client_reported_model: created.session_configured.model,
        })
    }

    pub fn last_event_kind(&self) -> Option<&str> {
        self.last_event_kind.as_deref()
    }

    pub async fn review(&mut self, request: &ReviewRequest) -> Result<ReviewResult, GateError> {
        validate_request(request)?;
        if self.used {
            return Err(GateError::InputContract);
        }
        self.used = true;
        let prompt = serde_json::to_string(request).map_err(|_| GateError::InputContract)?;
        let submitted = self
            .thread
            .start_turn_if_idle(TurnInputRequest::user_input(vec![UserInput::Text {
                text: prompt,
                text_elements: Vec::new(),
            }]))
            .await
            .map_err(|_| GateError::Runtime)?;
        if matches!(submitted, StartIfIdleSubmission::NotSubmitted { .. }) {
            return Err(GateError::Runtime);
        }
        self.collect(request).await
    }

    async fn collect(&mut self, request: &ReviewRequest) -> Result<ReviewResult, GateError> {
        let mut bytes = 0_usize;
        loop {
            let event = self
                .thread
                .next_event()
                .await
                .map_err(|_| GateError::Runtime)?;
            let descriptor = serde_json::to_value(&event.msg).map_err(|_| GateError::Runtime)?;
            self.last_event_kind = descriptor
                .get("type")
                .and_then(|value| value.as_str())
                .filter(|value| {
                    value.len() <= 64
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
                })
                .map(str::to_owned);
            if let EventMsg::RawResponseItem(raw) = &event.msg {
                let kind = match &raw.item {
                    ResponseItem::Message { role, .. } if role == "user" => {
                        "raw_response_item/user"
                    }
                    ResponseItem::Message { role, .. } if role == "developer" => {
                        "raw_response_item/developer"
                    }
                    ResponseItem::Message { role, .. } if role == "assistant" => {
                        "raw_response_item/assistant"
                    }
                    ResponseItem::AdditionalTools { .. } => "raw_response_item/additional_tools",
                    ResponseItem::Reasoning { .. } => "raw_response_item/reasoning",
                    ResponseItem::FunctionCall { .. } => "raw_response_item/function_call",
                    _ => "raw_response_item/other",
                };
                self.last_event_kind = Some(kind.to_owned());
            }
            bytes = bytes
                .checked_add(
                    serde_json::to_vec(&event.msg)
                        .map_err(|_| GateError::Runtime)?
                        .len(),
                )
                .ok_or(GateError::Runtime)?;
            if bytes > 2 * 1024 * 1024 {
                return Err(GateError::OutputContract);
            }
            match event.msg {
                EventMsg::TurnComplete(done) => {
                    if done.error.is_some() {
                        return Err(GateError::Runtime);
                    }
                    let text = done.last_agent_message.ok_or(GateError::OutputContract)?;
                    if text.len() > FRAME_BYTES {
                        return Err(GateError::OutputContract);
                    }
                    return parse_result(text.as_bytes(), request);
                }
                EventMsg::ModelReroute(route) => {
                    // Preserve provider safety routing; never spoof a requested model identity.
                    self.client_reported_model = route.to_model;
                }
                EventMsg::ItemStarted(item) => validate_item(&item.item)?,
                EventMsg::ItemCompleted(item) => validate_item(&item.item)?,
                EventMsg::RawResponseItem(event) => validate_response_item(&event.item)?,
                EventMsg::RawResponseCompleted(_) => {}
                EventMsg::Error(_) | EventMsg::TurnAborted(_) => return Err(GateError::Runtime),
                EventMsg::McpStartupComplete(summary) => {
                    if !summary.ready.is_empty()
                        || !summary.failed.is_empty()
                        || !summary.cancelled.is_empty()
                    {
                        return Err(GateError::ExecutionEvent);
                    }
                }
                EventMsg::TurnStarted(_)
                | EventMsg::SessionConfigured(_)
                | EventMsg::ThreadSettingsApplied(_)
                | EventMsg::TokenCount(_)
                | EventMsg::AgentMessage(_)
                | EventMsg::UserMessage(_)
                | EventMsg::AgentReasoning(_)
                | EventMsg::AgentReasoningRawContent(_)
                | EventMsg::AgentReasoningSectionBreak(_)
                | EventMsg::AgentMessageContentDelta(_)
                | EventMsg::ReasoningContentDelta(_)
                | EventMsg::ReasoningRawContentDelta(_)
                | EventMsg::Warning(_)
                | EventMsg::DeprecationNotice(_)
                | EventMsg::AuthRecoveryStarted(_)
                | EventMsg::AuthRecoveryCompleted(_)
                | EventMsg::ModelVerification(_)
                | EventMsg::TurnModerationMetadata(_)
                | EventMsg::SafetyBuffering(_) => {}
                _ => return Err(GateError::ExecutionEvent),
            }
        }
    }

    pub async fn shutdown(self) -> Result<(), GateError> {
        tokio::time::timeout(Duration::from_secs(10), self.thread.shutdown_and_wait())
            .await
            .map_err(|_| GateError::Deadline)?
            .map_err(|_| GateError::Runtime)?;
        self.manager.remove_thread(&self.thread_id).await;
        Ok(())
    }
}

fn validate_item(item: &TurnItem) -> Result<(), GateError> {
    match item {
        TurnItem::UserMessage(_) | TurnItem::AgentMessage(_) | TurnItem::Reasoning(_) => Ok(()),
        _ => Err(GateError::ExecutionEvent),
    }
}

fn validate_response_item(item: &ResponseItem) -> Result<(), GateError> {
    match item {
        ResponseItem::Message { role, content, .. }
            if role == "assistant"
                && content
                    .iter()
                    .all(|part| matches!(part, ContentItem::OutputText { .. })) =>
        {
            Ok(())
        }
        ResponseItem::Message { role, content, .. }
            if matches!(role.as_str(), "developer" | "user")
                && content
                    .iter()
                    .all(|part| matches!(part, ContentItem::InputText { .. })) =>
        {
            Ok(())
        }
        ResponseItem::Reasoning { .. } => Ok(()),
        _ => Err(GateError::ExecutionEvent),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn raw_item_validation_accepts_text_but_never_tool_or_alternate_role_items() {
        for item in [
            json!({"type":"message","role":"assistant","content":[{"type":"output_text","text":"inert"}]}),
            json!({"type":"message","role":"developer","content":[{"type":"input_text","text":"SDK context fixture"}]}),
            json!({"type":"message","role":"user","content":[{"type":"input_text","text":"authorized input fixture"}]}),
            json!({"type":"reasoning","summary":[],"encrypted_content":null}),
        ] {
            let item: ResponseItem = serde_json::from_value(item).unwrap();
            assert!(validate_response_item(&item).is_ok());
        }
        for item in [
            json!({"type":"function_call","name":"exec_command","arguments":"{}","call_id":"fixture-call"}),
            json!({"type":"message","role":"system","content":[{"type":"output_text","text":"inert"}]}),
            json!({"type":"message","role":"developer","content":[{"type":"output_text","text":"not input context"}]}),
            json!({"type":"message","role":"assistant","content":[{"type":"input_image","image_url":"https://invalid.test/fixture"}]}),
        ] {
            let item: ResponseItem = serde_json::from_value(item).unwrap();
            assert_eq!(
                validate_response_item(&item),
                Err(GateError::ExecutionEvent)
            );
        }
    }
}
