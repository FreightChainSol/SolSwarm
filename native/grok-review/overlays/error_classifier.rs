//! Freight Chain adaptation: no provider text is returned, logged or persisted.
use serde::Serialize;
use serde_json::Value;

pub const MAX_ERROR_BYTES: usize = 16 * 1024;
pub const CATEGORIES: &[&str] = &[
    "invalid_parameter",
    "parameter_hint",
    "ambiguous_parameter_hint",
    "unclassified",
    "malformed_json",
    "oversized_body",
    "body_timeout",
    "body_unavailable",
];
pub const PARAMETERS: &[&str] = &[
    "tool_choice",
    "tools",
    "model",
    "max_tokens",
    "max_completion_tokens",
    "messages",
    "stream_options",
    "response_format",
    "client_version",
    "x-grok-conv-id",
    "x-grok-req-id",
    "x-grok-session-id",
    "x-grok-agent-id",
    "conversation_id",
    "conv_id",
    "request_id",
    "req_id",
    "session_id",
    "agent_id",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub category: &'static str,
    pub parameter: Option<&'static str>,
}

impl Diagnostic {
    pub fn category(category: &'static str) -> Self {
        Self {
            category: CATEGORIES
                .iter()
                .copied()
                .find(|known| *known == category)
                .unwrap_or("unclassified"),
            parameter: None,
        }
    }

    pub fn tag(self) -> String {
        // Only canonical static strings enter the native error-code field.
        format!(
            "freightchain-review:{}",
            serde_json::to_string(&self).unwrap_or_default()
        )
    }

    pub fn from_tag(tag: &str) -> Option<Self> {
        let text = tag.strip_prefix("freightchain-review:")?;
        if text.len() > 256 {
            return None;
        }
        let value: Value = serde_json::from_str(text).ok()?;
        let object = value.as_object()?;
        if object.len() != 2
            || !object.contains_key("category")
            || !object.contains_key("parameter")
        {
            return None;
        }
        let category = CATEGORIES
            .iter()
            .copied()
            .find(|known| Some(*known) == value["category"].as_str())?;
        let parameter = if value["parameter"].is_null() {
            None
        } else {
            Some(
                PARAMETERS
                    .iter()
                    .copied()
                    .find(|known| Some(*known) == value["parameter"].as_str())?,
            )
        };
        if matches!(category, "invalid_parameter" | "parameter_hint") != parameter.is_some() {
            return None;
        }
        Some(Self {
            category,
            parameter,
        })
    }
}

fn parameter(value: &Value) -> Option<&'static str> {
    let value = value.as_str()?;
    let value = value
        .strip_prefix("body.")
        .or_else(|| value.strip_prefix("headers."))
        .or_else(|| value.strip_prefix("metadata."))
        .unwrap_or(value);
    PARAMETERS.iter().copied().find(|known| *known == value)
}

pub fn classify(bytes: &[u8]) -> Diagnostic {
    if bytes.len() > MAX_ERROR_BYTES {
        return Diagnostic::category("oversized_body");
    }
    let value: Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => return Diagnostic::category("malformed_json"),
    };
    let envelope = value
        .get("error")
        .filter(|value| value.is_object())
        .unwrap_or(&value);
    for key in ["param", "parameter", "field"] {
        if let Some(value) = envelope.get(key) {
            if value.is_null() {
                continue;
            }
            // A provider-supplied unknown name must never be reflected.
            return match parameter(value) {
                Some(parameter) => Diagnostic {
                    category: "invalid_parameter",
                    parameter: Some(parameter),
                },
                None => Diagnostic::category("unclassified"),
            };
        }
    }
    // Hints are intentionally distinct from a structured rejected parameter.
    let message = envelope
        .get("message")
        .and_then(Value::as_str)
        .or_else(|| value.get("error").and_then(Value::as_str))
        .or_else(|| value.get("detail").and_then(Value::as_str))
        .unwrap_or("");
    let lower = message.to_ascii_lowercase();
    let tokens: Vec<_> = lower
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
        .collect();
    let mut found: Vec<_> = PARAMETERS
        .iter()
        .copied()
        .filter(|known| tokens.contains(known))
        .collect();
    if found.contains(&"tool_choice") {
        found.retain(|known| *known != "tools");
    }
    match found.as_slice() {
        [parameter] => Diagnostic {
            category: "parameter_hint",
            parameter: Some(*parameter),
        },
        [] => Diagnostic::category("unclassified"),
        _ => Diagnostic::category("ambiguous_parameter_hint"),
    }
}
