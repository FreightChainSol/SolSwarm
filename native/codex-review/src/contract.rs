use std::collections::HashSet;

use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

use crate::FRAME_BYTES;
use crate::GateError;
use crate::REVIEW_INSTRUCTION;
use crate::SOURCE_BYTES;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRequest {
    pub version: u8,
    pub instruction: String,
    pub files: Vec<SourceFile>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFile {
    pub path: String,
    pub sha256: String,
    #[serde(rename = "lineCount")]
    pub line_count: usize,
    pub code: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewResult {
    pub summary: String,
    pub notes: Vec<ReviewNote>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewNote {
    pub path: String,
    pub line: usize,
    pub kind: String,
    pub message: String,
    pub recommendation: String,
}

fn relative_file(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('/')
        && !value.contains(['\\', ':'])
        && !value.chars().any(|c| c.is_control())
        && !value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum && !value.contains('\0')
}

pub fn parse_request(bytes: &[u8]) -> Result<ReviewRequest, GateError> {
    if bytes.len() > FRAME_BYTES {
        return Err(GateError::InputContract);
    }
    let request: ReviewRequest =
        serde_json::from_slice(bytes).map_err(|_| GateError::InputContract)?;
    validate_request(&request)?;
    Ok(request)
}

pub fn validate_request(request: &ReviewRequest) -> Result<(), GateError> {
    if request.version != 1
        || request.instruction != REVIEW_INSTRUCTION.trim_end_matches('\n')
        || request.files.is_empty()
        || request.files.len() > 3
    {
        return Err(GateError::InputContract);
    }
    let mut bytes = 0_usize;
    let mut paths = HashSet::new();
    for file in &request.files {
        bytes = bytes
            .checked_add(file.code.len())
            .ok_or(GateError::InputContract)?;
        let hash = format!("{:x}", Sha256::digest(file.code.as_bytes()));
        if !relative_file(&file.path)
            || !paths.insert(file.path.as_str())
            || file.code.contains('\0')
            || file.sha256 != hash
            || file.line_count != file.code.split('\n').count()
            || bytes > SOURCE_BYTES
        {
            return Err(GateError::InputContract);
        }
    }
    Ok(())
}

pub fn parse_result(bytes: &[u8], request: &ReviewRequest) -> Result<ReviewResult, GateError> {
    if bytes.len() > FRAME_BYTES {
        return Err(GateError::OutputContract);
    }
    let result: ReviewResult =
        serde_json::from_slice(bytes).map_err(|_| GateError::OutputContract)?;
    if !bounded_text(&result.summary, 4000) || result.notes.len() > 20 {
        return Err(GateError::OutputContract);
    }
    for note in &result.notes {
        let file = request.files.iter().find(|file| file.path == note.path);
        if !file.is_some_and(|file| note.line > 0 && note.line <= file.line_count)
            || !matches!(
                note.kind.as_str(),
                "correctness" | "maintainability" | "hardening"
            )
            || !bounded_text(&note.message, 2000)
            || !bounded_text(&note.recommendation, 2000)
        {
            return Err(GateError::OutputContract);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn request() -> serde_json::Value {
        let code = "export const label = 'inert';\n";
        json!({
            "version": 1,
            "instruction": REVIEW_INSTRUCTION.trim_end_matches('\n'),
            "files": [{
                "path": "sample.mjs",
                "sha256": format!("{:x}", Sha256::digest(code.as_bytes())),
                "lineCount": 2,
                "code": code
            }]
        })
    }

    #[test]
    fn accepts_only_the_fixed_bounded_source_contract() {
        let input = request();
        let parsed = parse_request(&serde_json::to_vec(&input).unwrap()).unwrap();
        assert_eq!(parsed.files.len(), 1);
        for field in [
            "command",
            "url",
            "model",
            "provider",
            "resume",
            "credentials",
        ] {
            let mut extra = input.clone();
            extra[field] = json!("not a permitted field");
            assert!(parse_request(&serde_json::to_vec(&extra).unwrap()).is_err());
        }
    }

    #[test]
    fn rejects_wrong_policy_hash_paths_counts_and_budgets() {
        for path in ["../outside", "/absolute", "a\\b", "a:b", "a//b", ""] {
            let mut input = request();
            input["files"][0]["path"] = json!(path);
            assert!(parse_request(&serde_json::to_vec(&input).unwrap()).is_err());
        }
        for (field, value) in [
            ("sha256", json!("wrong hash")),
            ("lineCount", json!(1)),
            ("code", json!("\0")),
        ] {
            let mut input = request();
            input["files"][0][field] = value;
            assert!(parse_request(&serde_json::to_vec(&input).unwrap()).is_err());
        }
        let mut input = request();
        input["instruction"] = json!("different instructions");
        assert!(parse_request(&serde_json::to_vec(&input).unwrap()).is_err());
        assert!(parse_request(&vec![b' '; FRAME_BYTES + 1]).is_err());
        let mut input = request();
        input["files"] = json!([input["files"][0].clone(), input["files"][0].clone()]);
        assert!(parse_request(&serde_json::to_vec(&input).unwrap()).is_err());
    }

    #[test]
    fn result_citations_and_fields_remain_data_only() {
        let input = parse_request(&serde_json::to_vec(&request()).unwrap()).unwrap();
        let result = json!({"summary":"Inert static review.","notes":[]});
        assert!(parse_result(&serde_json::to_vec(&result).unwrap(), &input).is_ok());
        for field in ["command", "poc", "attack", "tool_use"] {
            let mut extra = result.clone();
            extra[field] = json!("not a permitted field");
            assert!(parse_result(&serde_json::to_vec(&extra).unwrap(), &input).is_err());
        }
        let bad = json!({"summary":"Inert.","notes":[{
            "path":"outside.mjs","line":1,"kind":"hardening",
            "message":"Inert.","recommendation":"Inert."
        }]});
        assert!(parse_result(&serde_json::to_vec(&bad).unwrap(), &input).is_err());
    }
}
