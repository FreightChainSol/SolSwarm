// Every adaptation is narrowly anchored against the immutable public snapshot.
const replaceOnce = (source, before, after) => {
  if(source.split(before).length!==2)throw new Error('grok_overlay_anchor_changed');
  return source.replace(before,after);
};
export const LOGIN_MANAGER = 'crates/codegen/xai-grok-login/src/manager.rs';
export const LOGIN_RESOLVER = 'crates/codegen/xai-grok-login/src/credential_provider.rs';
export const SAMPLER_CLIENT = 'crates/codegen/xai-grok-sampler/src/client.rs';
export const ROUTING = 'crates/codegen/xai-grok-shell/src/agent/config.rs';
export const AUTH_MODULE = 'crates/codegen/xai-grok-login/src/manager/text_review.rs';
export const LOGIN_CONFIG = 'crates/codegen/xai-grok-login/src/config.rs';
export const CONFIG_LIB = 'crates/codegen/xai-grok-config/src/lib.rs';
export const MDM = 'crates/codegen/xai-grok-config/src/macos_managed.rs';
export const ERROR_MODULE = 'crates/codegen/xai-grok-sampler/src/review_error.rs';

export function overlaySource(name, source) {
  return '// Modified by Freight Chain for bounded text review; see freightchain-review/NOTICE.\n'+transformSource(name,source);
}

function transformSource(name, source) {
  if(name===LOGIN_CONFIG){
    return `${source}\n// Freight Chain: apply one already-validated snapshot without implicit disk reads.\nimpl GrokComConfig {\n    pub fn from_text_review_snapshot(value: &toml::Value) -> Result<Self, toml::de::Error> {\n        let expanded = expand_auth_alias(value);\n        let mut config = match expanded.get("grok_com_config") {\n            Some(section) => GrokComConfigSection::deserialize(section.clone())?.merge_over(Self::default())?,\n            None => Self::default(),\n        };\n        config.force_login_team_uuid = resolve_force_login_team(None, force_login_team_from_env(), config.force_login_team_uuid.take());\n        Ok(config)\n    }\n}\n`;
  }
  if(name===CONFIG_LIB){
    return `${source}\n// Freight Chain: forced MDM is unsupported by the initial bounded profile.\npub fn freightchain_text_review_mdm_present() -> bool {\n    macos_managed::text_review_forced_policy_present()\n}\n`;
  }
  if(name===MDM){
    return `${source}\n// Freight Chain: inspect only the forced bit, never coerce malformed policy to absent.\n#[cfg(target_os = "macos")]\npub(crate) fn text_review_forced_policy_present() -> bool {\n    use core_foundation::base::TCFType;\n    use core_foundation::string::{CFString, CFStringRef};\n    #[link(name = "CoreFoundation", kind = "framework")]\n    unsafe extern "C" { fn CFPreferencesAppValueIsForced(key: CFStringRef, application_id: CFStringRef) -> u8; }\n    let key = CFString::new(REQUIREMENTS_KEY);\n    let app = CFString::new(MANAGED_PREFERENCES_DOMAIN);\n    unsafe { CFPreferencesAppValueIsForced(key.as_concrete_TypeRef(), app.as_concrete_TypeRef()) != 0 }\n}\n#[cfg(not(target_os = "macos"))]\npub(crate) fn text_review_forced_policy_present() -> bool { false }\n`;
  }
  if(name===LOGIN_MANAGER){
    source=replaceOnce(source,'pub struct AuthManager {\n','pub struct AuthManager {\n    text_review_cached_only: bool,\n');
    source=replaceOnce(source,'            inner: RwLock::new(inner),','            text_review_cached_only: false,\n            inner: RwLock::new(inner),');
    return `${source}\n// Freight Chain cached-only review adaptation; see retained overlay notice.\n#[path = "manager/text_review.rs"]\nmod text_review;\n`;
  }
  if(name===LOGIN_RESOLVER){
    return replaceOnce(source,
      '        Box::pin(async move {\n            if !ActiveAuthBackend::default().is_xai_authority() {',
      '        Box::pin(async move {\n            if self.0.is_text_review_cached_only() {\n                return;\n            }\n            if !ActiveAuthBackend::default().is_xai_authority() {');
  }
  if(name===ROUTING){
    return `${source}\n// Freight Chain fixed-route facade: no arbitrary headers, URLs or auth values.\npub fn freightchain_text_review_headers() -> IndexMap<String, String> {\n    let mut headers = IndexMap::new();\n    inject_url_derived_headers(&mut headers, None, xai_grok_login::CLI_CHAT_PROXY_BASE_URL_DEFAULT);\n    headers\n}\n`;
  }
  if(name===SAMPLER_CLIENT){
    // A missing resolver credential must fail before sending, not retry anonymously.
    source=replaceOnce(source,
      '    fn post(&self, url: impl reqwest::IntoUrl) -> SentRequest {',
      '    fn post(&self, url: impl reqwest::IntoUrl) -> Result<SentRequest> {');
    source=replaceOnce(source,
      '        {\n            let auth_prefix = headers',
      '        if self.bearer_resolver.is_some()\n            && !headers.contains_key(AUTHORIZATION)\n            && !headers.contains_key(HeaderName::from_static("x-api-key"))\n        {\n            return Err(SamplingError::auth_unknown("review credential unavailable"));\n        }\n        {\n            let auth_prefix = headers');
    source=replaceOnce(source,
      '        SentRequest {\n            builder: self.http.post(url).headers(headers),\n            sent_bearer,\n        }\n',
      '        Ok(SentRequest {\n            builder: self.http.post(url).headers(headers),\n            sent_bearer,\n        })\n');
    // All pinned call sites have a single-line expression.
    const calls=[...source.matchAll(/self\.post\(([^\n]+)\);/g)];
    if(calls.length!==6)throw new Error('grok_sampler_post_shape_changed');
    source=source.replace(/self\.post\(([^\n]+)\);/g,'self.post($1)?;');
    const method=source.indexOf('    async fn chat_completion_stream_inner(');
    const errorStart=source.indexOf('        if !status.is_success() {',method);
    const errorEnd=source.indexOf('        // Strip UTF-8 BOM if present:',errorStart);
    if(method<0||errorStart<0||errorEnd<0)throw new Error('grok_sampler_error_shape_changed');
    // Bounded in-memory classification only; no provider text or header logging.
    source=source.slice(0,errorStart)
      +'        if !status.is_success() {\n'
      +'            use freightchain_review_error::{Diagnostic, MAX_ERROR_BYTES};\n'
      +'            let diagnostic = if response.content_length().is_some_and(|size| size > MAX_ERROR_BYTES as u64) {\n'
      +'                Diagnostic::category("oversized_body")\n'
      +'            } else {\n'
      +'                let read = async {\n'
      +'                    let mut response = response;\n'
      +'                    let mut bytes = Vec::new();\n'
      +'                    loop {\n'
      +'                        match response.chunk().await {\n'
      +'                            Ok(Some(chunk)) => {\n'
      +'                                if bytes.len().saturating_add(chunk.len()) > MAX_ERROR_BYTES {\n'
      +'                                    return Diagnostic::category("oversized_body");\n'
      +'                                }\n'
      +'                                bytes.extend_from_slice(&chunk);\n'
      +'                            }\n'
      +'                            Ok(None) => return freightchain_review_error::classify(&bytes),\n'
      +'                            Err(_) => return Diagnostic::category("body_unavailable"),\n'
      +'                        }\n'
      +'                    }\n'
      +'                };\n'
      +'                match tokio::time::timeout(std::time::Duration::from_secs(2), read).await {\n'
      +'                    Ok(diagnostic) => diagnostic,\n'
      +'                    Err(_) => Diagnostic::category("body_timeout"),\n'
      +'                }\n'
      +'            };\n'
      +'            return Err(SamplingError::Api {\n'
      +'                status,\n'
      +'                message: "review provider request rejected".to_owned(),\n'
      +'                model_metadata,\n'
      +'                retry_after_secs,\n'
      +'                should_retry,\n'
      +'                error_code: Some(xai_grok_sampling_types::ApiErrorCode::parse(&diagnostic.tag())),\n'
      +'            });\n'
      +'        }\n\n'
      +source.slice(errorEnd);
    // The wire byte budget precedes SSE decoding, including reasoning frames.
    const anchor='        let byte_stream = response.bytes_stream().map(move |result| {';
    if(source.split(anchor).length!==4)throw new Error('grok_sampler_stream_shape_changed');
    return source.split(anchor).join(
      '        let byte_stream = response.bytes_stream().scan(0_usize, |total, result| {\n'
      +'            let result = result.map_err(std::io::Error::other).and_then(|bytes| {\n'
      +'                *total = total.saturating_add(bytes.len());\n'
      +'                if *total > 2 * 1024 * 1024 {\n'
      +'                    Err(std::io::Error::other("review stream byte limit"))\n'
      +'                } else { Ok(bytes) }\n'
      +'            });\n'
      +'            std::future::ready(Some(result))\n'
      +'        }).map(move |result| {')
      +'\n// Freight Chain bounded error classifier; no raw diagnostic output.\n#[path = "review_error.rs"]\npub mod freightchain_review_error;\n';
  }
  throw new Error('grok_overlay_path_rejected');
}
