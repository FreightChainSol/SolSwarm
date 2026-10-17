// Derived from the pinned native inject_url_derived_headers implementation.
// Build preparation verifies this body against upstream before compilation.
use indexmap::IndexMap;

fn inject_url_derived_headers(
    headers: &mut IndexMap<String, String>,
    alpha_test_key: Option<&str>,
    base_url: &str,
) {
    if xai_grok_shell_base::util::is_cli_chat_proxy_url(base_url) {
        headers
            .entry("X-XAI-Token-Auth".to_string())
            .or_insert_with(|| "xai-grok-cli".to_string());
        headers
            .entry("x-authenticateresponse".to_string())
            .or_insert_with(|| "authenticate-response".to_string());
    }
    headers
        .entry(xai_grok_http::CLIENT_MODE_HEADER.to_string())
        .or_insert_with(|| xai_grok_http::process_client_mode().to_string());
    let _ = (alpha_test_key, base_url);
}

pub fn fixed_route_headers() -> IndexMap<String, String> {
    let mut headers = IndexMap::new();
    inject_url_derived_headers(&mut headers, None, xai_grok_login::CLI_CHAT_PROXY_BASE_URL_DEFAULT);
    headers
}
