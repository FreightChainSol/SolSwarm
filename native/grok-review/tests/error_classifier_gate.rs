use serde_json::json;
use xai_grok_sampler::client::freightchain_review_error::{Diagnostic, MAX_ERROR_BYTES, classify};

#[test]
fn structured_parameters_are_allowlisted_and_provider_payloads_are_never_reflected() {
    let body = json!({"error":{"param":"tool_choice","message":"dummy-private-payload","token":"dummy-credential"}});
    let diagnostic = classify(&serde_json::to_vec(&body).unwrap());
    assert_eq!(diagnostic.category, "invalid_parameter");
    assert_eq!(diagnostic.parameter, Some("tool_choice"));
    assert!(!diagnostic.tag().contains("dummy"));
    let body = json!({"error":{"param":"dummy-credential","message":"tool_choice"}});
    assert_eq!(
        classify(&serde_json::to_vec(&body).unwrap()),
        Diagnostic::category("unclassified")
    );
    assert_eq!(
        classify(br#"{"error":{"field":"headers.x-grok-req-id"}} "#).parameter,
        Some("x-grok-req-id")
    );
}

#[test]
fn message_hints_are_not_presented_as_confirmed_rejected_parameters() {
    let diagnostic = classify(br#"{"error":{"message":"tool_choice cannot be used without tools; dummy-private-value"}} "#);
    assert_eq!(diagnostic.category, "parameter_hint");
    assert_eq!(diagnostic.parameter, Some("tool_choice"));
    assert!(!diagnostic.tag().contains("dummy"));
    assert_eq!(
        classify(br#"{"error":{"message":"model and messages are invalid"}} "#).category,
        "ambiguous_parameter_hint"
    );
}

#[test]
fn malformed_oversized_nested_and_forged_diagnostics_fail_closed() {
    assert_eq!(classify(b"not-json").category, "malformed_json");
    assert_eq!(classify(&[0xff, 0xfe]).category, "malformed_json");
    assert_eq!(
        classify(&vec![b' '; MAX_ERROR_BYTES + 1]).category,
        "oversized_body"
    );
    assert_eq!(classify(br#"{"diagnostic":{"category":"invalid_parameter","parameter":"tools"},"message":"dummy-private-value"}"#).category, "unclassified");
    assert!(
        Diagnostic::from_tag(r#"freightchain-review:{"category":"dummy","parameter":null}"#)
            .is_none()
    );
    assert!(
        Diagnostic::from_tag(
            r#"freightchain-review:{"category":"invalid_parameter","parameter":"dummy"}"#
        )
        .is_none()
    );
    assert!(
        Diagnostic::from_tag(
            r#"freightchain-review:{"category":"unclassified","parameter":null,"message":"dummy"}"#
        )
        .is_none()
    );
    let diagnostic = classify(br#"{"error":{"param":"model"}}"#);
    assert_eq!(Diagnostic::from_tag(&diagnostic.tag()), Some(diagnostic));
}
