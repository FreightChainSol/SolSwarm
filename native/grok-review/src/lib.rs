//! Review-only sampler foundation. Authentication and runtime admission are separate gates.
pub mod contract;
pub mod config;
pub mod runtime;
pub mod routing;
pub use xai_grok_sampler::client::freightchain_review_error::Diagnostic as ProviderDiagnostic;

pub const SOURCE_COMMIT: &str = "2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8";
pub const SOURCE_REVISION: &str = "559751fdcec02d413e4c57c8832ab275e4f44980";
pub const FRAME_BYTES: usize = 512 * 1024;
pub const SOURCE_BYTES: usize = 64 * 1024;
pub const REVIEW_INSTRUCTION: &str = include_str!("../review-instruction.txt");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateError {
    InputContract,
    OutputContract,
    Configuration,
    Authentication,
    Runtime,
    ExecutionEvent,
    Deadline,
    ProviderStatus(u16),
    ProviderTransport,
    ProviderProtocol,
    ProviderStream,
    ProviderClassified(u16, ProviderDiagnostic),
}

impl GateError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InputContract => "grok_input_contract_rejected",
            Self::OutputContract => "grok_output_contract_rejected",
            Self::Configuration => "grok_configuration_rejected",
            Self::Authentication => "grok_subscription_auth_required",
            Self::Runtime => "grok_runtime_failed",
            Self::ExecutionEvent => "grok_execution_event_rejected",
            Self::Deadline => "grok_deadline_exceeded",
            Self::ProviderStatus(400) => "grok_provider_http_400",
            Self::ProviderStatus(401) => "grok_provider_http_401",
            Self::ProviderStatus(403) => "grok_provider_http_403",
            Self::ProviderStatus(404) => "grok_provider_http_404",
            Self::ProviderStatus(409) => "grok_provider_http_409",
            Self::ProviderStatus(413) => "grok_provider_http_413",
            Self::ProviderStatus(422) => "grok_provider_http_422",
            Self::ProviderStatus(429) => "grok_provider_http_429",
            Self::ProviderStatus(500..=599) => "grok_provider_unavailable",
            Self::ProviderStatus(_) => "grok_provider_http_rejected",
            Self::ProviderTransport => "grok_provider_transport_failed",
            Self::ProviderProtocol => "grok_provider_protocol_rejected",
            Self::ProviderStream => "grok_provider_stream_rejected",
            Self::ProviderClassified(status, _) => Self::ProviderStatus(status).code(),
        }
    }

    pub fn diagnostic(self) -> Option<ProviderDiagnostic> {
        match self { Self::ProviderClassified(_, diagnostic) => Some(diagnostic), _ => None }
    }
}
