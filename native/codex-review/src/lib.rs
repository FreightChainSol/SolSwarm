//! Fixed review-only native embedding; harness admission remains separately gated.
pub mod contract;
pub mod policy;
pub mod runtime;
pub mod runtime_config;

pub const SOURCE_COMMIT: &str = "092d3acd6bec3e3a14bdc7e7a2810ab628ab759d";
pub const FRAME_BYTES: usize = 512 * 1024;
pub const SOURCE_BYTES: usize = 64 * 1024;
pub const REVIEW_INSTRUCTION: &str = include_str!("../review-instruction.txt");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateError {
    InputContract,
    OutputContract,
    StartupPolicy,
    Configuration,
    Authentication,
    Runtime,
    ExecutionEvent,
    Deadline,
}

impl GateError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InputContract => "native_input_contract_rejected",
            Self::OutputContract => "native_output_contract_rejected",
            Self::StartupPolicy => "native_startup_policy_incompatible",
            Self::Configuration => "native_configuration_rejected",
            Self::Authentication => "native_subscription_auth_required",
            Self::Runtime => "native_runtime_failed",
            Self::ExecutionEvent => "native_execution_event_rejected",
            Self::Deadline => "native_deadline_exceeded",
        }
    }
}
