use thiserror::Error;

#[derive(Error, Debug)]
pub enum AgentError{
    #[error("Failed to load eBPF: {0}")]
    BpfLoadError(#[from] aya::BpfError),

    #[error("Failed to attach program '{program}': {source}")]
    BpfAttachError{
        program: String,
        #[source]
        source: aya::programs::ProgramError,
    },

    #[error("Program '{name}' not found in BPF object")]
    ProgramNotFound { name: String },

    #[error("Failed to read ring buffer: {0}")]
    RingBufError(#[from] aya::maps::ring_buf::RingBufError),

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Failed to send event to backend: {0}")]
    BackendError(String),

    #[error("Invalid event data: {0}")]
    InvalidEventData(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, AgentError>;