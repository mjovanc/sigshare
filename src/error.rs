use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigshareError {
    #[error("missing required field: {field}")]
    MissingField { field: &'static str },

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("duplicate event URI: {uri}")]
    DuplicateEventUri { uri: String },
}
