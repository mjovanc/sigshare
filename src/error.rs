//! Error types for the sigshare library.

use thiserror::Error;

/// Errors that can occur when building, serializing, or deserializing SETs.
#[derive(Debug, Error)]
pub enum SigshareError {
    /// A required field was not provided to the builder, or was absent during
    /// deserialization. The `field` name matches the JWT claim name
    /// (e.g. `"iss"`, `"iat"`, `"jti"`, `"events"`).
    #[error("missing required field: {field}")]
    MissingField { field: &'static str },

    /// A JSON serialization or deserialization error from `serde_json`.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// The builder was given two events with the same event type URI.
    /// RFC 8417 requires each event URI key in the `events` object to be unique.
    #[error("duplicate event URI: {uri}")]
    DuplicateEventUri { uri: String },
}
