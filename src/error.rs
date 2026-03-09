//! Error types for the sigshare library.
//!
//! [`Error`] is the single error type for all fallible operations —
//! HTTP transport, discovery validation, JSON serialization, and SET
//! construction.

use thiserror::Error;

/// Unified error type for the sigshare library.
///
/// Covers HTTP transport failures, SSF protocol violations, and
/// SET building/serialization errors.
#[derive(Debug, Error)]
pub enum Error {
    /// An HTTP request failed at the transport level (DNS, TLS, timeout, etc.).
    #[error("HTTP request failed: {0}")]
    Http(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The transmitter returned a non-success HTTP status code.
    #[error("HTTP {status}: {body}")]
    HttpStatus {
        /// HTTP status code (e.g. `401`, `404`, `500`).
        status: u16,
        /// Response body, typically a JSON error object or plain text.
        body: String,
    },

    /// Failed to construct the underlying HTTP client.
    ///
    /// Only available when the `reqwest` feature is enabled.
    #[error("failed to build HTTP client: {0}")]
    #[cfg(feature = "reqwest")]
    HttpClient(#[source] reqwest::Error),

    /// The issuer URL could not be parsed or is not a valid HTTPS URL
    /// as required by SSF §7.2.
    #[error("invalid issuer URL: {0}")]
    InvalidIssuerUrl(String),

    /// The `issuer` field in the transmitter's discovery response does
    /// not match the issuer URL used to fetch it, violating SSF §7.2.4.
    #[error("issuer mismatch: expected `{expected}`, got `{got}`")]
    IssuerMismatch {
        /// The issuer URL that was used for discovery.
        expected: String,
        /// The `issuer` value returned in the transmitter configuration.
        got: String,
    },

    /// The cached [`crate::ssf::TransmitterConfiguration`] does not
    /// advertise a required endpoint (e.g. `configuration_endpoint`).
    #[error("transmitter config missing required endpoint: {0}")]
    MissingEndpoint(&'static str),

    /// [`crate::SsfClient::discover`] has not been called for this issuer,
    /// so endpoint URLs cannot be resolved.
    #[error("issuer not cached: {0}")]
    NotCached(String),

    /// The transmitter returned a response body that could not be
    /// deserialized into the expected type.
    #[error("invalid response: {0}")]
    InvalidResponse(#[source] serde_json::Error),

    /// Failed to serialize a request body to JSON.
    #[error("serialization error: {0}")]
    Serialization(#[source] serde_json::Error),

    /// A required field was not set on
    /// [`crate::SecurityEventTokenBuilder`].
    ///
    /// The field name matches the JWT claim (e.g. `"iss"`, `"iat"`,
    /// `"jti"`, `"events"`).
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// The SET builder received two events with the same event type URI.
    ///
    /// [RFC 8417] requires each key in the `events` object to be unique.
    ///
    /// [RFC 8417]: https://www.rfc-editor.org/rfc/rfc8417
    #[error("duplicate event URI: {0}")]
    DuplicateEventUri(String),
}

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
