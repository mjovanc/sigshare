//! [SSF 1.0] stream management, delivery configuration, and transmitter metadata.
//!
//! This module covers the operational layer of the Shared Signals Framework:
//! creating and managing event streams, configuring push ([RFC 8935]) and poll
//! ([RFC 8936]) delivery, discovering transmitter capabilities, and handling
//! verification and stream-updated events.
//!
//! # Stream lifecycle
//!
//! | Operation | Struct |
//! |-----------|--------|
//! | Create / read / update stream | [`StreamConfiguration`] |
//! | Read stream status | [`StreamStatusResponse`] |
//! | Update stream status | [`StreamStatusUpdate`] |
//! | Add a subject to a stream | [`AddSubjectRequest`] |
//! | Remove a subject from a stream | [`RemoveSubjectRequest`] |
//! | Request a verification event | [`VerificationRequest`] |
//!
//! # Delivery
//!
//! | Method | Struct variant | RFC |
//! |--------|---------------|-----|
//! | Push | [`DeliveryConfig::Push`] | [RFC 8935] |
//! | Poll | [`DeliveryConfig::Poll`] | [RFC 8936] |
//!
//! Poll-based receivers use [`PollRequest`] / [`PollResponse`] to fetch and
//! acknowledge SETs.
//!
//! # SSF-defined events
//!
//! | Event | URI constant | Struct |
//! |-------|-------------|--------|
//! | Verification | [`VERIFICATION_EVENT_URI`] | [`VerificationEvent`] |
//! | Stream Updated | [`STREAM_UPDATED_EVENT_URI`] | [`StreamUpdatedEvent`] |
//!
//! # Transmitter discovery
//!
//! [`TransmitterConfiguration`] models the JSON document returned by a
//! transmitter's `/.well-known/ssf-configuration` endpoint.
//!
//! [SSF 1.0]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html
//! [RFC 8935]: https://www.rfc-editor.org/rfc/rfc8935
//! [RFC 8936]: https://www.rfc-editor.org/rfc/rfc8936

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::subject::SubjectIdentifier;

/// Delivery method URN for SET push delivery per [RFC 8935].
///
/// [RFC 8935]: https://www.rfc-editor.org/rfc/rfc8935
pub const PUSH_DELIVERY_METHOD: &str = "urn:ietf:rfc:8935";

/// Delivery method URN for SET poll delivery per [RFC 8936].
///
/// [RFC 8936]: https://www.rfc-editor.org/rfc/rfc8936
pub const POLL_DELIVERY_METHOD: &str = "urn:ietf:rfc:8936";

/// Schema URI for the SSF verification event ([SSF §8.1.4]).
///
/// [SSF §8.1.4]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4
pub const VERIFICATION_EVENT_URI: &str = "https://schemas.openid.net/secevent/ssf/event-type/verification";

/// Schema URI for the SSF stream-updated event ([SSF §8.1.5]).
///
/// [SSF §8.1.5]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.5
pub const STREAM_UPDATED_EVENT_URI: &str = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated";

/// Delivery method configuration for a stream ([SSF §6.1]).
///
/// Serialized with an internally-tagged `"method"` discriminator whose
/// value is the delivery method URN.
///
/// [SSF §6.1]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-6.1
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum DeliveryConfig {
    /// Push delivery per [RFC 8935](https://www.rfc-editor.org/rfc/rfc8935).
    ///
    /// The transmitter POSTs SETs to the receiver's `endpoint_url`.
    #[serde(rename = "urn:ietf:rfc:8935")]
    Push {
        /// The URL to which the transmitter will POST SETs.
        endpoint_url: String,
        /// An optional `Authorization` header value the transmitter should
        /// include when delivering SETs.
        #[serde(skip_serializing_if = "Option::is_none")]
        authorization_header: Option<String>,
    },
    /// Poll delivery per [RFC 8936](https://www.rfc-editor.org/rfc/rfc8936).
    ///
    /// The receiver polls the transmitter's endpoint to retrieve queued SETs.
    #[serde(rename = "urn:ietf:rfc:8936")]
    Poll {
        /// The URL the receiver should poll. The transmitter may provide this
        /// in the stream configuration response.
        #[serde(skip_serializing_if = "Option::is_none")]
        endpoint_url: Option<String>,
    },
}

/// The operational status of an event stream ([SSF §8.1.2]).
///
/// [SSF §8.1.2]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamStatus {
    /// The stream is active and events are being delivered.
    Enabled,
    /// The stream is temporarily paused; events are queued but not delivered.
    Paused,
    /// The stream is disabled; events may be dropped.
    Disabled,
}

/// Configuration of an event stream ([SSF §8.1.1]).
///
/// Used for both creating new streams (request body) and reading existing
/// stream configuration (response body). All fields are optional because
/// the transmitter and receiver populate different subsets.
///
/// [SSF §8.1.1]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamConfiguration {
    /// Transmitter-assigned stream identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    /// The issuer (`iss` claim) for SETs on this stream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// The audience(s) (`aud` claim) for SETs on this stream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    /// Event type URIs supported by the transmitter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events_supported: Option<Vec<String>>,
    /// Event type URIs requested by the receiver.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events_requested: Option<Vec<String>>,
    /// Event type URIs actually being delivered on this stream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events_delivered: Option<Vec<String>>,
    /// The delivery configuration (push or poll).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery: Option<DeliveryConfig>,
    /// Minimum interval (in seconds) between verification events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_verification_interval: Option<u64>,
    /// Duration (in seconds) after which the transmitter considers the stream inactive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inactivity_timeout: Option<u64>,
    /// Human-readable description of the stream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Response to a stream status read request ([SSF §8.1.2]).
///
/// [SSF §8.1.2]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamStatusResponse {
    /// The stream this status applies to.
    pub stream_id: String,
    /// The current status of the stream.
    pub status: StreamStatus,
    /// An optional human-readable reason for the current status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Request to update a stream's status ([SSF §8.1.2]).
///
/// [SSF §8.1.2]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamStatusUpdate {
    /// The stream to update.
    pub stream_id: String,
    /// The desired new status.
    pub status: StreamStatus,
    /// An optional human-readable reason for the status change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Request to add a subject to a stream ([SSF §8.1.3]).
///
/// [SSF §8.1.3]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.3
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AddSubjectRequest {
    /// The stream to add the subject to.
    pub stream_id: String,
    /// The subject identifier to add.
    pub subject: SubjectIdentifier,
    /// Whether the receiver has verified the subject (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
}

/// Request to remove a subject from a stream ([SSF §8.1.3]).
///
/// [SSF §8.1.3]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.3
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoveSubjectRequest {
    /// The stream to remove the subject from.
    pub stream_id: String,
    /// The subject identifier to remove.
    pub subject: SubjectIdentifier,
}

/// Request to trigger a verification event on a stream ([SSF §8.1.4]).
///
/// [SSF §8.1.4]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationRequest {
    /// The stream to verify.
    pub stream_id: String,
    /// An opaque value that the transmitter echoes back in the verification event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// Payload of a verification event ([SSF §8.1.4]).
///
/// Carried inside a SET under the [`VERIFICATION_EVENT_URI`] key.
/// The `state` value, if present, must match the value from the
/// corresponding [`VerificationRequest`].
///
/// [SSF §8.1.4]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationEvent {
    /// The opaque state value echoed from the verification request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// Payload of a stream-updated event ([SSF §8.1.5]).
///
/// Carried inside a SET under the [`STREAM_UPDATED_EVENT_URI`] key.
/// Notifies the receiver that the transmitter has changed the stream's status.
///
/// [SSF §8.1.5]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.5
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamUpdatedEvent {
    /// The new status of the stream.
    pub status: StreamStatus,
    /// An optional human-readable reason for the status change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// An error reported by the receiver for a specific SET in a poll response ([RFC 8936 §2]).
///
/// Used in the `setErrs` field of [`PollRequest`] to report errors
/// for individual SETs that could not be processed.
///
/// [RFC 8936 §2]: https://www.rfc-editor.org/rfc/rfc8936#section-2
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SetError {
    /// An error code string (e.g. `"invalid_request"`, `"access_denied"`).
    pub err: String,
    /// An optional human-readable error description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A poll request sent by the receiver to fetch and acknowledge SETs ([RFC 8936 §2]).
///
/// [RFC 8936 §2]: https://www.rfc-editor.org/rfc/rfc8936#section-2
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct PollRequest {
    /// JTIs of SETs the receiver has successfully processed (acknowledgements).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ack: Vec<String>,
    /// Errors for SETs the receiver could not process, keyed by JTI.
    #[serde(rename = "setErrs", default, skip_serializing_if = "BTreeMap::is_empty")]
    pub set_errs: BTreeMap<String, SetError>,
    /// If `true`, the transmitter should return immediately even if no SETs
    /// are available. If `false` or absent, the transmitter may use long polling.
    #[serde(rename = "returnImmediately", skip_serializing_if = "Option::is_none")]
    pub return_immediately: Option<bool>,
    /// Maximum number of SETs to return in the response.
    #[serde(rename = "maxEvents", skip_serializing_if = "Option::is_none")]
    pub max_events: Option<u32>,
}

/// A poll response from the transmitter containing queued SETs ([RFC 8936 §2]).
///
/// [RFC 8936 §2]: https://www.rfc-editor.org/rfc/rfc8936#section-2
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PollResponse {
    /// Queued SETs, keyed by JTI. Each value is a compact-serialized JWT (or
    /// unsigned JSON SET depending on the stream configuration).
    pub sets: BTreeMap<String, String>,
    /// If `true`, additional SETs are available and the receiver should poll again.
    #[serde(rename = "moreAvailable", skip_serializing_if = "Option::is_none")]
    pub more_available: Option<bool>,
}

/// An authorization scheme supported by a transmitter ([SSF §7.1.1]).
///
/// [SSF §7.1.1]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1.1
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationScheme {
    /// The specification URN identifying the authorization scheme.
    pub spec_urn: String,
}

/// Default subject population for a stream ([SSF §7.1]).
///
/// Indicates whether the transmitter includes all subjects by default
/// or requires subjects to be explicitly added.
///
/// [SSF §7.1]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefaultSubjects {
    /// All subjects are included in the stream by default.
    #[serde(rename = "ALL")]
    All,
    /// No subjects are included by default; they must be added explicitly.
    #[serde(rename = "NONE")]
    None,
}

/// Transmitter metadata returned by the `/.well-known/ssf-configuration`
/// discovery endpoint ([SSF §7.1]).
///
/// This document allows receivers to discover a transmitter's capabilities,
/// supported delivery methods, and management endpoints.
///
/// [SSF §7.1]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransmitterConfiguration {
    /// The SSF specification version (e.g. `"1_0"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_version: Option<String>,
    /// The transmitter's issuer identifier.
    pub issuer: String,
    /// URL of the transmitter's JWK Set document for SET signature verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// Delivery method URNs the transmitter supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_methods_supported: Option<Vec<String>>,
    /// URL of the stream configuration endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration_endpoint: Option<String>,
    /// URL of the stream status endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_endpoint: Option<String>,
    /// URL of the add-subject endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add_subject_endpoint: Option<String>,
    /// URL of the remove-subject endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remove_subject_endpoint: Option<String>,
    /// URL of the verification endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_endpoint: Option<String>,
    /// Subject members that the transmitter considers critical for complex subjects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub critical_subject_members: Option<Vec<String>>,
    /// Authorization schemes the transmitter supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_schemes: Option<Vec<AuthorizationScheme>>,
    /// Whether the transmitter includes all subjects by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_subjects: Option<DefaultSubjects>,
}
