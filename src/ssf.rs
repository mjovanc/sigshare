use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::subject::SubjectIdentifier;

pub const PUSH_DELIVERY_METHOD: &str = "urn:ietf:rfc:8935";
pub const POLL_DELIVERY_METHOD: &str = "urn:ietf:rfc:8936";

pub const VERIFICATION_EVENT_URI: &str = "https://schemas.openid.net/secevent/ssf/event-type/verification";

pub const STREAM_UPDATED_EVENT_URI: &str = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum DeliveryConfig {
    #[serde(rename = "urn:ietf:rfc:8935")]
    Push {
        endpoint_url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        authorization_header: Option<String>,
    },
    #[serde(rename = "urn:ietf:rfc:8936")]
    Poll {
        #[serde(skip_serializing_if = "Option::is_none")]
        endpoint_url: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamStatus {
    Enabled,
    Paused,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamConfiguration {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events_requested: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events_delivered: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery: Option<DeliveryConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_verification_interval: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inactivity_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamStatusResponse {
    pub stream_id: String,
    pub status: StreamStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamStatusUpdate {
    pub stream_id: String,
    pub status: StreamStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AddSubjectRequest {
    pub stream_id: String,
    pub subject: SubjectIdentifier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoveSubjectRequest {
    pub stream_id: String,
    pub subject: SubjectIdentifier,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationRequest {
    pub stream_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamUpdatedEvent {
    pub status: StreamStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SetError {
    pub err: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct PollRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ack: Vec<String>,
    #[serde(rename = "setErrs", default, skip_serializing_if = "BTreeMap::is_empty")]
    pub set_errs: BTreeMap<String, SetError>,
    #[serde(rename = "returnImmediately", skip_serializing_if = "Option::is_none")]
    pub return_immediately: Option<bool>,
    #[serde(rename = "maxEvents", skip_serializing_if = "Option::is_none")]
    pub max_events: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PollResponse {
    pub sets: BTreeMap<String, String>,
    #[serde(rename = "moreAvailable", skip_serializing_if = "Option::is_none")]
    pub more_available: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationScheme {
    pub spec_urn: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefaultSubjects {
    #[serde(rename = "ALL")]
    All,
    #[serde(rename = "NONE")]
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransmitterConfiguration {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_version: Option<String>,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_methods_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add_subject_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remove_subject_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub critical_subject_members: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_schemes: Option<Vec<AuthorizationScheme>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_subjects: Option<DefaultSubjects>,
}
