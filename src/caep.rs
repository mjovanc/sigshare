//! [CAEP 1.0] event types for the Continuous Access Evaluation Profile.
//!
//! This module implements all 8 event types defined by the CAEP specification,
//! which enables continuous access evaluation by signaling session, credential,
//! compliance, assurance, and risk changes in real time.
//!
//! # Event types
//!
//! | Event | URI suffix | Section | Struct |
//! |-------|-----------|---------|--------|
//! | Session Revoked | `session-revoked` | §3.1 | [`SessionRevoked`] |
//! | Token Claims Change | `token-claims-change` | §3.2 | [`TokenClaimsChange`] |
//! | Credential Change | `credential-change` | §3.3 | [`CredentialChange`] |
//! | Assurance Level Change | `assurance-level-change` | §3.4 | [`AssuranceLevelChange`] |
//! | Device Compliance Change | `device-compliance-change` | §3.5 | [`DeviceComplianceChange`] |
//! | Session Established | `session-established` | §3.6 | [`SessionEstablished`] |
//! | Session Presented | `session-presented` | §3.7 | [`SessionPresented`] |
//! | Risk Level Change | `risk-level-change` | §3.8 | [`RiskLevelChange`] |
//!
//! Every event struct contains a [`CaepCommon`] (flattened during serialization)
//! carrying the optional fields shared across all CAEP events: `initiating_entity`,
//! `reason_admin`, `reason_user`, and `event_timestamp`.
//!
//! # Wire format
//!
//! Each event is keyed by its full schema URI (e.g.
//! `https://schemas.openid.net/secevent/caep/event-type/session-revoked`) inside
//! the SET `events` object. The event payload is the JSON serialization of the
//! corresponding struct.
//!
//! [CAEP 1.0]: https://openid.net/specs/openid-caep-1_0.html

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub use crate::subject::CredentialType;

/// Fields shared by all CAEP events ([CAEP §2]).
///
/// These fields are flattened into each event struct via `#[serde(flatten)]`,
/// so they appear as top-level members of the event payload on the wire.
///
/// The `reason_admin` and `reason_user` fields are BCP 47 localized string
/// maps (`BTreeMap<String, String>`) where the key is a language tag and
/// the value is the localized message, as specified in [CAEP §2].
///
/// [CAEP §2]: https://openid.net/specs/openid-caep-1_0.html#section-2
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct CaepCommon {
    /// The entity that initiated or caused the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiating_entity: Option<InitiatingEntity>,
    /// Administrator-facing reason in BCP 47 localized form (language tag → message).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_admin: Option<BTreeMap<String, String>>,
    /// User-facing reason in BCP 47 localized form (language tag → message).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_user: Option<BTreeMap<String, String>>,
    /// UNIX timestamp (seconds since epoch) of the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_timestamp: Option<i64>,
}

/// The entity that initiated or caused a CAEP event ([CAEP §2]).
///
/// [CAEP §2]: https://openid.net/specs/openid-caep-1_0.html#section-2
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InitiatingEntity {
    /// An administrator took the action.
    Admin,
    /// The end user took the action.
    User,
    /// An automated policy triggered the action.
    Policy,
    /// The system itself triggered the action.
    System,
}

/// The type of change applied to a credential ([CAEP §3.3]).
///
/// [CAEP §3.3]: https://openid.net/specs/openid-caep-1_0.html#section-3.3
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialChangeType {
    /// A new credential was created.
    Create,
    /// An existing credential was revoked.
    Revoke,
    /// An existing credential was updated.
    Update,
    /// An existing credential was deleted.
    Delete,
}

/// Device compliance status for [`DeviceComplianceChange`] events ([CAEP §3.5]).
///
/// [CAEP §3.5]: https://openid.net/specs/openid-caep-1_0.html#section-3.5
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceStatus {
    /// The device is compliant with the required policies.
    #[serde(rename = "compliant")]
    Compliant,
    /// The device is not compliant with the required policies.
    #[serde(rename = "not-compliant")]
    NotCompliant,
}

/// Direction of an assurance level change ([CAEP §3.4]).
///
/// [CAEP §3.4]: https://openid.net/specs/openid-caep-1_0.html#section-3.4
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeDirection {
    /// The assurance level increased.
    Increase,
    /// The assurance level decreased.
    Decrease,
}

/// Risk level for [`RiskLevelChange`] events ([CAEP §3.8]).
///
/// [CAEP §3.8]: https://openid.net/specs/openid-caep-1_0.html#section-3.8
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    /// High risk.
    #[serde(rename = "HIGH")]
    High,
    /// Medium risk.
    #[serde(rename = "MEDIUM")]
    Medium,
    /// Low risk.
    #[serde(rename = "LOW")]
    Low,
}

/// The principal whose risk level changed ([CAEP §3.8]).
///
/// [CAEP §3.8]: https://openid.net/specs/openid-caep-1_0.html#section-3.8
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskPrincipal {
    /// The risk pertains to a user.
    #[serde(rename = "USER")]
    User,
    /// The risk pertains to a device.
    #[serde(rename = "DEVICE")]
    Device,
    /// The risk pertains to a session.
    #[serde(rename = "SESSION")]
    Session,
    /// The risk pertains to a tenant.
    #[serde(rename = "TENANT")]
    Tenant,
    /// The risk pertains to an organizational unit.
    #[serde(rename = "ORG_UNIT")]
    OrgUnit,
    /// The risk pertains to a group.
    #[serde(rename = "GROUP")]
    Group,
}

/// A session was revoked ([CAEP §3.1]).
///
/// Signals that a session has been revoked and the receiver should terminate
/// any associated sessions or tokens.
///
/// [CAEP §3.1]: https://openid.net/specs/openid-caep-1_0.html#section-3.1
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionRevoked {
    /// Common CAEP event fields (initiating entity, reason, timestamp).
    #[serde(flatten)]
    pub common: CaepCommon,
}

/// A credential was created, updated, revoked, or deleted ([CAEP §3.3]).
///
/// [CAEP §3.3]: https://openid.net/specs/openid-caep-1_0.html#section-3.3
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialChange {
    /// Common CAEP event fields.
    #[serde(flatten)]
    pub common: CaepCommon,
    /// The type of credential that changed.
    pub credential_type: CredentialType,
    /// The kind of change (create, revoke, update, delete).
    pub change_type: CredentialChangeType,
    /// A human-readable name for the credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    /// The X.509 certificate issuer DN (when `credential_type` is [`CredentialType::X509`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_issuer: Option<String>,
    /// The X.509 certificate serial number (when `credential_type` is [`CredentialType::X509`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_serial: Option<String>,
    /// The FIDO2 AAGUID of the authenticator (when `credential_type` is a FIDO2 variant).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fido2_aaguid: Option<String>,
}

/// Token claims have changed ([CAEP §3.2]).
///
/// Signals that the claims in an active token have been modified and the
/// receiver should re-evaluate access based on the updated claims.
///
/// [CAEP §3.2]: https://openid.net/specs/openid-caep-1_0.html#section-3.2
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenClaimsChange {
    /// Common CAEP event fields.
    #[serde(flatten)]
    pub common: CaepCommon,
    /// The updated token claims as a freeform JSON object.
    pub claims: serde_json::Value,
}

/// A device's compliance status changed ([CAEP §3.5]).
///
/// [CAEP §3.5]: https://openid.net/specs/openid-caep-1_0.html#section-3.5
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceComplianceChange {
    /// Common CAEP event fields.
    #[serde(flatten)]
    pub common: CaepCommon,
    /// The compliance status before the change.
    pub previous_status: ComplianceStatus,
    /// The compliance status after the change.
    pub current_status: ComplianceStatus,
}

/// An assurance level changed ([CAEP §3.4]).
///
/// Signals that a subject's authentication or identity assurance level
/// has changed within a given namespace.
///
/// [CAEP §3.4]: https://openid.net/specs/openid-caep-1_0.html#section-3.4
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssuranceLevelChange {
    /// Common CAEP event fields.
    #[serde(flatten)]
    pub common: CaepCommon,
    /// The assurance framework namespace (e.g. `"nist-aal"`, `"rfc6711"`).
    pub namespace: String,
    /// The current assurance level value within the namespace.
    pub current_level: String,
    /// The previous assurance level value, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_level: Option<String>,
    /// Whether the assurance level increased or decreased.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_direction: Option<ChangeDirection>,
}

/// A risk level changed ([CAEP §3.8]).
///
/// Signals that the assessed risk for a principal has changed.
///
/// [CAEP §3.8]: https://openid.net/specs/openid-caep-1_0.html#section-3.8
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskLevelChange {
    /// Common CAEP event fields.
    #[serde(flatten)]
    pub common: CaepCommon,
    /// The type of principal whose risk changed.
    pub principal: RiskPrincipal,
    /// The current risk level.
    pub current_level: RiskLevel,
    /// The previous risk level, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_level: Option<RiskLevel>,
    /// A human-readable explanation of why the risk level changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_reason: Option<String>,
}

/// A session was established ([CAEP §3.6]).
///
/// Signals that a new session has been created for the subject.
///
/// [CAEP §3.6]: https://openid.net/specs/openid-caep-1_0.html#section-3.6
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionEstablished {
    /// Common CAEP event fields.
    #[serde(flatten)]
    pub common: CaepCommon,
    /// User-Agent fingerprint for the session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp_ua: Option<String>,
    /// Authentication Context Class Reference used to establish the session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Authentication Methods References used to establish the session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    /// External session identifier assigned by the transmitter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext_id: Option<String>,
}

/// A session was presented (used) ([CAEP §3.7]).
///
/// Signals that an existing session was used (presented) at the transmitter.
///
/// [CAEP §3.7]: https://openid.net/specs/openid-caep-1_0.html#section-3.7
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionPresented {
    /// Common CAEP event fields.
    #[serde(flatten)]
    pub common: CaepCommon,
    /// User-Agent fingerprint for the session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp_ua: Option<String>,
    /// External session identifier assigned by the transmitter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext_id: Option<String>,
}

/// Schema URI for the [`SessionRevoked`] event.
pub const SESSION_REVOKED_URI: &str = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

/// Schema URI for the [`CredentialChange`] event.
pub const CREDENTIAL_CHANGE_URI: &str = "https://schemas.openid.net/secevent/caep/event-type/credential-change";

/// Schema URI for the [`TokenClaimsChange`] event.
pub const TOKEN_CLAIMS_CHANGE_URI: &str = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change";

/// Schema URI for the [`DeviceComplianceChange`] event.
pub const DEVICE_COMPLIANCE_CHANGE_URI: &str =
    "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change";

/// Schema URI for the [`AssuranceLevelChange`] event.
pub const ASSURANCE_LEVEL_CHANGE_URI: &str =
    "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";

/// Schema URI for the [`RiskLevelChange`] event.
pub const RISK_LEVEL_CHANGE_URI: &str = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";

/// Schema URI for the [`SessionEstablished`] event.
pub const SESSION_ESTABLISHED_URI: &str = "https://schemas.openid.net/secevent/caep/event-type/session-established";

/// Schema URI for the [`SessionPresented`] event.
pub const SESSION_PRESENTED_URI: &str = "https://schemas.openid.net/secevent/caep/event-type/session-presented";

/// A typed CAEP event ([CAEP 1.0]).
///
/// This enum wraps all 8 CAEP event structs and provides access to
/// their schema URI and JSON payload. It is not serialized directly;
/// instead, [`SecurityEventTokenBuilder`](crate::set::SecurityEventTokenBuilder)
/// uses [`uri`](CaepEvent::uri) and [`to_payload`](CaepEvent::to_payload) to
/// place the event under the correct key in the SET `events` map.
///
/// [CAEP 1.0]: https://openid.net/specs/openid-caep-1_0.html
#[derive(Debug, Clone, PartialEq)]
pub enum CaepEvent {
    /// See [`SessionRevoked`].
    SessionRevoked(SessionRevoked),
    /// See [`CredentialChange`].
    CredentialChange(CredentialChange),
    /// See [`TokenClaimsChange`].
    TokenClaimsChange(TokenClaimsChange),
    /// See [`DeviceComplianceChange`].
    DeviceComplianceChange(DeviceComplianceChange),
    /// See [`AssuranceLevelChange`].
    AssuranceLevelChange(AssuranceLevelChange),
    /// See [`RiskLevelChange`].
    RiskLevelChange(RiskLevelChange),
    /// See [`SessionEstablished`].
    SessionEstablished(SessionEstablished),
    /// See [`SessionPresented`].
    SessionPresented(SessionPresented),
}

impl CaepEvent {
    /// Returns the schema URI that identifies this event type.
    ///
    /// The URI is an opaque identifier used as the key in the SET `events`
    /// object; it is not intended to be a dereferenceable URL.
    pub fn uri(&self) -> &'static str {
        match self {
            Self::SessionRevoked(_) => SESSION_REVOKED_URI,
            Self::CredentialChange(_) => CREDENTIAL_CHANGE_URI,
            Self::TokenClaimsChange(_) => TOKEN_CLAIMS_CHANGE_URI,
            Self::DeviceComplianceChange(_) => DEVICE_COMPLIANCE_CHANGE_URI,
            Self::AssuranceLevelChange(_) => ASSURANCE_LEVEL_CHANGE_URI,
            Self::RiskLevelChange(_) => RISK_LEVEL_CHANGE_URI,
            Self::SessionEstablished(_) => SESSION_ESTABLISHED_URI,
            Self::SessionPresented(_) => SESSION_PRESENTED_URI,
        }
    }

    /// Serializes the event payload to a [`serde_json::Value`].
    ///
    /// The returned value is placed under this event's [`uri`](CaepEvent::uri) key
    /// in the SET `events` object.
    pub fn to_payload(&self) -> Result<serde_json::Value, crate::error::SigshareError> {
        let value = match self {
            Self::SessionRevoked(e) => serde_json::to_value(e)?,
            Self::CredentialChange(e) => serde_json::to_value(e)?,
            Self::TokenClaimsChange(e) => serde_json::to_value(e)?,
            Self::DeviceComplianceChange(e) => serde_json::to_value(e)?,
            Self::AssuranceLevelChange(e) => serde_json::to_value(e)?,
            Self::RiskLevelChange(e) => serde_json::to_value(e)?,
            Self::SessionEstablished(e) => serde_json::to_value(e)?,
            Self::SessionPresented(e) => serde_json::to_value(e)?,
        };
        Ok(value)
    }
}
