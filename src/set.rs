//! Security Event Token (SET) per [RFC 8417](https://www.rfc-editor.org/rfc/rfc8417).
//!
//! This module provides [`SecurityEventToken`] for representing SETs,
//! [`SecurityEventTokenBuilder`] for constructing them with validation, and
//! [`SsfEvent`] as a unified wrapper for CAEP, RISC, SSF, and custom events.
//!
//! # Wire format
//!
//! The `events` claim is serialized as `Map<URI, Object>` using a [`BTreeMap`]
//! for deterministic key ordering. The `aud` claim accepts both a single JSON
//! string and a JSON array on deserialization, per RFC 7519.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::error::SigshareError;
use crate::subject::SubjectIdentifier;

/// A Security Event Token as defined by [RFC 8417](https://www.rfc-editor.org/rfc/rfc8417).
///
/// Contains the standard JWT/SET claims (`iss`, `iat`, `jti`, etc.) plus
/// the `events` payload carrying one or more [`SsfEvent`] values. The `sub_id`
/// claim is an [RFC 9493](https://www.rfc-editor.org/rfc/rfc9493) extension
/// used by the Shared Signals Framework to identify the event subject.
///
/// Use [`SecurityEventTokenBuilder`] to construct instances with validation.
/// Implements `Serialize` and `Deserialize` for spec-compliant JSON wire format.
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityEventToken {
    /// Issuer identifier (REQUIRED per RFC 8417).
    pub iss: String,
    /// Issued-at timestamp as seconds since Unix epoch (REQUIRED per RFC 8417).
    pub iat: i64,
    /// JWT ID — a unique identifier for this token (REQUIRED per RFC 8417).
    pub jti: String,
    /// Audience — one or more intended recipients (RECOMMENDED per RFC 8417).
    /// Deserialization accepts both a single JSON string and a JSON array.
    pub aud: Option<Vec<String>>,
    /// JWT subject claim (OPTIONAL). Note: SSF 1.0 specifies that `sub`
    /// MUST NOT be present in SETs containing SSF events; use `sub_id` instead.
    pub sub: Option<String>,
    /// Transaction identifier for correlating related events (OPTIONAL per RFC 8417).
    pub txn: Option<String>,
    /// Time of event — when the security event occurred, as seconds since Unix epoch
    /// (OPTIONAL per RFC 8417).
    pub toe: Option<i64>,
    /// Subject identifier per [RFC 9493](https://www.rfc-editor.org/rfc/rfc9493) (OPTIONAL).
    pub sub_id: Option<SubjectIdentifier>,
    /// The security events carried by this token. RFC 8417 requires at least one event.
    pub events: Vec<SsfEvent>,
}

impl Serialize for SecurityEventToken {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let wire = SecurityEventTokenWire::try_from_token(self).map_err(serde::ser::Error::custom)?;
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecurityEventToken {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = SecurityEventTokenWire::deserialize(deserializer)?;
        SecurityEventToken::try_from(wire).map_err(serde::de::Error::custom)
    }
}

/// A single event within a Security Event Token.
///
/// Wraps CAEP, RISC, SSF management events, or arbitrary custom events.
/// Each variant maps to a specific event type URI in the SET `events` object.
#[derive(Debug, Clone, PartialEq)]
pub enum SsfEvent {
    /// A [CAEP 1.0](https://openid.net/specs/openid-caep-1_0.html) event
    /// (session, credential, compliance, assurance, or risk).
    Caep(crate::caep::CaepEvent),
    /// A [RISC 1.0](https://openid.net/specs/openid-risc-profile-specification-1_0.html) event
    /// (account, identifier, credential, recovery, or opt-in/out).
    Risc(crate::risc::RiscEvent),
    /// An SSF verification event used to confirm stream liveness.
    Verification(crate::ssf::VerificationEvent),
    /// An SSF stream-updated event indicating a stream status change.
    StreamUpdated(crate::ssf::StreamUpdatedEvent),
    /// A custom or unrecognized event type, preserved as raw JSON.
    Custom {
        /// The event type URI.
        uri: String,
        /// The event payload as raw JSON.
        payload: serde_json::Value,
    },
}

impl SsfEvent {
    /// Returns the event type URI for this event.
    pub fn uri(&self) -> &str {
        match self {
            Self::Caep(e) => e.uri(),
            Self::Risc(e) => e.uri(),
            Self::Verification(_) => crate::ssf::VERIFICATION_EVENT_URI,
            Self::StreamUpdated(_) => crate::ssf::STREAM_UPDATED_EVENT_URI,
            Self::Custom { uri, .. } => uri,
        }
    }

    /// Serializes the event payload to a JSON value.
    pub fn to_payload(&self) -> Result<serde_json::Value, SigshareError> {
        let value = match self {
            Self::Caep(e) => e.to_payload()?,
            Self::Risc(e) => e.to_payload()?,
            Self::Verification(e) => serde_json::to_value(e)?,
            Self::StreamUpdated(e) => serde_json::to_value(e)?,
            Self::Custom { payload, .. } => payload.clone(),
        };
        Ok(value)
    }
}

/// Builder for [`SecurityEventToken`] with validation.
///
/// Validates that all required fields (`iss`, `iat`, `jti`) are present,
/// that at least one event is provided, and that no two events share the
/// same event type URI.
///
/// # Example
///
/// ```
/// use sigshare::set::{SecurityEventTokenBuilder, SsfEvent};
/// use sigshare::caep::{CaepEvent, SessionRevoked, CaepCommon};
///
/// let token = SecurityEventTokenBuilder::new()
///     .iss("https://idp.example.com")
///     .iat(1_700_000_000)
///     .jti("evt-001")
///     .event(SsfEvent::Caep(CaepEvent::SessionRevoked(SessionRevoked {
///         common: CaepCommon::default(),
///     })))
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Default)]
pub struct SecurityEventTokenBuilder {
    iss: Option<String>,
    iat: Option<i64>,
    jti: Option<String>,
    aud: Option<Vec<String>>,
    sub: Option<String>,
    txn: Option<String>,
    toe: Option<i64>,
    sub_id: Option<SubjectIdentifier>,
    events: Vec<SsfEvent>,
}

impl SecurityEventTokenBuilder {
    /// Creates a new empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the issuer (`iss`) claim. Required.
    pub fn iss(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    /// Sets the issued-at (`iat`) timestamp as seconds since Unix epoch. Required.
    pub fn iat(mut self, iat: i64) -> Self {
        self.iat = Some(iat);
        self
    }

    /// Sets the JWT ID (`jti`) claim. Required.
    pub fn jti(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }

    /// Sets the audience (`aud`) claim.
    pub fn aud(mut self, aud: Vec<String>) -> Self {
        self.aud = Some(aud);
        self
    }

    /// Sets the JWT subject (`sub`) claim.
    ///
    /// Note: SSF 1.0 specifies that `sub` MUST NOT be present in SETs
    /// containing SSF events. Prefer [`sub_id`](Self::sub_id) instead.
    #[allow(clippy::should_implement_trait)]
    pub fn sub(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    /// Sets the transaction identifier (`txn`) claim.
    pub fn txn(mut self, txn: impl Into<String>) -> Self {
        self.txn = Some(txn.into());
        self
    }

    /// Sets the time-of-event (`toe`) claim as seconds since Unix epoch.
    pub fn toe(mut self, toe: i64) -> Self {
        self.toe = Some(toe);
        self
    }

    /// Sets the subject identifier (`sub_id`) per RFC 9493.
    pub fn sub_id(mut self, sub_id: SubjectIdentifier) -> Self {
        self.sub_id = Some(sub_id);
        self
    }

    /// Adds an event to the token.
    pub fn event(mut self, event: SsfEvent) -> Self {
        self.events.push(event);
        self
    }

    /// Builds the [`SecurityEventToken`], validating all required fields.
    ///
    /// # Errors
    ///
    /// Returns [`SigshareError::MissingField`] if `iss`, `iat`, `jti`, or
    /// `events` is missing. Returns [`SigshareError::DuplicateEventUri`] if
    /// two events share the same event type URI.
    pub fn build(self) -> Result<SecurityEventToken, SigshareError> {
        let iss = self.iss.ok_or(SigshareError::MissingField { field: "iss" })?;
        let iat = self.iat.ok_or(SigshareError::MissingField { field: "iat" })?;
        let jti = self.jti.ok_or(SigshareError::MissingField { field: "jti" })?;

        if self.events.is_empty() {
            return Err(SigshareError::MissingField { field: "events" });
        }

        let mut seen_uris = std::collections::HashSet::new();
        for event in &self.events {
            if !seen_uris.insert(event.uri()) {
                return Err(SigshareError::DuplicateEventUri { uri: event.uri().to_owned() });
            }
        }

        Ok(SecurityEventToken {
            iss,
            iat,
            jti,
            aud: self.aud,
            sub: self.sub,
            txn: self.txn,
            toe: self.toe,
            sub_id: self.sub_id,
            events: self.events,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct SecurityEventTokenWire {
    iss: String,
    iat: i64,
    jti: String,
    #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_aud", default)]
    aud: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    txn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    toe: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub_id: Option<serde_json::Value>,
    events: BTreeMap<String, serde_json::Value>,
}

fn deserialize_aud<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Vec<String>>, D::Error> {
    let value: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(vec![s])),
        Some(serde_json::Value::Array(arr)) => {
            let mut result = Vec::with_capacity(arr.len());
            for item in arr {
                match item {
                    serde_json::Value::String(s) => result.push(s),
                    other => {
                        return Err(serde::de::Error::custom(format!("expected string in aud array, got {other}")));
                    }
                }
            }
            Ok(Some(result))
        }
        Some(other) => Err(serde::de::Error::custom(format!("expected string or array for aud, got {other}"))),
    }
}

impl SecurityEventTokenWire {
    fn try_from_token(token: &SecurityEventToken) -> Result<Self, SigshareError> {
        let mut events = BTreeMap::new();
        for event in &token.events {
            events.insert(event.uri().to_owned(), event.to_payload()?);
        }

        let sub_id = token.sub_id.as_ref().map(serde_json::to_value).transpose()?;

        Ok(Self {
            iss: token.iss.clone(),
            iat: token.iat,
            jti: token.jti.clone(),
            aud: token.aud.clone(),
            sub: token.sub.clone(),
            txn: token.txn.clone(),
            toe: token.toe,
            sub_id,
            events,
        })
    }
}

impl TryFrom<SecurityEventTokenWire> for SecurityEventToken {
    type Error = SigshareError;

    fn try_from(wire: SecurityEventTokenWire) -> Result<Self, Self::Error> {
        if wire.events.is_empty() {
            return Err(SigshareError::MissingField { field: "events" });
        }

        let sub_id = wire.sub_id.map(serde_json::from_value).transpose().map_err(SigshareError::Serialization)?;

        let mut events = Vec::with_capacity(wire.events.len());
        for (uri, payload) in wire.events {
            let event = parse_ssf_event(uri, payload)?;
            events.push(event);
        }

        Ok(Self {
            iss: wire.iss,
            iat: wire.iat,
            jti: wire.jti,
            aud: wire.aud,
            sub: wire.sub,
            txn: wire.txn,
            toe: wire.toe,
            sub_id,
            events,
        })
    }
}

fn parse_ssf_event(uri: String, payload: serde_json::Value) -> Result<SsfEvent, SigshareError> {
    use crate::caep::*;

    match uri.as_str() {
        SESSION_REVOKED_URI => {
            return Ok(SsfEvent::Caep(CaepEvent::SessionRevoked(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        CREDENTIAL_CHANGE_URI => {
            return Ok(SsfEvent::Caep(CaepEvent::CredentialChange(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        TOKEN_CLAIMS_CHANGE_URI => {
            return Ok(SsfEvent::Caep(CaepEvent::TokenClaimsChange(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        DEVICE_COMPLIANCE_CHANGE_URI => {
            return Ok(SsfEvent::Caep(CaepEvent::DeviceComplianceChange(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        ASSURANCE_LEVEL_CHANGE_URI => {
            return Ok(SsfEvent::Caep(CaepEvent::AssuranceLevelChange(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        RISK_LEVEL_CHANGE_URI => {
            return Ok(SsfEvent::Caep(CaepEvent::RiskLevelChange(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        SESSION_ESTABLISHED_URI => {
            return Ok(SsfEvent::Caep(CaepEvent::SessionEstablished(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        SESSION_PRESENTED_URI => {
            return Ok(SsfEvent::Caep(CaepEvent::SessionPresented(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        _ => {}
    }

    use crate::risc::*;

    match uri.as_str() {
        ACCOUNT_CREDENTIAL_CHANGE_REQUIRED_URI => {
            return Ok(SsfEvent::Risc(RiscEvent::AccountCredentialChangeRequired(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        ACCOUNT_PURGED_URI => {
            return Ok(SsfEvent::Risc(RiscEvent::AccountPurged(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        ACCOUNT_DISABLED_URI => {
            return Ok(SsfEvent::Risc(RiscEvent::AccountDisabled(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        ACCOUNT_ENABLED_URI => {
            return Ok(SsfEvent::Risc(RiscEvent::AccountEnabled(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        IDENTIFIER_CHANGED_URI => {
            return Ok(SsfEvent::Risc(RiscEvent::IdentifierChanged(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        IDENTIFIER_RECYCLED_URI => {
            return Ok(SsfEvent::Risc(RiscEvent::IdentifierRecycled(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        CREDENTIAL_COMPROMISE_URI => {
            return Ok(SsfEvent::Risc(RiscEvent::CredentialCompromise(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        OPT_IN_URI => {
            return Ok(SsfEvent::Risc(RiscEvent::OptIn(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        OPT_OUT_INITIATED_URI => {
            return Ok(SsfEvent::Risc(RiscEvent::OptOutInitiated(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        OPT_OUT_CANCELLED_URI => {
            return Ok(SsfEvent::Risc(RiscEvent::OptOutCancelled(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        OPT_OUT_EFFECTIVE_URI => {
            return Ok(SsfEvent::Risc(RiscEvent::OptOutEffective(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        RECOVERY_ACTIVATED_URI => {
            return Ok(SsfEvent::Risc(RiscEvent::RecoveryActivated(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        RECOVERY_INFORMATION_CHANGED_URI => {
            return Ok(SsfEvent::Risc(RiscEvent::RecoveryInformationChanged(
                serde_json::from_value(payload).map_err(SigshareError::Serialization)?,
            )));
        }
        _ => {}
    }

    match uri.as_str() {
        crate::ssf::VERIFICATION_EVENT_URI => {
            return Ok(SsfEvent::Verification(serde_json::from_value(payload).map_err(SigshareError::Serialization)?));
        }
        crate::ssf::STREAM_UPDATED_EVENT_URI => {
            return Ok(SsfEvent::StreamUpdated(serde_json::from_value(payload).map_err(SigshareError::Serialization)?));
        }
        _ => {}
    }

    Ok(SsfEvent::Custom { uri, payload })
}
