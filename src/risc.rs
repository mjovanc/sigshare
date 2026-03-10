//! [RISC 1.0] event types for Risk Incident Sharing and Coordination.
//!
//! This module implements 13 event types defined by the RISC specification,
//! which enables identity providers and relying parties to share account
//! lifecycle and security signals.
//!
//! The spec-defined `sessions-revoked` event ([RISC §2.11]) is intentionally
//! omitted because it is deprecated; new implementations should use the CAEP
//! [`SessionRevoked`](crate::caep::SessionRevoked) event instead.
//!
//! # Event types
//!
//! | Event | URI suffix | Section | Struct |
//! |-------|-----------|---------|--------|
//! | Account Credential Change Required | `account-credential-change-required` | §2.1 | [`AccountCredentialChangeRequired`] |
//! | Account Purged | `account-purged` | §2.2 | [`AccountPurged`] |
//! | Account Disabled | `account-disabled` | §2.3 | [`AccountDisabled`] |
//! | Account Enabled | `account-enabled` | §2.4 | [`AccountEnabled`] |
//! | Identifier Changed | `identifier-changed` | §2.5 | [`IdentifierChanged`] |
//! | Identifier Recycled | `identifier-recycled` | §2.6 | [`IdentifierRecycled`] |
//! | Credential Compromise | `credential-compromise` | §2.7 | [`CredentialCompromise`] |
//! | Opt In | `opt-in` | §2.8.1 | [`OptIn`] |
//! | Opt Out Initiated | `opt-out-initiated` | §2.8.2 | [`OptOutInitiated`] |
//! | Opt Out Cancelled | `opt-out-cancelled` | §2.8.3 | [`OptOutCancelled`] |
//! | Opt Out Effective | `opt-out-effective` | §2.8.4 | [`OptOutEffective`] |
//! | Recovery Activated | `recovery-activated` | §2.9 | [`RecoveryActivated`] |
//! | Recovery Information Changed | `recovery-information-changed` | §2.10 | [`RecoveryInformationChanged`] |
//!
//! Most RISC events carry no payload (empty JSON object `{}`). The exceptions are
//! [`AccountDisabled`] (optional `reason`), [`IdentifierChanged`] (optional `new-value`),
//! and [`CredentialCompromise`] (credential type, timestamp, localized reasons).
//!
//! [RISC 1.0]: https://openid.net/specs/openid-risc-profile-specification-1_0.html

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::Error;

/// Reason an account was disabled ([RISC §2.3]).
///
/// [RISC §2.3]: https://openid.net/specs/openid-risc-profile-specification-1_0.html#section-2.3
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum AccountDisabledReason {
    /// The account was disabled because it was hijacked.
    Hijacking,
    /// The account was disabled because it is a bulk/spam account.
    BulkAccount,
}

/// The subject's credentials should be changed ([RISC §2.1]).
///
/// Signals that the transmitter has reason to believe the subject's
/// credentials may have been compromised and should be reset.
///
/// This event carries no additional payload.
///
/// [RISC §2.1]: https://openid.net/specs/openid-risc-profile-specification-1_0.html#section-2.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AccountCredentialChangeRequired {}

/// The subject's account has been permanently deleted ([RISC §2.2]).
///
/// Signals that the account no longer exists at the transmitter and any
/// locally cached data for it should be removed.
///
/// This event carries no additional payload.
///
/// [RISC §2.2]: https://openid.net/specs/openid-risc-profile-specification-1_0.html#section-2.2
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AccountPurged {}

/// The subject's account has been disabled ([RISC §2.3]).
///
/// [RISC §2.3]: https://openid.net/specs/openid-risc-profile-specification-1_0.html#section-2.3
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDisabled {
    /// The reason the account was disabled, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<AccountDisabledReason>,
}

/// The subject's account has been re-enabled ([RISC §2.4]).
///
/// This event carries no additional payload.
///
/// [RISC §2.4]: https://openid.net/specs/openid-risc-profile-specification-1_0.html#section-2.4
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AccountEnabled {}

/// An identifier for the subject has changed ([RISC §2.5]).
///
/// For example, a user's email address or phone number was updated.
/// The subject identifier in the SET refers to the **previous** identifier.
///
/// [RISC §2.5]: https://openid.net/specs/openid-risc-profile-specification-1_0.html#section-2.5
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentifierChanged {
    /// The new value of the identifier, if the transmitter chooses to disclose it.
    #[serde(rename = "new-value", skip_serializing_if = "Option::is_none")]
    pub new_value: Option<String>,
}

/// An identifier previously associated with one subject is now assigned to
/// a different subject ([RISC §2.6]).
///
/// This event carries no additional payload.
///
/// [RISC §2.6]: https://openid.net/specs/openid-risc-profile-specification-1_0.html#section-2.6
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IdentifierRecycled {}

/// A credential associated with the subject has been compromised ([RISC §2.7]).
///
/// The `reason_admin` and `reason_user` fields follow the BCP 47 localized
/// string map convention used by [CAEP §2] (language tag → message).
///
/// [RISC §2.7]: https://openid.net/specs/openid-risc-profile-specification-1_0.html#section-2.7
/// [CAEP §2]: https://openid.net/specs/openid-caep-1_0.html#section-2
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialCompromise {
    /// The type of credential that was compromised.
    pub credential_type: crate::subject::CredentialType,
    /// UNIX timestamp (seconds since epoch) of the compromise event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_timestamp: Option<i64>,
    /// Administrator-facing reason in BCP 47 localized form.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_admin: Option<BTreeMap<String, String>>,
    /// User-facing reason in BCP 47 localized form.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_user: Option<BTreeMap<String, String>>,
}

/// The subject has opted in to RISC event sharing ([RISC §2.8.1]).
///
/// This event carries no additional payload.
///
/// [RISC §2.8.1]: https://openid.net/specs/openid-risc-profile-specification-1_0.html#section-2.8.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OptIn {}

/// The subject has initiated an opt-out from RISC event sharing ([RISC §2.8.2]).
///
/// This event carries no additional payload.
///
/// [RISC §2.8.2]: https://openid.net/specs/openid-risc-profile-specification-1_0.html#section-2.8.2
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OptOutInitiated {}

/// The subject's opt-out has been cancelled ([RISC §2.8.3]).
///
/// This event carries no additional payload.
///
/// [RISC §2.8.3]: https://openid.net/specs/openid-risc-profile-specification-1_0.html#section-2.8.3
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OptOutCancelled {}

/// The subject's opt-out is now effective ([RISC §2.8.4]).
///
/// After this event, no further RISC events will be sent for this subject.
///
/// This event carries no additional payload.
///
/// [RISC §2.8.4]: https://openid.net/specs/openid-risc-profile-specification-1_0.html#section-2.8.4
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OptOutEffective {}

/// Account recovery has been activated ([RISC §2.9]).
///
/// This event carries no additional payload.
///
/// [RISC §2.9]: https://openid.net/specs/openid-risc-profile-specification-1_0.html#section-2.9
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RecoveryActivated {}

/// The subject's recovery information (e.g. recovery email, phone) has
/// changed ([RISC §2.10]).
///
/// This event carries no additional payload.
///
/// [RISC §2.10]: https://openid.net/specs/openid-risc-profile-specification-1_0.html#section-2.10
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RecoveryInformationChanged {}

/// Schema URI for the [`AccountCredentialChangeRequired`] event.
pub const ACCOUNT_CREDENTIAL_CHANGE_REQUIRED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required";

/// Schema URI for the [`AccountPurged`] event.
pub const ACCOUNT_PURGED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-purged";

/// Schema URI for the [`AccountDisabled`] event.
pub const ACCOUNT_DISABLED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled";

/// Schema URI for the [`AccountEnabled`] event.
pub const ACCOUNT_ENABLED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-enabled";

/// Schema URI for the [`IdentifierChanged`] event.
pub const IDENTIFIER_CHANGED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/identifier-changed";

/// Schema URI for the [`IdentifierRecycled`] event.
pub const IDENTIFIER_RECYCLED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled";

/// Schema URI for the [`CredentialCompromise`] event.
pub const CREDENTIAL_COMPROMISE_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/credential-compromise";

/// Schema URI for the [`OptIn`] event.
pub const OPT_IN_URI: &str = "https://schemas.openid.net/secevent/risc/event-type/opt-in";

/// Schema URI for the [`OptOutInitiated`] event.
pub const OPT_OUT_INITIATED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated";

/// Schema URI for the [`OptOutCancelled`] event.
pub const OPT_OUT_CANCELLED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled";

/// Schema URI for the [`OptOutEffective`] event.
pub const OPT_OUT_EFFECTIVE_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective";

/// Schema URI for the [`RecoveryActivated`] event.
pub const RECOVERY_ACTIVATED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/recovery-activated";

/// Schema URI for the [`RecoveryInformationChanged`] event.
pub const RECOVERY_INFORMATION_CHANGED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed";

/// A typed RISC event ([RISC 1.0]).
///
/// This enum wraps all 13 RISC event structs and provides access to
/// their schema URI and JSON payload. It is not serialized directly;
/// instead, [`SecurityEventTokenBuilder`](crate::set::SecurityEventTokenBuilder)
/// uses [`uri`](RiscEvent::uri) and [`to_payload`](RiscEvent::to_payload) to
/// place the event under the correct key in the SET `events` map.
///
/// [RISC 1.0]: https://openid.net/specs/openid-risc-profile-specification-1_0.html
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RiscEvent {
    /// See [`AccountCredentialChangeRequired`].
    AccountCredentialChangeRequired(AccountCredentialChangeRequired),
    /// See [`AccountPurged`].
    AccountPurged(AccountPurged),
    /// See [`AccountDisabled`].
    AccountDisabled(AccountDisabled),
    /// See [`AccountEnabled`].
    AccountEnabled(AccountEnabled),
    /// See [`IdentifierChanged`].
    IdentifierChanged(IdentifierChanged),
    /// See [`IdentifierRecycled`].
    IdentifierRecycled(IdentifierRecycled),
    /// See [`CredentialCompromise`].
    CredentialCompromise(CredentialCompromise),
    /// See [`OptIn`].
    OptIn(OptIn),
    /// See [`OptOutInitiated`].
    OptOutInitiated(OptOutInitiated),
    /// See [`OptOutCancelled`].
    OptOutCancelled(OptOutCancelled),
    /// See [`OptOutEffective`].
    OptOutEffective(OptOutEffective),
    /// See [`RecoveryActivated`].
    RecoveryActivated(RecoveryActivated),
    /// See [`RecoveryInformationChanged`].
    RecoveryInformationChanged(RecoveryInformationChanged),
}

impl RiscEvent {
    /// Returns the schema URI that identifies this event type.
    ///
    /// The URI is an opaque identifier used as the key in the SET `events`
    /// object; it is not intended to be a dereferenceable URL.
    pub fn uri(&self) -> &'static str {
        match self {
            Self::AccountCredentialChangeRequired(_) => ACCOUNT_CREDENTIAL_CHANGE_REQUIRED_URI,
            Self::AccountPurged(_) => ACCOUNT_PURGED_URI,
            Self::AccountDisabled(_) => ACCOUNT_DISABLED_URI,
            Self::AccountEnabled(_) => ACCOUNT_ENABLED_URI,
            Self::IdentifierChanged(_) => IDENTIFIER_CHANGED_URI,
            Self::IdentifierRecycled(_) => IDENTIFIER_RECYCLED_URI,
            Self::CredentialCompromise(_) => CREDENTIAL_COMPROMISE_URI,
            Self::OptIn(_) => OPT_IN_URI,
            Self::OptOutInitiated(_) => OPT_OUT_INITIATED_URI,
            Self::OptOutCancelled(_) => OPT_OUT_CANCELLED_URI,
            Self::OptOutEffective(_) => OPT_OUT_EFFECTIVE_URI,
            Self::RecoveryActivated(_) => RECOVERY_ACTIVATED_URI,
            Self::RecoveryInformationChanged(_) => RECOVERY_INFORMATION_CHANGED_URI,
        }
    }

    /// Serializes the event payload to a [`serde_json::Value`].
    ///
    /// The returned value is placed under this event's [`uri`](RiscEvent::uri) key
    /// in the SET `events` object.
    pub fn to_payload(&self) -> Result<serde_json::Value, Error> {
        let value = match self {
            Self::AccountCredentialChangeRequired(e) => {
                serde_json::to_value(e).map_err(Error::Serialization)?
            }
            Self::AccountPurged(e) => serde_json::to_value(e).map_err(Error::Serialization)?,
            Self::AccountDisabled(e) => serde_json::to_value(e).map_err(Error::Serialization)?,
            Self::AccountEnabled(e) => serde_json::to_value(e).map_err(Error::Serialization)?,
            Self::IdentifierChanged(e) => serde_json::to_value(e).map_err(Error::Serialization)?,
            Self::IdentifierRecycled(e) => serde_json::to_value(e).map_err(Error::Serialization)?,
            Self::CredentialCompromise(e) => {
                serde_json::to_value(e).map_err(Error::Serialization)?
            }
            Self::OptIn(e) => serde_json::to_value(e).map_err(Error::Serialization)?,
            Self::OptOutInitiated(e) => serde_json::to_value(e).map_err(Error::Serialization)?,
            Self::OptOutCancelled(e) => serde_json::to_value(e).map_err(Error::Serialization)?,
            Self::OptOutEffective(e) => serde_json::to_value(e).map_err(Error::Serialization)?,
            Self::RecoveryActivated(e) => serde_json::to_value(e).map_err(Error::Serialization)?,
            Self::RecoveryInformationChanged(e) => {
                serde_json::to_value(e).map_err(Error::Serialization)?
            }
        };
        Ok(value)
    }
}
