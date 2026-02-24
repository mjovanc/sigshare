use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccountDisabledReason {
    Hijacking,
    BulkAccount,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AccountCredentialChangeRequired {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AccountPurged {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountDisabled {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<AccountDisabledReason>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AccountEnabled {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentifierChanged {
    #[serde(rename = "new-value", skip_serializing_if = "Option::is_none")]
    pub new_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct IdentifierRecycled {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialCompromise {
    pub credential_type: crate::subject::CredentialType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_admin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct OptIn {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct OptOutInitiated {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct OptOutCancelled {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct OptOutEffective {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RecoveryActivated {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RecoveryInformationChanged {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SessionsRevoked {}

pub const ACCOUNT_CREDENTIAL_CHANGE_REQUIRED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required";

pub const ACCOUNT_PURGED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-purged";

pub const ACCOUNT_DISABLED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled";

pub const ACCOUNT_ENABLED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-enabled";

pub const IDENTIFIER_CHANGED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/identifier-changed";

pub const IDENTIFIER_RECYCLED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled";

pub const CREDENTIAL_COMPROMISE_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/credential-compromise";

pub const OPT_IN_URI: &str = "https://schemas.openid.net/secevent/risc/event-type/opt-in";

pub const OPT_OUT_INITIATED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated";

pub const OPT_OUT_CANCELLED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled";

pub const OPT_OUT_EFFECTIVE_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective";

pub const RECOVERY_ACTIVATED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/recovery-activated";

pub const RECOVERY_INFORMATION_CHANGED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed";

pub const SESSIONS_REVOKED_URI: &str =
    "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked";

#[derive(Debug, Clone, PartialEq)]
pub enum RiscEvent {
    AccountCredentialChangeRequired(AccountCredentialChangeRequired),
    AccountPurged(AccountPurged),
    AccountDisabled(AccountDisabled),
    AccountEnabled(AccountEnabled),
    IdentifierChanged(IdentifierChanged),
    IdentifierRecycled(IdentifierRecycled),
    CredentialCompromise(CredentialCompromise),
    OptIn(OptIn),
    OptOutInitiated(OptOutInitiated),
    OptOutCancelled(OptOutCancelled),
    OptOutEffective(OptOutEffective),
    RecoveryActivated(RecoveryActivated),
    RecoveryInformationChanged(RecoveryInformationChanged),
    SessionsRevoked(SessionsRevoked),
}

impl RiscEvent {
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
            Self::SessionsRevoked(_) => SESSIONS_REVOKED_URI,
        }
    }

    pub fn to_payload(&self) -> Result<serde_json::Value, crate::error::SigshareError> {
        let value = match self {
            Self::AccountCredentialChangeRequired(e) => serde_json::to_value(e)?,
            Self::AccountPurged(e) => serde_json::to_value(e)?,
            Self::AccountDisabled(e) => serde_json::to_value(e)?,
            Self::AccountEnabled(e) => serde_json::to_value(e)?,
            Self::IdentifierChanged(e) => serde_json::to_value(e)?,
            Self::IdentifierRecycled(e) => serde_json::to_value(e)?,
            Self::CredentialCompromise(e) => serde_json::to_value(e)?,
            Self::OptIn(e) => serde_json::to_value(e)?,
            Self::OptOutInitiated(e) => serde_json::to_value(e)?,
            Self::OptOutCancelled(e) => serde_json::to_value(e)?,
            Self::OptOutEffective(e) => serde_json::to_value(e)?,
            Self::RecoveryActivated(e) => serde_json::to_value(e)?,
            Self::RecoveryInformationChanged(e) => serde_json::to_value(e)?,
            Self::SessionsRevoked(e) => serde_json::to_value(e)?,
        };
        Ok(value)
    }
}
