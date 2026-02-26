use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub use crate::subject::CredentialType;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct CaepCommon {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiating_entity: Option<InitiatingEntity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_admin: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_user: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_timestamp: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InitiatingEntity {
    Admin,
    User,
    Policy,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialChangeType {
    Create,
    Revoke,
    Update,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceStatus {
    #[serde(rename = "compliant")]
    Compliant,
    #[serde(rename = "not-compliant")]
    NotCompliant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeDirection {
    Increase,
    Decrease,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    #[serde(rename = "HIGH")]
    High,
    #[serde(rename = "MEDIUM")]
    Medium,
    #[serde(rename = "LOW")]
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskPrincipal {
    #[serde(rename = "USER")]
    User,
    #[serde(rename = "DEVICE")]
    Device,
    #[serde(rename = "SESSION")]
    Session,
    #[serde(rename = "TENANT")]
    Tenant,
    #[serde(rename = "ORG_UNIT")]
    OrgUnit,
    #[serde(rename = "GROUP")]
    Group,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionRevoked {
    #[serde(flatten)]
    pub common: CaepCommon,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialChange {
    #[serde(flatten)]
    pub common: CaepCommon,
    pub credential_type: CredentialType,
    pub change_type: CredentialChangeType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fido2_aaguid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenClaimsChange {
    #[serde(flatten)]
    pub common: CaepCommon,
    pub claims: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceComplianceChange {
    #[serde(flatten)]
    pub common: CaepCommon,
    pub previous_status: ComplianceStatus,
    pub current_status: ComplianceStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssuranceLevelChange {
    #[serde(flatten)]
    pub common: CaepCommon,
    pub namespace: String,
    pub current_level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_direction: Option<ChangeDirection>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskLevelChange {
    #[serde(flatten)]
    pub common: CaepCommon,
    pub principal: RiskPrincipal,
    pub current_level: RiskLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_level: Option<RiskLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionEstablished {
    #[serde(flatten)]
    pub common: CaepCommon,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp_ua: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionPresented {
    #[serde(flatten)]
    pub common: CaepCommon,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp_ua: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext_id: Option<String>,
}

pub const SESSION_REVOKED_URI: &str = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

pub const CREDENTIAL_CHANGE_URI: &str = "https://schemas.openid.net/secevent/caep/event-type/credential-change";

pub const TOKEN_CLAIMS_CHANGE_URI: &str = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change";

pub const DEVICE_COMPLIANCE_CHANGE_URI: &str =
    "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change";

pub const ASSURANCE_LEVEL_CHANGE_URI: &str =
    "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";

pub const RISK_LEVEL_CHANGE_URI: &str = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";

pub const SESSION_ESTABLISHED_URI: &str = "https://schemas.openid.net/secevent/caep/event-type/session-established";

pub const SESSION_PRESENTED_URI: &str = "https://schemas.openid.net/secevent/caep/event-type/session-presented";

#[derive(Debug, Clone, PartialEq)]
pub enum CaepEvent {
    SessionRevoked(SessionRevoked),
    CredentialChange(CredentialChange),
    TokenClaimsChange(TokenClaimsChange),
    DeviceComplianceChange(DeviceComplianceChange),
    AssuranceLevelChange(AssuranceLevelChange),
    RiskLevelChange(RiskLevelChange),
    SessionEstablished(SessionEstablished),
    SessionPresented(SessionPresented),
}

impl CaepEvent {
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
