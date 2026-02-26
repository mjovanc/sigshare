use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "format")]
pub enum SubjectIdentifier {
    #[serde(rename = "account")]
    Account { uri: String },

    #[serde(rename = "email")]
    Email { email: String },

    #[serde(rename = "phone_number")]
    PhoneNumber { phone_number: String },

    #[serde(rename = "iss_sub")]
    IssuerSubject { iss: String, sub: String },

    #[serde(rename = "opaque")]
    Opaque { id: String },

    #[serde(rename = "did")]
    Did { url: String },

    #[serde(rename = "uri")]
    Uri { uri: String },

    #[serde(rename = "aliases")]
    Aliases { identifiers: Vec<Box<SubjectIdentifier>> },

    #[serde(rename = "jwt_id")]
    JwtId { iss: String, jti: String },

    #[serde(rename = "saml_assertion_id")]
    SamlAssertionId { issuer: String, assertion_id: String },

    #[serde(rename = "complex")]
    Complex(Box<ComplexSubject>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplexSubject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<Box<SubjectIdentifier>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<Box<SubjectIdentifier>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<Box<SubjectIdentifier>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<Box<SubjectIdentifier>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<Box<SubjectIdentifier>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_unit: Option<Box<SubjectIdentifier>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<Box<SubjectIdentifier>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialType {
    #[serde(rename = "password")]
    Password,
    #[serde(rename = "pin")]
    Pin,
    #[serde(rename = "x509")]
    X509,
    #[serde(rename = "fido2-platform")]
    Fido2Platform,
    #[serde(rename = "fido2-roaming")]
    Fido2Roaming,
    #[serde(rename = "fido-u2f")]
    FidoU2f,
    #[serde(rename = "verifiable-credential")]
    VerifiableCredential,
    #[serde(rename = "phone-voice")]
    PhoneVoice,
    #[serde(rename = "phone-sms")]
    PhoneSms,
    #[serde(rename = "app")]
    App,
}
