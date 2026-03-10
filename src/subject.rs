//! Subject identifier formats per [RFC 9493] and [SSF §3].
//!
//! This module defines the [`SubjectIdentifier`] enum covering all 8 identifier
//! formats from [RFC 9493 §3.2] plus 3 formats defined by the Shared Signals
//! Framework ([SSF §3.5]):
//!
//! | Format | Spec |
//! |--------|------|
//! | `account` | [RFC 9493 §3.2.1] — `acct:` URI per RFC 7565 |
//! | `email` | [RFC 9493 §3.2.2] — email address per RFC 5322 |
//! | `iss_sub` | [RFC 9493 §3.2.3] — issuer + subject pair |
//! | `opaque` | [RFC 9493 §3.2.4] — opaque string identifier |
//! | `phone_number` | [RFC 9493 §3.2.5] — E.164 phone number |
//! | `did` | [RFC 9493 §3.2.6] — Decentralized Identifier (DID) URL |
//! | `uri` | [RFC 9493 §3.2.7] — generic URI |
//! | `aliases` | [RFC 9493 §3.2.8] — array of alternative identifiers |
//! | `jwt_id` | [SSF §3.5.1] — JWT ID (`iss` + `jti`) |
//! | `saml_assertion_id` | [SSF §3.5.2] — SAML assertion identifier |
//! | `complex` | [SSF §3.3] — composite subject with user, device, session, etc. |
//!
//! The module also defines [`ComplexSubject`] for the SSF complex subject format
//! and [`CredentialType`] for identifying credential kinds used in CAEP and RISC events.
//!
//! [RFC 9493]: https://www.rfc-editor.org/rfc/rfc9493
//! [RFC 9493 §3.2]: https://www.rfc-editor.org/rfc/rfc9493#section-3.2
//! [RFC 9493 §3.2.1]: https://www.rfc-editor.org/rfc/rfc9493#section-3.2.1
//! [RFC 9493 §3.2.2]: https://www.rfc-editor.org/rfc/rfc9493#section-3.2.2
//! [RFC 9493 §3.2.3]: https://www.rfc-editor.org/rfc/rfc9493#section-3.2.3
//! [RFC 9493 §3.2.4]: https://www.rfc-editor.org/rfc/rfc9493#section-3.2.4
//! [RFC 9493 §3.2.5]: https://www.rfc-editor.org/rfc/rfc9493#section-3.2.5
//! [RFC 9493 §3.2.6]: https://www.rfc-editor.org/rfc/rfc9493#section-3.2.6
//! [RFC 9493 §3.2.7]: https://www.rfc-editor.org/rfc/rfc9493#section-3.2.7
//! [RFC 9493 §3.2.8]: https://www.rfc-editor.org/rfc/rfc9493#section-3.2.8
//! [SSF §3]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3
//! [SSF §3.3]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.3
//! [SSF §3.5]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5
//! [SSF §3.5.1]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5.1
//! [SSF §3.5.2]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5.2

use serde::{Deserialize, Serialize};

/// A subject identifier as defined by [RFC 9493] and [SSF §3].
///
/// Each variant corresponds to one of the 11 subject identifier formats.
/// The enum is serialized with an internally-tagged `"format"` discriminator,
/// matching the wire format required by the specification.
///
/// # Example
///
/// ```
/// use sigshare::subject::SubjectIdentifier;
///
/// let email = SubjectIdentifier::Email {
///     email: "user@example.com".into(),
/// };
/// let json = serde_json::to_value(&email).unwrap();
/// assert_eq!(json["format"], "email");
/// assert_eq!(json["email"], "user@example.com");
/// ```
///
/// [RFC 9493]: https://www.rfc-editor.org/rfc/rfc9493
/// [SSF §3]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "format")]
pub enum SubjectIdentifier {
    /// Account identifier — an `acct:` URI per [RFC 7565](https://www.rfc-editor.org/rfc/rfc7565).
    #[serde(rename = "account")]
    Account { uri: String },

    /// Email address identifier per [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322).
    #[serde(rename = "email")]
    Email { email: String },

    /// Phone number identifier in E.164 format (e.g. `"+12065551234"`).
    #[serde(rename = "phone_number")]
    PhoneNumber { phone_number: String },

    /// Issuer + subject pair — uniquely identifies a subject within an issuer's namespace.
    #[serde(rename = "iss_sub")]
    IssuerSubject {
        /// The issuer URI.
        iss: String,
        /// The subject identifier within that issuer.
        sub: String,
    },

    /// Opaque identifier — a transmitter-specific string with no semantic meaning to receivers.
    #[serde(rename = "opaque")]
    Opaque { id: String },

    /// Decentralized Identifier (DID) URL per the [W3C DID Core](https://www.w3.org/TR/did-core/) spec.
    #[serde(rename = "did")]
    Did { url: String },

    /// Generic URI identifier per [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986).
    #[serde(rename = "uri")]
    Uri { uri: String },

    /// Aliases — an array of alternative [`SubjectIdentifier`]s that all refer to the same subject.
    #[serde(rename = "aliases")]
    Aliases { identifiers: Vec<Box<SubjectIdentifier>> },

    /// JWT ID — identifies a subject by the issuer and JWT ID (`jti`) of a token.
    #[serde(rename = "jwt_id")]
    JwtId {
        /// The token issuer.
        iss: String,
        /// The JWT ID (`jti` claim).
        jti: String,
    },

    /// SAML assertion identifier — identifies a subject by a SAML assertion.
    #[serde(rename = "saml_assertion_id")]
    SamlAssertionId {
        /// The SAML assertion issuer.
        issuer: String,
        /// The SAML assertion ID.
        assertion_id: String,
    },

    /// Complex subject — a composite identifier carrying multiple member
    /// identifiers (user, device, session, etc.) as defined by [SSF §3.3].
    ///
    /// [SSF §3.3]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.3
    #[serde(rename = "complex")]
    Complex(Box<ComplexSubject>),
}

/// A composite subject identifier defined by [SSF §3.3].
///
/// A complex subject bundles multiple member identifiers to describe a subject
/// along several dimensions (user, device, session, application, tenant, etc.).
/// All fields are optional; at least one should be present.
///
/// [SSF §3.3]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.3
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ComplexSubject {
    /// The user associated with the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<Box<SubjectIdentifier>>,
    /// The device associated with the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<Box<SubjectIdentifier>>,
    /// The session associated with the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<Box<SubjectIdentifier>>,
    /// The application (client) associated with the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<Box<SubjectIdentifier>>,
    /// The tenant associated with the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<Box<SubjectIdentifier>>,
    /// The organizational unit associated with the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_unit: Option<Box<SubjectIdentifier>>,
    /// The group associated with the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<Box<SubjectIdentifier>>,
}

/// Credential types used in CAEP and RISC events.
///
/// Identifies the kind of credential involved in a credential change or
/// credential compromise event. Values are defined in [CAEP §3.3] and
/// referenced by [RISC §2.7].
///
/// [CAEP §3.3]: https://openid.net/specs/openid-caep-1_0.html#section-3.3
/// [RISC §2.7]: https://openid.net/specs/openid-risc-profile-specification-1_0.html#section-2.7
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialType {
    /// A password credential.
    #[serde(rename = "password")]
    Password,
    /// A PIN credential.
    #[serde(rename = "pin")]
    Pin,
    /// An X.509 certificate credential.
    #[serde(rename = "x509")]
    X509,
    /// A FIDO2 platform authenticator (e.g. Touch ID, Windows Hello).
    #[serde(rename = "fido2-platform")]
    Fido2Platform,
    /// A FIDO2 roaming authenticator (e.g. a hardware security key).
    #[serde(rename = "fido2-roaming")]
    Fido2Roaming,
    /// A FIDO U2F security key.
    #[serde(rename = "fido-u2f")]
    FidoU2f,
    /// A verifiable credential per the [W3C VC Data Model](https://www.w3.org/TR/vc-data-model/).
    #[serde(rename = "verifiable-credential")]
    VerifiableCredential,
    /// A phone-based voice credential (voice call OTP).
    #[serde(rename = "phone-voice")]
    PhoneVoice,
    /// A phone-based SMS credential (SMS OTP).
    #[serde(rename = "phone-sms")]
    PhoneSms,
    /// An authenticator application (TOTP/HOTP app).
    #[serde(rename = "app")]
    App,
}
