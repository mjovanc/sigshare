//! A Rust SDK for the [OpenID Shared Signals Framework][ssf] (SSF).
//!
//! `sigshare` provides types for constructing, serializing, and deserializing
//! [Security Event Tokens][rfc8417] (SETs) carrying [CAEP][caep-spec],
//! [RISC][risc-spec], and SSF management events. It covers the full data model
//! needed to build SSF transmitters and receivers that interoperate with any
//! spec-compliant system.
//!
//! # Specifications implemented
//!
//! | Spec | Coverage |
//! |------|----------|
//! | [RFC 8417 — Security Event Token][rfc8417] | SET claims, wire format, `events` map |
//! | [RFC 9493 — Subject Identifiers][rfc9493] | All 8 identifier formats, plus SSF-defined `jwt_id`, `saml_assertion_id`, and `complex` |
//! | [CAEP 1.0][caep-spec] | All 8 event types |
//! | [RISC 1.0][risc-spec] | 13 of 14 event types (deprecated `sessions-revoked` omitted) |
//! | [SSF 1.0][ssf] | Stream management, push/poll delivery, transmitter discovery |
//!
//! # Quick start
//!
//! Build a SET carrying a CAEP session-revoked event:
//!
//! ```
//! use sigshare::set::{SecurityEventTokenBuilder, SsfEvent};
//! use sigshare::caep::{CaepEvent, SessionRevoked, CaepCommon};
//!
//! let token = SecurityEventTokenBuilder::new()
//!     .iss("https://idp.example.com")
//!     .iat(1_700_000_000)
//!     .jti("unique-id-123")
//!     .event(SsfEvent::Caep(CaepEvent::SessionRevoked(SessionRevoked {
//!         common: CaepCommon::default(),
//!     })))
//!     .build()
//!     .unwrap();
//!
//! let json = serde_json::to_string_pretty(&token).unwrap();
//! let roundtrip: sigshare::SecurityEventToken = serde_json::from_str(&json).unwrap();
//! assert_eq!(token, roundtrip);
//! ```
//!
//! # Modules
//!
//! - [`set`] — Security Event Token and builder
//! - [`caep`] — CAEP 1.0 event types (session, credential, compliance, risk)
//! - [`risc`] — RISC 1.0 event types (account, identifier, recovery, opt-in/out)
//! - [`ssf`] — Stream management, delivery config, poll/push, transmitter metadata
//! - [`subject`] — Subject identifier formats per RFC 9493 and SSF 1.0
//! - [`error`] — Error types
//!
//! [ssf]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html
//! [rfc8417]: https://www.rfc-editor.org/rfc/rfc8417
//! [rfc9493]: https://www.rfc-editor.org/rfc/rfc9493
//! [caep-spec]: https://openid.net/specs/openid-caep-1_0.html
//! [risc-spec]: https://openid.net/specs/openid-risc-profile-specification-1_0.html

mod cache;
pub mod caep;
pub mod client;
pub mod discovery;
pub mod error;
pub mod http;
pub mod risc;
pub mod set;
pub mod ssf;
pub mod subject;

pub use caep::CaepEvent;
pub use error::{Error, SigshareError};
pub use risc::RiscEvent;
pub use set::{SecurityEventToken, SecurityEventTokenBuilder, SsfEvent};
pub use ssf::{StreamConfiguration, StreamStatus, TransmitterConfiguration};
pub use subject::{CredentialType, SubjectIdentifier};
