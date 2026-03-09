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
pub mod error;
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

pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    async fn get(&self, url: &str) -> Result<HttpResponse, Error>;

    async fn post(&self, url: &str, body: Vec<u8>) -> Result<HttpResponse, Error>;

    async fn put(&self, url: &str, body: Vec<u8>) -> Result<HttpResponse, Error>;

    async fn delete(&self, url: &str) -> Result<HttpResponse, Error>;
}

#[cfg(feature = "reqwest")]
pub(crate) struct ReqwestClient {
    inner: reqwest::Client,
}

#[cfg(feature = "reqwest")]
impl ReqwestClient {
    pub fn new(timeout: std::time::Duration) -> Result<Self, Error> {
        let inner =
            reqwest::Client::builder().timeout(timeout).build().map_err(Error::HttpClient)?;
        Ok(Self { inner })
    }
}

#[cfg(feature = "reqwest")]
#[async_trait::async_trait]
impl HttpClient for ReqwestClient {
    async fn get(&self, url: &str) -> Result<HttpResponse, Error> {
        let resp = self.inner.get(url).send().await.map_err(|e| Error::Http(Box::new(e)))?;
        Ok(HttpResponse {
            status: resp.status().as_u16(),
            body: resp.bytes().await.map_err(|e| Error::Http(Box::new(e)))?.to_vec(),
        })
    }
    async fn post(&self, url: &str, body: Vec<u8>) -> Result<HttpResponse, Error> {
        let resp = self
            .inner
            .post(url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| Error::Http(Box::new(e)))?;
        Ok(HttpResponse {
            status: resp.status().as_u16(),
            body: resp.bytes().await.map_err(|e| Error::Http(Box::new(e)))?.to_vec(),
        })
    }
    async fn put(&self, url: &str, body: Vec<u8>) -> Result<HttpResponse, Error> {
        let resp = self
            .inner
            .put(url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| Error::Http(Box::new(e)))?;
        Ok(HttpResponse {
            status: resp.status().as_u16(),
            body: resp.bytes().await.map_err(|e| Error::Http(Box::new(e)))?.to_vec(),
        })
    }
    async fn delete(&self, url: &str) -> Result<HttpResponse, Error> {
        let resp = self.inner.delete(url).send().await.map_err(|e| Error::Http(Box::new(e)))?;
        Ok(HttpResponse {
            status: resp.status().as_u16(),
            body: resp.bytes().await.map_err(|e| Error::Http(Box::new(e)))?.to_vec(),
        })
    }
}
