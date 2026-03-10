//! SSF client for discovery, stream management, and event delivery.
//!
//! [`SsfClient`] is the single entry point for receivers interacting with an
//! SSF transmitter. Behavior is split across impl blocks in sibling modules:
//!
//! - [`crate::discovery`] — transmitter configuration discovery
//! - [`crate::stream`] — stream lifecycle, status, subjects, verification
//! - [`crate::delivery`] — poll-based delivery and push SET parsing

use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::cache::TtlCache;
use crate::error::Error;
use crate::http::{HttpClient, HttpResponse, Method};
use crate::ssf::TransmitterConfiguration;

/// A client for interacting with an SSF transmitter.
///
/// Handles discovery, stream management, and poll delivery. Caches
/// [`TransmitterConfiguration`] per issuer with a configurable TTL.
pub struct SsfClient<C: HttpClient> {
    pub(crate) http: C,
    pub(crate) cache: TtlCache<TransmitterConfiguration>,
}

impl<C: HttpClient> SsfClient<C> {
    /// Create a new client.
    ///
    /// `cache_ttl` controls how long a discovered [`TransmitterConfiguration`]
    /// is reused before re-fetching from the well-known endpoint.
    #[must_use]
    pub fn new(http: C, cache_ttl: Duration) -> Self {
        Self { http, cache: TtlCache::new(cache_ttl) }
    }

    /// Resolve a transmitter endpoint URL from cached config.
    pub(crate) async fn resolve_endpoint(
        &self,
        issuer: &str,
        extract: fn(&TransmitterConfiguration) -> Option<&String>,
        name: &'static str,
    ) -> Result<String, Error> {
        let config =
            self.cache.get(issuer).await.ok_or_else(|| Error::NotCached(issuer.to_owned()))?;

        extract(&config).cloned().ok_or(Error::MissingEndpoint(name))
    }

    /// Build a URL with optional query parameters.
    pub(crate) fn url_with_params(base: &str, params: &[(&str, &str)]) -> Result<String, Error> {
        if params.is_empty() {
            return Ok(base.to_owned());
        }

        let mut parsed =
            url::Url::parse(base).map_err(|e| Error::InvalidIssuerUrl(e.to_string()))?;
        {
            let mut query = parsed.query_pairs_mut();
            for (key, value) in params {
                query.append_pair(key, value);
            }
        }

        Ok(parsed.to_string())
    }

    /// Make an authenticated HTTP request and return the raw response.
    pub(crate) async fn authenticated_request(
        &self,
        method: Method,
        url: &str,
        token: &str,
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse, Error> {
        let auth = format!("Bearer {}", token);
        let headers = [("authorization", auth.as_str())];

        let resp = self.http.request(method, url, &headers, body).await?;

        if resp.status >= 400 {
            return Err(Error::HttpStatus {
                status: resp.status,
                body: String::from_utf8_lossy(&resp.body).into_owned(),
            });
        }

        Ok(resp)
    }

    /// Unauthenticated GET for discovery.
    pub(crate) async fn unauthenticated_get(&self, url: &str) -> Result<HttpResponse, Error> {
        let resp = self.http.request(Method::Get, url, &[], None).await?;

        if resp.status >= 400 {
            return Err(Error::HttpStatus {
                status: resp.status,
                body: String::from_utf8_lossy(&resp.body).into_owned(),
            });
        }

        Ok(resp)
    }

    /// Authenticated GET, deserialize JSON response.
    pub(crate) async fn get_json<T: DeserializeOwned>(
        &self,
        url: &str,
        token: &str,
    ) -> Result<T, Error> {
        let resp = self.authenticated_request(Method::Get, url, token, None).await?;
        serde_json::from_slice(&resp.body).map_err(Error::InvalidResponse)
    }

    /// Authenticated POST with JSON body, deserialize JSON response.
    pub(crate) async fn post_json<T: DeserializeOwned, B: Serialize>(
        &self,
        url: &str,
        token: &str,
        body: &B,
    ) -> Result<T, Error> {
        let bytes = serde_json::to_vec(body).map_err(Error::Serialization)?;
        let resp = self.authenticated_request(Method::Post, url, token, Some(bytes)).await?;
        serde_json::from_slice(&resp.body).map_err(Error::InvalidResponse)
    }

    /// Authenticated PATCH with JSON body, deserialize JSON response.
    pub(crate) async fn patch_json<T: DeserializeOwned, B: Serialize>(
        &self,
        url: &str,
        token: &str,
        body: &B,
    ) -> Result<T, Error> {
        let bytes = serde_json::to_vec(body).map_err(Error::Serialization)?;
        let resp = self.authenticated_request(Method::Patch, url, token, Some(bytes)).await?;
        serde_json::from_slice(&resp.body).map_err(Error::InvalidResponse)
    }

    /// Authenticated PUT with JSON body, deserialize JSON response.
    pub(crate) async fn put_json<T: DeserializeOwned, B: Serialize>(
        &self,
        url: &str,
        token: &str,
        body: &B,
    ) -> Result<T, Error> {
        let bytes = serde_json::to_vec(body).map_err(Error::Serialization)?;
        let resp = self.authenticated_request(Method::Put, url, token, Some(bytes)).await?;
        serde_json::from_slice(&resp.body).map_err(Error::InvalidResponse)
    }

    /// Authenticated POST with JSON body, expect no meaningful response body.
    pub(crate) async fn post_empty<B: Serialize>(
        &self,
        url: &str,
        token: &str,
        body: &B,
    ) -> Result<(), Error> {
        let bytes = serde_json::to_vec(body).map_err(Error::Serialization)?;
        self.authenticated_request(Method::Post, url, token, Some(bytes)).await?;
        Ok(())
    }

    /// Authenticated DELETE, expect no meaningful response body.
    pub(crate) async fn delete_empty(&self, url: &str, token: &str) -> Result<(), Error> {
        self.authenticated_request(Method::Delete, url, token, None).await?;
        Ok(())
    }
}
