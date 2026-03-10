//! SSF client for discovery, stream management, and event delivery.
//!
//! [`SsfClient`] is the single entry point for receivers interacting with an
//! SSF transmitter.

use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::cache::TtlCache;
use crate::error::Error;
use crate::http::{HttpClient, HttpResponse, Method};
use crate::set::SecurityEventToken;
use crate::ssf::{
    AddSubjectRequest, PollRequest, PollResponse, RemoveSubjectRequest, StreamConfiguration,
    StreamStatusResponse, StreamStatusUpdate, TransmitterConfiguration, VerificationRequest,
};

const SSF_WELL_KNOWN_PATH: &str = "/.well-known/ssf-configuration";

/// A client for interacting with an SSF transmitter.
///
/// Handles discovery, stream management, and poll delivery. Caches
/// [`TransmitterConfiguration`] per issuer with a configurable TTL.
pub struct SsfClient<C: HttpClient> {
    http: C,
    cache: TtlCache<TransmitterConfiguration>,
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

    /// Discover and cache the transmitter configuration for the given issuer.
    ///
    /// Fetches the `/.well-known/ssf-configuration` document, validates that
    /// the `issuer` field matches, and caches the result for the configured TTL.
    pub async fn discover(&self, issuer: &str) -> Result<TransmitterConfiguration, Error> {
        todo!()
    }

    /// Return the cached transmitter configuration, re-fetching if expired.
    pub async fn get_transmitter_config(
        &self,
        issuer: &str,
    ) -> Result<TransmitterConfiguration, Error> {
        todo!()
    }

    /// Remove the cached transmitter configuration for the given issuer.
    ///
    /// Returns `true` if an entry was removed, `false` if no entry existed.
    pub async fn invalidate_transmitter_config(&self, issuer: &str) -> bool {
        todo!()
    }

    /// Check whether the transmitter supports a given delivery method.
    pub async fn supports_delivery_method(
        &self,
        issuer: &str,
        method_urn: &str,
    ) -> Result<bool, Error> {
        todo!()
    }

    /// Return the list of event type URIs the transmitter supports, if advertised.
    pub async fn supported_events(&self, issuer: &str) -> Result<Option<Vec<String>>, Error> {
        todo!()
    }

    /// Create a new event stream (POST, SSF §8.1.1).
    ///
    /// The `token` is a Bearer token for authenticating with the transmitter.
    /// Tokens are accepted per-call to support short-lived / rotating OAuth2
    /// credentials without requiring interior mutability in the client.
    pub async fn create_stream(
        &self,
        issuer: &str,
        token: &str,
        config: &StreamConfiguration,
    ) -> Result<StreamConfiguration, Error> {
        todo!()
    }

    /// Read a stream's configuration by ID (GET, SSF §8.1.1).
    pub async fn get_stream(
        &self,
        issuer: &str,
        token: &str,
        stream_id: &str,
    ) -> Result<StreamConfiguration, Error> {
        todo!()
    }

    /// Fully replace a stream's configuration (PUT, SSF §8.1.1).
    ///
    /// Replaces the entire configuration. For partial updates, use
    /// [`update_stream`](Self::update_stream) instead.
    pub async fn replace_stream(
        &self,
        issuer: &str,
        token: &str,
        config: &StreamConfiguration,
    ) -> Result<StreamConfiguration, Error> {
        todo!()
    }

    /// Partially update a stream's configuration (PATCH, SSF §8.1.1).
    ///
    /// Merges the provided fields into the existing configuration. For a
    /// full replacement, use [`replace_stream`](Self::replace_stream) instead.
    pub async fn update_stream(
        &self,
        issuer: &str,
        token: &str,
        config: &StreamConfiguration,
    ) -> Result<StreamConfiguration, Error> {
        todo!()
    }

    /// Delete a stream (DELETE, SSF §8.1.1).
    pub async fn delete_stream(
        &self,
        issuer: &str,
        token: &str,
        stream_id: &str,
    ) -> Result<(), Error> {
        todo!()
    }

    /// List all streams for this receiver (GET, SSF §8.1.1).
    pub async fn list_streams(
        &self,
        issuer: &str,
        token: &str,
    ) -> Result<Vec<StreamConfiguration>, Error> {
        todo!()
    }

    /// Read a stream's current status (GET, SSF §8.1.2).
    pub async fn get_stream_status(
        &self,
        issuer: &str,
        token: &str,
        stream_id: &str,
    ) -> Result<StreamStatusResponse, Error> {
        todo!()
    }

    /// Update a stream's status (PATCH, SSF §8.1.2).
    pub async fn update_stream_status(
        &self,
        issuer: &str,
        token: &str,
        stream_id: &str,
        update: &StreamStatusUpdate,
    ) -> Result<StreamStatusResponse, Error> {
        todo!()
    }

    /// Add a subject to a stream (POST, SSF §8.1.3).
    pub async fn add_subject(
        &self,
        issuer: &str,
        token: &str,
        request: &AddSubjectRequest,
    ) -> Result<(), Error> {
        todo!()
    }

    /// Remove a subject from a stream (POST, SSF §8.1.3).
    pub async fn remove_subject(
        &self,
        issuer: &str,
        token: &str,
        request: &RemoveSubjectRequest,
    ) -> Result<(), Error> {
        todo!()
    }

    /// Request a verification event on a stream (POST, SSF §8.1.4).
    pub async fn verify_stream(
        &self,
        issuer: &str,
        token: &str,
        request: &VerificationRequest,
    ) -> Result<(), Error> {
        todo!()
    }

    /// Poll for queued SETs from the transmitter (POST, RFC 8936 §2).
    pub async fn poll(
        &self,
        endpoint_url: &str,
        token: &str,
        request: &PollRequest,
    ) -> Result<PollResponse, Error> {
        todo!()
    }

    /// Parse and validate a push-delivered SET (RFC 8935).
    ///
    /// Deserializes the raw body into a [`SecurityEventToken`] and validates
    /// that the `iss` and `aud` claims match the expected values.
    pub fn parse_push_set(
        &self,
        body: &[u8],
        expected_issuer: &str,
        expected_audience: &str,
    ) -> Result<SecurityEventToken, Error> {
        todo!()
    }

    /// Normalize and validate an issuer URL per SSF §7.2.
    fn validate_issuer_url(issuer: &str) -> Result<url::Url, Error> {
        todo!()
    }

    fn build_discovery_url(issuer: &str) -> Result<String, Error> {
        todo!()
    }

    fn validate_issuer_match(
        expected: &str,
        config: &TransmitterConfiguration,
    ) -> Result<(), Error> {
        todo!()
    }

    /// Resolve a transmitter endpoint URL from cached config.
    async fn resolve_endpoint(
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
    fn url_with_params(base: &str, params: &[(&str, &str)]) -> Result<String, Error> {
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
    async fn authenticated_request(
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
    async fn unauthenticated_get(&self, url: &str) -> Result<HttpResponse, Error> {
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
    async fn get_json<T: DeserializeOwned>(
        &self,
        url: &str,
        token: &str,
    ) -> Result<T, Error> {
        let resp = self.authenticated_request(Method::Get, url, token, None).await?;
        serde_json::from_slice(&resp.body).map_err(Error::InvalidResponse)
    }

    /// Authenticated POST with JSON body, deserialize JSON response.
    async fn post_json<T: DeserializeOwned, B: Serialize>(
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
    async fn patch_json<T: DeserializeOwned, B: Serialize>(
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
    async fn put_json<T: DeserializeOwned, B: Serialize>(
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
    async fn post_empty<B: Serialize>(
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
    async fn delete_empty(&self, url: &str, token: &str) -> Result<(), Error> {
        self.authenticated_request(Method::Delete, url, token, None).await?;
        Ok(())
    }
}
