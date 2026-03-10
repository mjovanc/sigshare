//! HTTP abstraction layer for [`crate::SsfClient`].
//!
//! Consumers that need custom transport (e.g. mTLS, retries, middleware)
//! can implement [`HttpClient`] directly. When the `reqwest` feature is
//! enabled, [`ReqwestClient`] provides a ready-made implementation.

use crate::error::Error;

/// Raw HTTP response returned by an [`HttpClient`] implementation.
pub struct HttpResponse {
    /// HTTP status code (e.g. `200`, `404`).
    pub status: u16,
    /// Response body as raw bytes.
    pub body: Vec<u8>,
}

/// HTTP method for a request.
#[derive(Debug, Clone, Copy)]
pub enum Method {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP PATCH.
    Patch,
    /// HTTP DELETE.
    Delete,
}

/// Trait abstracting HTTP transport for the SSF client.
///
/// Implement this to plug in your own HTTP stack. The [`crate::SsfClient`]
/// is generic over `C: HttpClient`, so any implementation works —
/// reqwest, hyper, a mock for testing, etc.
///
/// # Example
///
/// ```ignore
/// struct MyClient;
///
/// #[async_trait::async_trait]
/// impl HttpClient for MyClient {
///     async fn request(
///         &self,
///         method: Method,
///         url: &str,
///         headers: &[(&str, &str)],
///         body: Option<Vec<u8>>,
///     ) -> Result<HttpResponse, Error> {
///         // your implementation
///     }
/// }
/// ```
#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    /// Send an HTTP request and return the raw response.
    ///
    /// Implementations MUST:
    /// - Apply all entries from `headers` as request headers.
    /// - Send `body` as the request payload when `Some`.
    ///
    /// Implementations SHOULD NOT interpret status codes — the caller
    /// ([`crate::SsfClient`]) handles error status mapping.
    async fn request(
        &self,
        method: Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse, Error>;
}

/// [`HttpClient`] implementation backed by [`reqwest`].
///
/// Available when the `reqwest` feature is enabled. Automatically sets
/// `Content-Type: application/json` when a body is present.
#[cfg(feature = "reqwest")]
pub struct ReqwestClient {
    inner: reqwest::Client,
}

#[cfg(feature = "reqwest")]
impl ReqwestClient {
    /// Create a new client with the given request timeout.
    pub fn new(timeout: std::time::Duration) -> Result<Self, Error> {
        let inner =
            reqwest::Client::builder().timeout(timeout).build().map_err(Error::HttpClient)?;
        Ok(Self { inner })
    }
}

#[cfg(feature = "reqwest")]
#[async_trait::async_trait]
impl HttpClient for ReqwestClient {
    async fn request(
        &self,
        method: Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse, Error> {
        let mut builder = match method {
            Method::Get => self.inner.get(url),
            Method::Post => self.inner.post(url),
            Method::Put => self.inner.put(url),
            Method::Patch => self.inner.patch(url),
            Method::Delete => self.inner.delete(url),
        };

        for (key, value) in headers {
            builder = builder.header(*key, *value);
        }

        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }

        if let Some(body) = body {
            builder = builder.body(body);
        }

        let resp = builder.send().await.map_err(|e| Error::Http(Box::new(e)))?;

        Ok(HttpResponse {
            status: resp.status().as_u16(),
            body: resp.bytes().await.map_err(|e| Error::Http(Box::new(e)))?.to_vec(),
        })
    }
}
