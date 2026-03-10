use crate::{
    Error, SecurityEventToken,
    client::SsfClient,
    http::HttpClient,
    ssf::{PollRequest, PollResponse},
};

impl<C: HttpClient> SsfClient<C> {
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
}
