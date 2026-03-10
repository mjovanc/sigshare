use crate::{Error, TransmitterConfiguration, client::SsfClient, http::HttpClient};

const SSF_WELL_KNOWN_PATH: &str = "/.well-known/ssf-configuration";

impl<C: HttpClient> SsfClient<C> {
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
}
