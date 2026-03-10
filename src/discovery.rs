use crate::{Error, TransmitterConfiguration, client::SsfClient, http::HttpClient};

const SSF_WELL_KNOWN_PATH: &str = "/.well-known/ssf-configuration";

impl<C: HttpClient> SsfClient<C> {
    pub async fn discover(&self, issuer: &str) -> Result<TransmitterConfiguration, Error> {
        todo!()
    }

    pub async fn get_transmitter_config(
        &self,
        issuer: &str,
    ) -> Result<TransmitterConfiguration, Error> {
        todo!()
    }

    pub async fn invalidate_transmitter_config(&self, issuer: &str) {
        todo!()
    }

    fn validate_issuer_url(issuer: &str) -> Result<(), Error> {
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

    pub async fn supports_delivery_method(
        &self,
        issuer: &str,
        method_urn: &str,
    ) -> Result<bool, Error> {
        todo!()
    }

    pub async fn supported_events(&self, issuer: &str) -> Result<Option<Vec<String>>, Error> {
        todo!()
    }
}
