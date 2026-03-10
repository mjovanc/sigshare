use crate::{Error, StreamConfiguration, client::SsfClient, http::HttpClient};

impl<C: HttpClient> SsfClient<C> {
    pub async fn create_stream(
        &self,
        issuer: &str,
        token: &str,
        config: &StreamConfiguration,
    ) -> Result<StreamConfiguration, Error> {
        todo!()
    }
}
