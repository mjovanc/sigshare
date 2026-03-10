use crate::{
    Error, SecurityEventToken,
    client::SsfClient,
    http::HttpClient,
    ssf::{PollRequest, PollResponse},
};

impl<C: HttpClient> SsfClient<C> {
    pub async fn poll(
        &self,
        endpoint_url: &str,
        token: &str,
        request: &PollRequest,
    ) -> Result<PollResponse, Error> {
        todo!()
    }

    pub fn parse_push_set(
        &self,
        body: &[u8],
        expected_issuer: &str,
        expected_audience: &str,
    ) -> Result<SecurityEventToken, Error> {
        todo!()
    }
}
