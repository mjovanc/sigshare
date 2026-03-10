use crate::{
    Error, StreamConfiguration,
    client::SsfClient,
    http::HttpClient,
    ssf::{
        AddSubjectRequest, RemoveSubjectRequest, StreamStatusResponse, StreamStatusUpdate,
        VerificationRequest,
    },
};

impl<C: HttpClient> SsfClient<C> {
    pub async fn create_stream(
        &self,
        issuer: &str,
        token: &str,
        config: &StreamConfiguration,
    ) -> Result<StreamConfiguration, Error> {
        todo!()
    }

    pub async fn get_stream(
        &self,
        issuer: &str,
        token: &str,
        stream_id: &str,
    ) -> Result<StreamConfiguration, Error> {
        todo!()
    }

    pub async fn replace_stream(
        &self,
        issuer: &str,
        token: &str,
        config: &StreamConfiguration,
    ) -> Result<StreamConfiguration, Error> {
        todo!()
    }

    pub async fn update_stream(
        &self,
        issuer: &str,
        token: &str,
        config: &StreamConfiguration,
    ) -> Result<StreamConfiguration, Error> {
        todo!()
    }

    pub async fn delete_stream(
        &self,
        issuer: &str,
        token: &str,
        stream_id: &str,
    ) -> Result<(), Error> {
        todo!()
    }

    pub async fn list_streams(
        &self,
        issuer: &str,
        token: &str,
    ) -> Result<Vec<StreamConfiguration>, Error> {
        todo!()
    }

    pub async fn get_stream_status(
        &self,
        issuer: &str,
        token: &str,
        stream_id: &str,
    ) -> Result<StreamStatusResponse, Error> {
        todo!()
    }

    pub async fn update_stream_status(
        &self,
        issuer: &str,
        token: &str,
        stream_id: &str,
        update: &StreamStatusUpdate,
    ) -> Result<StreamStatusResponse, Error> {
        todo!()
    }

    pub async fn add_subject(
        &self,
        issuer: &str,
        token: &str,
        request: &AddSubjectRequest,
    ) -> Result<(), Error> {
        todo!()
    }

    pub async fn remove_subject(
        &self,
        issuer: &str,
        token: &str,
        request: &RemoveSubjectRequest,
    ) -> Result<(), Error> {
        todo!()
    }

    pub async fn verify_stream(
        &self,
        issuer: &str,
        token: &str,
        request: &VerificationRequest,
    ) -> Result<(), Error> {
        todo!()
    }
}
