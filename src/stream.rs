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
}
