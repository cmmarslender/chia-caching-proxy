use crate::handlers::proxy_handler;
use chia_wallet_sdk::prelude::ChiaRpcClient;
use hyper::body::Bytes;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::sync::Arc;

/// A wrapper around `ChiaRpcClient` that routes all calls through the local proxy
/// to leverage caching instead of making direct network calls.
pub struct ProxyRpcClient {
    backend_client: Arc<crate::client::BackendClient>,
    base_url: String,
}

impl ProxyRpcClient {
    pub fn new(backend_client: Arc<crate::client::BackendClient>) -> Self {
        Self {
            backend_client,
            // base_url is required by the trait but not used since we route through proxy internally
            base_url: "http://localhost".to_string(),
        }
    }
}

impl ChiaRpcClient for ProxyRpcClient {
    type Error = anyhow::Error;

    fn base_url(&self) -> &str {
        &self.base_url
    }

    async fn make_post_request<R, B>(&self, endpoint: &str, body: B) -> Result<R, Self::Error>
    where
        B: Serialize + Send,
        R: DeserializeOwned + Send,
    {
        // Convert the JSON body to bytes
        let body_bytes = Bytes::from(serde_json::to_vec(&body)?);

        // Ensure endpoint starts with /
        let path = if endpoint.starts_with('/') {
            endpoint.to_string()
        } else {
            format!("/{endpoint}")
        };

        // Call the proxy handler internally to get the cached response
        let response_bytes =
            proxy_handler::proxy_handler(path, body_bytes, self.backend_client.clone()).await?;

        // Parse the JSON response into the requested type
        let json_response: R = serde_json::from_slice(&response_bytes)?;

        Ok(json_response)
    }
}
