use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, Response, Uri};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use std::time::Duration;
use tokio::time;

/// Wrapper around hyper client that handles backend host/port configuration
#[derive(Clone)]
pub struct BackendClient {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    host: String,
    port: u16,
    timeout: Duration,
}

impl BackendClient {
    pub(crate) fn new(client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>) -> Self {
        let host = std::env::var("CHIA_FULL_NODE_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port = std::env::var("CHIA_FULL_NODE_PORT")
            .unwrap_or_else(|_| "8555".to_string())
            .parse()
            .unwrap_or(8555);

        // Load timeout from environment variable (default: 30 seconds)
        let timeout_secs = std::env::var("UPSTREAM_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "30".to_string())
            .parse()
            .unwrap_or(30);
        let timeout = Duration::from_secs(timeout_secs);

        Self {
            client,
            host,
            port,
            timeout,
        }
    }

    pub(crate) async fn request(
        &self,
        path: &str,
        body: Bytes,
    ) -> anyhow::Result<Response<Full<Bytes>>> {
        // Ensure path starts with /
        let normalized_path = if path.starts_with('/') {
            path
        } else {
            return Err(anyhow::anyhow!("Path must start with /, got: {path}"));
        };
        let uri =
            format!("https://{}:{}{}", self.host, self.port, normalized_path).parse::<Uri>()?;
        let mut request_builder = Request::builder().method(Method::POST).uri(uri);

        // Copy headers from the original request
        let request_headers = request_builder.headers_mut().unwrap();
        request_headers.insert("content-type", "application/json".parse().unwrap());

        // Normalize empty request body to "{}"
        let request_body = if body.is_empty() {
            Bytes::from("{}")
        } else {
            body
        };

        let backend_request = request_builder.body(Full::new(request_body))?;

        // Apply timeout to the request
        let response = time::timeout(self.timeout, self.client.request(backend_request))
            .await
            .map_err(|_| anyhow::anyhow!("Request to upstream timed out after {:?}", self.timeout))?
            .map_err(|e| anyhow::anyhow!("Request to upstream failed: {e}"))?;

        // Convert response body from Incoming to Full<Bytes>
        let (parts, body) = response.into_parts();
        let body_bytes = body.collect().await?.to_bytes();
        Ok(Response::from_parts(parts, Full::new(body_bytes)))
    }
}
