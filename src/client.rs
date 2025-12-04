use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, Response, Uri};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;

/// Wrapper around hyper client that handles backend host/port configuration
#[derive(Clone)]
pub struct BackendClient {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    host: String,
    port: u16,
}

impl BackendClient {
    pub(crate) fn new(client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>) -> Self {
        let host = std::env::var("CHIA_FULL_NODE_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port = std::env::var("CHIA_FULL_NODE_PORT")
            .unwrap_or_else(|_| "8555".to_string())
            .parse()
            .unwrap_or(8555);

        Self { client, host, port }
    }

    pub(crate) async fn request(
        &self,
        path: &str,
        body: Bytes,
    ) -> anyhow::Result<Response<Full<Bytes>>> {
        let uri = format!("https://{}:{}{}", self.host, self.port, path).parse::<Uri>()?;
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
        let response = self.client.request(backend_request).await?;

        // Convert response body from Incoming to Full<Bytes>
        let (parts, body) = response.into_parts();
        let body_bytes = body.collect().await?.to_bytes();
        Ok(Response::from_parts(parts, Full::new(body_bytes)))
    }
}
