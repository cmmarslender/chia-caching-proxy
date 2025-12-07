use crate::client::BackendClient;
use http_body_util::BodyExt;
use hyper::body::Bytes;
use std::sync::Arc;

pub(crate) async fn proxy_handler(
    request_path: String,
    body_bytes: Bytes,
    backend_client: Arc<BackendClient>,
) -> anyhow::Result<Bytes> {
    // Make request to backend using the wrapper client (use normalized path)
    let response = backend_client.request(&request_path, body_bytes).await?;

    // Extract status and headers from the response
    let (_parts, body) = response.into_parts();

    Ok(body.collect().await?.to_bytes())
}
