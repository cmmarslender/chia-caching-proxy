mod tls;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioIo;
use rocksdb::{DB, Options};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

// Type alias for convenience
type SharedDB = Arc<DB>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Open rocksdb
    let mut opts = Options::default();
    opts.create_if_missing(true);
    let db = Arc::new(DB::open(&opts, "rocksdb")?);

    // Create a shared hyper client
    let (cert, key) = tls::load_chia_certs()?;
    let tls_config = tls::make_client_config(cert, key)?;
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .build();
    let client =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build::<_, Full<Bytes>>(https);

    // We create a TcpListener and bind it to 127.0.0.1:3000
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(addr).await?;

    // Start a loop to continuously accept incoming connections
    loop {
        let (stream, _) = listener.accept().await?;

        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(stream);

        // clone for each connection task
        let db = db.clone();
        let client = client.clone();

        // Spawn a tokio task to serve multiple connections concurrently
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                // `service_fn` converts our function in a `Service`
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let db = db.clone();
                        let client = client.clone();
                        async move { proxy_service(req, db, client).await }
                    }),
                )
                .await
            {
                eprintln!("Error serving connection: {err:?}");
            }
        });
    }
}

async fn proxy_service(
    request: Request<hyper::body::Incoming>,
    db: SharedDB,
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(proxy_handler(request, db, client)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Proxy Error: {e}");
            Response::builder()
                .status(500)
                .body(Full::from("internal error"))
                .unwrap()
        }))
}

async fn proxy_handler(
    request: Request<hyper::body::Incoming>,
    db: SharedDB,
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let request_path = request.uri().path().to_owned();
    let request_headers = request.headers().clone();

    let mut body_bytes = request.collect().await?.to_bytes();
    // Ensure body is at least "{}" if empty
    if body_bytes.is_empty() {
        body_bytes = Bytes::from("{}");
    }

    // Generate the cache key and check RocksDB
    let cache_key = build_key(&request_path, &body_bytes);
    if let Ok(Some(cached_value)) = db.get(cache_key) {
        let mut response_builder = Response::builder();
        response_builder = response_builder.header("Content-Type", "application/json");
        response_builder = response_builder.header("X-Cache", "HIT");
        return Ok(response_builder.body(Full::new(Bytes::from(cached_value)))?);
    }

    // Open TCP connection to the remote host
    // @TODO make chia host and port configurable via env
    let host = "127.0.0.1";
    let port = "8555";
    let uri = format!("https://{host}:{port}{request_path}").parse::<Uri>()?;
    let mut request_builder = Request::builder().method(Method::POST).uri(uri);

    // Copy headers from the original request
    let headers = request_builder.headers_mut().unwrap();
    for (key, value) in &request_headers {
        headers.insert(key, value.clone());
    }

    // Ensure Content-Type is set to application/json
    if !request_headers.contains_key("content-type") {
        headers.insert("content-type", "application/json".parse().unwrap());
    }

    let backend_request = request_builder.body(Full::new(body_bytes))?;
    let response = client.request(backend_request).await?;

    // Extract status and headers from the response
    let (parts, body) = response.into_parts();

    // Read the response body
    let response_body_bytes = body.collect().await?.to_bytes();

    let mut response_builder = Response::builder().status(parts.status);
    response_builder = response_builder.header("Content-Type", "application/json");
    response_builder = response_builder.header("X-Cache", "MISS");

    let _ = db.put(cache_key, &response_body_bytes);

    Ok(response_builder
        .body(Full::new(response_body_bytes))
        .unwrap())
}

/// Hash input with BLAKE3 and return the first 16 bytes.
fn blake3_128(input: &[u8]) -> [u8; 16] {
    let full = blake3::hash(input);
    let truncated = &full.as_bytes()[0..16];
    truncated.try_into().unwrap() // [u8; 16]
}

/// Build a 32-byte composite key:
/// [16 bytes path-hash][16 bytes body-hash]
pub fn build_key(path: &str, body: &Bytes) -> [u8; 32] {
    let mut out = [0u8; 32];

    // 1. Hash path (namespace)
    let path_hash = blake3_128(path.as_bytes());

    // 2. Hash body (specific request fingerprint)
    let body_hash = blake3_128(body.as_ref());

    // 3. Concatenate into final key
    out[0..16].copy_from_slice(&path_hash);
    out[16..32].copy_from_slice(&body_hash);

    out
}
