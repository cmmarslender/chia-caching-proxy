mod client;
mod tls;

use crate::client::BackendClient;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use rocksdb::{DB, Options};
use std::collections::HashSet;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

// Type alias for convenience
type SharedDB = Arc<DB>;
type CacheAllowlist = Arc<HashSet<String>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Open rocksdb
    let db_path = std::env::var("ROCKSDB_PATH").unwrap_or_else(|_| "rocksdb".to_string());
    let mut opts = Options::default();
    opts.create_if_missing(true);
    let db = Arc::new(DB::open(&opts, &db_path)?);

    // Load cache allowlist from environment variable
    let cache_allowlist = Arc::new(load_cache_allowlist());

    // Create a shared hyper client
    let (cert, key) = tls::load_chia_certs()?;
    let tls_config = tls::make_client_config(cert, key)?;
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .build();
    let hyper_client =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build::<_, Full<Bytes>>(https);
    let backend_client = Arc::new(BackendClient::new(hyper_client));

    // We create a TcpListener and bind it to 0.0.0.0:3000
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = TcpListener::bind(addr).await?;

    // Start a loop to continuously accept incoming connections
    loop {
        let (stream, _) = listener.accept().await?;

        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(stream);

        // clone for each connection task
        let db = db.clone();
        let backend_client = backend_client.clone();
        let cache_allowlist = cache_allowlist.clone();

        // Spawn a tokio task to serve multiple connections concurrently
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                // `service_fn` converts our function in a `Service`
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let db = db.clone();
                        let backend_client = backend_client.clone();
                        let cache_allowlist = cache_allowlist.clone();
                        async move { proxy_service(req, db, backend_client, cache_allowlist).await }
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
    backend_client: Arc<BackendClient>,
    cache_allowlist: CacheAllowlist,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(proxy_handler(request, db, backend_client, cache_allowlist)
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
    backend_client: Arc<BackendClient>,
    cache_allowlist: CacheAllowlist,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let request_path = request.uri().path().to_owned();
    let body_bytes = request.collect().await?.to_bytes();

    // Check if this path is allowed to be cached
    // Only cache if allowlist is not empty AND path is in the allowlist
    let is_cacheable = !cache_allowlist.is_empty() && cache_allowlist.contains(&request_path);
    let cache_key = build_key(&request_path, &body_bytes);

    if is_cacheable {
        // Generate the cache key and check RocksDB
        let cache_key = build_key(&request_path, &body_bytes);
        if let Ok(Some(cached_value)) = db.get(cache_key) {
            let mut response_builder = Response::builder();
            response_builder = response_builder.header("Content-Type", "application/json");
            response_builder = response_builder.header("X-Cache", "HIT");
            return Ok(response_builder.body(Full::new(Bytes::from(cached_value)))?);
        }
    }

    // Make request to backend using the wrapper client
    let response = backend_client.request(&request_path, body_bytes).await?;

    // Extract status and headers from the response
    let (parts, body) = response.into_parts();

    // Read the response body
    let response_body_bytes = body.collect().await?.to_bytes();

    let mut response_builder = Response::builder().status(parts.status);
    response_builder = response_builder.header("Content-Type", "application/json");

    if is_cacheable {
        // Cache the respons
        let _ = db.put(cache_key, &response_body_bytes);
        response_builder = response_builder.header("X-Cache", "MISS");
    } else {
        response_builder = response_builder.header("X-Cache", "SKIP");
    }

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

/// Load cache allowlist from environment variable.
/// If `CACHE_ALLOWLIST` is set, it should be a comma-separated list of paths.
/// If empty or not set, no paths are cacheable (empty allowlist = cache nothing).
fn load_cache_allowlist() -> HashSet<String> {
    match std::env::var("CACHE_ALLOWLIST") {
        Ok(val) => {
            if val.trim().is_empty() {
                HashSet::new() // Empty allowlist = cache nothing
            } else {
                val.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
        }
        Err(_) => HashSet::new(), // Not set = cache nothing
    }
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
