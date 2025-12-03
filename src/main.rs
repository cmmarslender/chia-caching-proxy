mod tls;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, Uri};
use hyper_util::rt::TokioIo;
use rocksdb::{DB, Options};
use rustls::ServerName;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

// Type alias for convenience
type SharedDB = Arc<DB>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Open rocksdb
    let mut opts = Options::default();
    opts.create_if_missing(true);
    let db = Arc::new(DB::open(&opts, "rocksdb")?);

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

        // Spawn a tokio task to serve multiple connections concurrently
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                // `service_fn` converts our function in a `Service`
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let db = db.clone();
                        async move { proxy_service(req, db).await }
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
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(proxy_handler(request, db).await.unwrap_or_else(|e| {
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

    let (cert, key) = tls::load_chia_certs()?;
    let tls_config = tls::make_client_config(cert, key)?;
    let tls_connector = TlsConnector::from(tls_config);

    // Open TCP connection to the remote host
    // @TODO make chia host and port configurable via env
    let host = "127.0.0.1";
    let port = "8555";
    let stream = TcpStream::connect(format!("{host}:{port}")).await?;

    // For IP addresses, use "localhost" since we're skipping verification anyway
    let domain_str = if host.parse::<std::net::IpAddr>().is_ok() {
        "localhost"
    } else {
        host
    };
    let domain = ServerName::try_from(domain_str)?;
    let tls_stream = tls_connector.connect(domain, stream).await?;

    // Use an adapter to access something implementing `tokio::io` traits as if they implement
    // `hyper::rt` IO traits.
    let io = TokioIo::new(tls_stream);

    // Create the Hyper client
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io).await?;

    // Spawn a task to poll the connection, driving the HTTP state
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {err:?}");
        }
    });

    let uri = format!("https://{host}:{port}{request_path}").parse::<Uri>()?;
    let mut request_builder = Request::builder().method(Method::POST).uri(uri);

    // Copy headers from the original request
    for (key, value) in &request_headers {
        request_builder = request_builder.header(key, value);
    }

    // Ensure Content-Type is set to application/json
    if !request_headers.contains_key("content-type") {
        request_builder = request_builder.header("content-type", "application/json");
    }

    let backend_request = request_builder.body(Full::new(body_bytes))?;

    // Send the request and get the response
    let response = sender.send_request(backend_request).await?;

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
