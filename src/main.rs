mod client;
mod tls;

use crate::client::BackendClient;
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use rocksdb::{DB, Options, PrefixRange, ReadOptions};
use serde_json::Value;
use std::collections::HashSet;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

// Type alias for convenience
type SharedDB = Arc<DB>;
type CacheAllowlist = Arc<HashSet<String>>;

#[derive(Parser)]
#[command(name = "chia-caching-proxy")]
#[command(about = "A caching HTTP proxy for Chia full node RPC requests")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the proxy server (default)
    Serve,
    /// Fixup the coin cache by removing entries with spent: false
    FixupCoinCache,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::FixupCoinCache) => {
            fixup_coin_cache()?;
            Ok(())
        }
        Some(Commands::Serve) | None => serve().await,
    }
}

/// Open the Rocks DB database
fn open_db(create_if_missing: bool) -> anyhow::Result<DB> {
    let db_path = std::env::var("ROCKSDB_PATH").unwrap_or_else(|_| "rocksdb".to_string());
    let mut opts = Options::default();
    opts.create_if_missing(create_if_missing);
    Ok(DB::open(&opts, &db_path)?)
}

async fn serve() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Open rocksdb
    let db = Arc::new(open_db(true)?);

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

    // We create a TcpListener and bind it to 0.0.0.0:8555 (or PROXY_LISTEN_PORT env var)
    let port = std::env::var("PROXY_LISTEN_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8555);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
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
        // Check RocksDB for cached response
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

    // Clone data needed for async caching task
    let response_body_bytes_clone = response_body_bytes.clone();
    let db_clone = db.clone();
    let cache_key_clone = cache_key;
    let request_path_clone = request_path.clone();

    // Return response to client immediately
    let mut response_builder = Response::builder().status(parts.status);
    response_builder = response_builder.header("Content-Type", "application/json");

    if is_cacheable {
        response_builder = response_builder.header("X-Cache", "MISS");

        // Spawn background task to parse and cache if eligible
        tokio::task::spawn(async move {
            if let Ok(json_value) = serde_json::from_slice::<Value>(&response_body_bytes_clone)
                && should_cache_response(&request_path_clone, &json_value)
            {
                let _ = db_clone.put(cache_key_clone, &response_body_bytes_clone);
            }
        });
    } else {
        response_builder = response_builder.header("X-Cache", "SKIP");
    }

    Ok(response_builder
        .body(Full::new(response_body_bytes))
        .unwrap())
}

/// Check if a response should be cached based on the request path and JSON content.
///
/// General rule: Only cache if "success" field is true.
///
/// Path-specific rules:
/// - `/get_coin_record_by_name`: Additionally requires `.coin_record.spent` to be `true`.
///   This prevents caching unspent coins that might be spent later, which would invalidate the cache.
fn should_cache_response(request_path: &str, json_value: &Value) -> bool {
    // First check: response must have "success" field set to true
    let Some(success) = json_value.get("success") else {
        return false;
    };
    let Some(true) = success.as_bool() else {
        return false;
    };

    // Path-specific eligibility checks
    match request_path {
        "/get_coin_record_by_name" => {
            // Only cache if the coin is already spent (spent = true)
            // Unspent coins (spent = false) can be spent later, making the cache invalid
            if let Some(coin_record) = json_value.get("coin_record")
                && let Some(spent) = coin_record.get("spent")
                && let Some(true) = spent.as_bool()
            {
                return true;
            }

            false
        }
        _ => {
            // For other paths, just check success field (already verified above)
            true
        }
    }
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

/// Get the path hash for a given path (first 16 bytes of the cache key)
fn get_path_hash(path: &str) -> [u8; 16] {
    blake3_128(path.as_bytes())
}

/// Build a 32-byte composite key:
/// [16 bytes path-hash][16 bytes body-hash]
pub fn build_key(path: &str, body: &Bytes) -> [u8; 32] {
    let mut out = [0u8; 32];

    // 1. Hash path (namespace)
    let path_hash = get_path_hash(path);

    // 2. Hash body (specific request fingerprint)
    let body_hash = blake3_128(body.as_ref());

    // 3. Concatenate into final key
    out[0..16].copy_from_slice(&path_hash);
    out[16..32].copy_from_slice(&body_hash);

    out
}

/// Fixup the coin cache by removing entries with spent: false
fn fixup_coin_cache() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Open rocksdb (don't create if missing for fixup)
    let db = open_db(false)?;

    // Compute the path hash for /get_coin_record_by_name
    let target_path = "/get_coin_record_by_name";
    let target_path_hash = get_path_hash(target_path);

    println!("Scanning cache for {target_path} entries...");

    // Use prefix iteration to only scan keys with the matching path hash
    let mut read_options = ReadOptions::default();
    read_options.set_iterate_range(PrefixRange(&target_path_hash));
    let iter = db.iterator_opt(rocksdb::IteratorMode::Start, read_options);

    let mut checked = 0;
    let mut deleted = 0;

    for item in iter {
        let (key, value) = item?;

        // All keys from prefix iteration should match, but verify for safety
        // Keys are 32 bytes: [16 bytes path-hash][16 bytes body-hash]
        if key.len() == 32 && key[0..16] == target_path_hash {
            checked += 1;

            // Parse the cached value as JSON
            if let Ok(json_value) = serde_json::from_slice::<Value>(&value) {
                // Check if coin_record.spent is false
                if let Some(coin_record) = json_value.get("coin_record")
                    && let Some(spent) = coin_record.get("spent")
                    && let Some(false) = spent.as_bool()
                {
                    // Delete this entry
                    db.delete(&key)?;
                    deleted += 1;
                    if deleted % 100 == 0 {
                        println!("Deleted {deleted} entries so far...");
                    }
                }
            }
        } else {
            // Should not happen with prefix iteration, but break if we've gone past our prefix
            break;
        }
    }

    println!(
        "Fixup complete: checked {checked} entries, deleted {deleted} entries with spent: false"
    );

    Ok(())
}
