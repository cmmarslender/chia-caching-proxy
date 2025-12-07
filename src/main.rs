mod client;
mod handlers;
mod proxy_client;
mod tls;
mod wallet_sdk_extensions;

use clap::{Parser, Subcommand};
use client::BackendClient;
use handlers::get_coin_info::handle_get_coin_info;
use handlers::proxy_handler::proxy_handler;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use proxy_client::ProxyRpcClient;
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
    /// Clear cache for a particular endpoint
    ClearEndpointCache {
        /// The endpoint path to clear (e.g., `"/get_coin_info"` or `"get_coin_info"`)
        path: String,
    },
    /// Clear cache for a particular endpoint/request body combination
    ClearRequestCache,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::FixupCoinCache) => {
            fixup_coin_cache()?;
            Ok(())
        }
        Some(Commands::ClearEndpointCache { path }) => {
            clear_endpoint_cache(&path)?;
            Ok(())
        }
        Some(Commands::ClearRequestCache) => Ok(()),
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

    // Create the proxy RPC client once for reuse
    let proxy_rpc_client = Arc::new(ProxyRpcClient::new(backend_client.clone()));

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
        let proxy_rpc_client = proxy_rpc_client.clone();

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
                        let proxy_rpc_client = proxy_rpc_client.clone();
                        async move {
                            proxy_service(
                                req,
                                db,
                                backend_client,
                                cache_allowlist,
                                proxy_rpc_client,
                            )
                            .await
                        }
                    }),
                )
                .await
            {
                eprintln!("Error serving connection: {err:?}");
            }
        });
    }
}

/// Generic cached handler that wraps any handler function with caching logic.
/// Checks cache before calling handler, returns cached response if found,
/// and caches the response after returning it (in background).
/// The `request_cacheable` callback determines if a request should be cached based only on the request data.
/// The `response_cacheable` callback determines if the response is eligible for caching.
/// Both the request AND response must be eligible for caching to be stored into the cache DB
async fn cached_handler<F, Fut, P, R>(
    request: Request<hyper::body::Incoming>,
    db: SharedDB,
    request_cacheable: P,
    response_cacheable: R,
    handler: F,
) -> anyhow::Result<Response<Full<Bytes>>>
where
    F: FnOnce(&str, Bytes) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Bytes>>,
    P: FnOnce(&str) -> bool,
    R: FnOnce(&str, &Bytes) -> bool + Send + 'static,
{
    let request_path = request.uri().path();

    // Normalize path to ensure it starts with / for consistency
    let normalized_path = normalize_path(request_path);

    // Check if this path should be cached
    let is_cacheable = request_cacheable(&normalized_path);

    // Read request body for cache key generation
    let (_, body) = request.into_parts();
    let body_bytes = body.collect().await?.to_bytes();
    let cache_key = build_key(&normalized_path, &body_bytes);

    // Check RocksDB for cached response (only if cacheable)
    if is_cacheable && let Ok(Some(cached_value)) = db.get(cache_key) {
        let mut response_builder = Response::builder();
        response_builder = response_builder.header("Content-Type", "application/json");
        response_builder = response_builder.header("X-Cache", "HIT");
        return Ok(response_builder.body(Full::new(Bytes::from(cached_value)))?);
    }

    // Call the handler with body bytes directly
    let response_body_bytes = handler(&normalized_path, body_bytes).await?;

    // Clone data needed for async caching task
    let response_body_bytes_clone = response_body_bytes.clone();
    let db_clone = db.clone();
    let cache_key_clone = cache_key;
    let normalized_path_clone = normalized_path.clone();

    // Construct and return response to client immediately
    let mut response_builder = Response::builder()
        .status(200)
        .header("Content-Type", "application/json");

    if is_cacheable {
        response_builder = response_builder.header("X-Cache", "MISS");

        // Spawn background task to cache the response
        // Move response_cacheable into the task
        tokio::task::spawn(async move {
            if response_cacheable(&normalized_path_clone, &response_body_bytes_clone) {
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

async fn proxy_service(
    request: Request<hyper::body::Incoming>,
    db: SharedDB,
    backend_client: Arc<BackendClient>,
    cache_allowlist: CacheAllowlist,
    proxy_rpc_client: Arc<ProxyRpcClient>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let request_path = request.uri().path();

    // Route to appropriate handler based on path
    let result = match request_path {
        "/get_coin_info" => {
            cached_handler(
                request,
                db,
                |_path| true,            // Always cache /get_coin_info requests
                |_path, _response| true, // Always cache /get_coin_info responses
                |_path, body_bytes| handle_get_coin_info(body_bytes, proxy_rpc_client.clone()),
            )
            .await
        }
        _ => {
            // Fall back to proxy handler for all other paths
            cached_handler(
                request,
                db,
                |path| !cache_allowlist.is_empty() && cache_allowlist.contains(path),
                should_cache_response,
                |path, body_bytes| {
                    proxy_handler(path.to_string(), body_bytes, backend_client.clone())
                },
            )
            .await
        }
    };

    Ok(result.unwrap_or_else(|e| {
        eprintln!("Proxy Error: {e}");
        Response::builder()
            .status(500)
            .body(Full::from("internal error"))
            .unwrap()
    }))
}

/// Check if a response should be cached based on the request path and JSON content.
///
/// General rule: Only cache if "success" field is true.
///
/// Path-specific rules:
/// - `/get_coin_record_by_name`: Additionally requires `.coin_record.spent` to be `true`.
///   This prevents caching unspent coins that might be spent later, which would invalidate the cache.
fn should_cache_response(request_path: &str, json_bytes: &Bytes) -> bool {
    let Ok(json_value) = serde_json::from_slice::<Value>(json_bytes) else {
        return false;
    };
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

/// Normalize a path to ensure it starts with / for consistency.
/// If the path already starts with /, it's returned as-is.
/// Otherwise, a leading / is prepended.
fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
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
/// Normalizes the path to ensure it starts with / for cache consistency
fn get_path_hash(path: &str) -> [u8; 16] {
    let normalized_path = normalize_path(path);
    blake3_128(normalized_path.as_bytes())
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

/// Clear cache for a particular endpoint by deleting all entries with the path prefix
fn clear_endpoint_cache(path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Open rocksdb (don't create if missing)
    let db = open_db(false)?;

    // Normalize path to ensure it starts with / for consistency
    let normalized_path = normalize_path(path);

    // Get the path hash for the normalized path
    let path_hash = get_path_hash(&normalized_path);

    println!("Clearing cache for endpoint: {normalized_path}");

    // Use prefix iteration to only scan keys with the matching path hash
    let mut read_options = ReadOptions::default();
    read_options.set_iterate_range(PrefixRange(&path_hash));
    let iter = db.iterator_opt(rocksdb::IteratorMode::Start, read_options);

    let mut deleted = 0;

    for item in iter {
        let (key, _) = item?;

        // All keys from prefix iteration should match, but verify for safety
        // Keys are 32 bytes: [16 bytes path-hash][16 bytes body-hash]
        if key.len() == 32 && key[0..16] == path_hash {
            // Delete this entry
            db.delete(&key)?;
            deleted += 1;
            if deleted % 100 == 0 {
                println!("Deleted {deleted} entries so far...");
            }
        } else {
            // Should not happen with prefix iteration, but break if we've gone past our prefix
            break;
        }
    }

    println!("Cache clear complete: deleted {deleted} entries for {normalized_path}");

    Ok(())
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
