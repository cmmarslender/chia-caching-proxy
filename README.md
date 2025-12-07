# Chia Caching Proxy

A caching HTTP proxy for Chia full node RPC requests. This proxy intercepts requests to a Chia full node, caches responses based on request path and body, and returns cached responses for subsequent identical requests to improve performance.

## How It Works

The proxy listens for incoming HTTP requests and:
1. Checks if the request path is in the cache allowlist (if configured)
2. If cacheable, generates a cache key from the request path and body
3. Checks RocksDB for a cached response
4. Returns cached response if found (cache HIT)
5. Forwards the request to the Chia full node if not cached (cache MISS) or not cacheable
6. Returns the response to the client immediately (non-blocking)
7. Asynchronously parses the response JSON and caches it only if it contains `"success": true`

## Configuration

The proxy can be configured using the following environment variables:

### Backend Configuration
- `CHIA_FULL_NODE_HOST` - Hostname or IP address of the Chia full node (default: `127.0.0.1`)
- `CHIA_FULL_NODE_PORT` - Port of the Chia full node (default: `8555`)
- `UPSTREAM_TIMEOUT_SECONDS` - Timeout in seconds for upstream requests (default: `30`)

### Certificate Configuration
- `CHIA_CERT_PATH` - Path to the Chia full node certificate file (default: `~/.chia/config/ssl/full_node/private_full_node.crt`)
- `CHIA_KEY_PATH` - Path to the Chia full node private key file (default: `~/.chia/config/ssl/full_node/private_full_node.key`)

### Database Configuration
- `ROCKSDB_PATH` - Directory path for the RocksDB cache database (default: `rocksdb`)

### Server Configuration
- `PROXY_LISTEN_PORT` - Port for the proxy server to listen on (default: `8555`)

### Cache Configuration
- `CACHE_ALLOWLIST` - Comma-separated list of paths that should be cached. If not set or empty, no paths are cached (opt-in caching). Example: `/get_coin_record_by_name,/get_network_info`

## Security Warning

⚠️ **IMPORTANT**: This proxy accepts incoming connections **without requiring client certificates** and automatically adds the configured Chia certificates to forwarded requests. This means:

- The proxy does not authenticate incoming clients
- Anyone who can reach the proxy can make requests through it
- The proxy will authenticate to the Chia full node using the configured certificates

**This proxy is intended for use in private networks only**, such as:
- Kubernetes sidecar containers
- Internal service-to-service communication
- Local development environments

**DO NOT expose this proxy to the public internet** without additional security measures (firewall rules, network isolation, etc.).

## Usage

The proxy listens on `0.0.0.0:8555` by default (configurable via the `PROXY_LISTEN_PORT` environment variable). Simply point your Chia RPC clients to the proxy instead of directly to the full node.

### Running the Proxy

Example:
```bash
# Set environment variables
export CHIA_FULL_NODE_HOST=192.168.1.100
export CHIA_FULL_NODE_PORT=8555
export UPSTREAM_TIMEOUT_SECONDS=30
export ROCKSDB_PATH=/var/cache/chia-proxy
export CACHE_ALLOWLIST=/get_coin_record_by_name,/get_network_info

# Run the proxy (default command)
cargo run
# Or explicitly:
cargo run -- serve
```

### CLI Commands

The proxy supports the following commands:

- `serve` (default) - Run the proxy server
- `fixup-coin-cache` - Maintenance command to clean up the cache by removing entries for `/get_coin_record_by_name` where `spent: false`. This is useful if the cache contains unspent coins that were cached before the path-specific caching rules were implemented.

Example:
```bash
# Run the fixup command
cargo run -- fixup-coin-cache
```

### Cache Behavior

The proxy uses an opt-in caching model with success validation:
- **If `CACHE_ALLOWLIST` is not set or empty**: No requests are cached. All requests are forwarded to the backend and return `X-Cache: SKIP`.
- **If `CACHE_ALLOWLIST` is set**: Only requests to paths listed in the allowlist are eligible for caching. Cached requests return `X-Cache: HIT` or `X-Cache: MISS`, while non-cacheable requests return `X-Cache: SKIP`.

**Success-based caching**: Even for cacheable paths, responses are only cached if:
1. The response body is valid JSON
2. The JSON contains a `"success"` field
3. The `"success"` field has a value of `true`

This means error responses (even with HTTP 200 status) are never cached. The response is returned to the client immediately, and JSON parsing and caching happen asynchronously in the background, ensuring minimal latency.

All requests are still proxied to the backend regardless of cache configuration.

### Special Endpoints

#### `/get_coin_info`

The `/get_coin_info` endpoint is a special enhanced endpoint that:
- Always caches responses (not controlled by `CACHE_ALLOWLIST`)
- Provides enriched coin information including CAT2 and NFT metadata
- Parses parent coin puzzles to extract asset information
- Returns structured data with `coin_type`, `cat_info`, and `nft_info` fields

This endpoint is useful for applications that need detailed coin information without making multiple RPC calls.

### Path-Specific Caching Rules

Some endpoints have additional caching eligibility rules beyond the basic success check:

- **`/get_coin_record_by_name`**: Only caches responses where `coin_record.spent` is `true`. Unspent coins (`spent: false`) are not cached because they can be spent later, which would invalidate the cache. This prevents stale cache entries for coins that may change state.

All other cacheable paths follow the standard success-based caching rules.

