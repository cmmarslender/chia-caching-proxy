# Chia Caching Proxy

A caching HTTP proxy for Chia full node RPC requests. This proxy intercepts requests to a Chia full node, caches responses based on request path and body, and returns cached responses for subsequent identical requests to improve performance.

## How It Works

The proxy listens for incoming HTTP requests and:
1. Generates a cache key from the request path and body
2. Checks RocksDB for a cached response
3. Returns cached response if found (cache HIT)
4. Forwards the request to the Chia full node if not cached (cache MISS)
5. Stores the response in cache for future requests

## Configuration

The proxy can be configured using the following environment variables:

### Backend Configuration
- `CHIA_FULL_NODE_HOST` - Hostname or IP address of the Chia full node (default: `127.0.0.1`)
- `CHIA_FULL_NODE_PORT` - Port of the Chia full node (default: `8555`)

### Certificate Configuration
- `CHIA_CERT_PATH` - Path to the Chia full node certificate file (default: `~/.chia/config/ssl/full_node/private_full_node.crt`)
- `CHIA_KEY_PATH` - Path to the Chia full node private key file (default: `~/.chia/config/ssl/full_node/private_full_node.key`)

### Database Configuration
- `ROCKSDB_PATH` - Directory path for the RocksDB cache database (default: `rocksdb`)

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

The proxy listens on `0.0.0.0:3000` by default. Simply point your Chia RPC clients to the proxy instead of directly to the full node.

Example:
```bash
# Set environment variables
export CHIA_FULL_NODE_HOST=192.168.1.100
export CHIA_FULL_NODE_PORT=8555
export ROCKSDB_PATH=/var/cache/chia-proxy

# Run the proxy
cargo run
```

