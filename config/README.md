# Nexus SFU Configuration Guide

## Configuration Sources

Nexus SFU loads configuration from three sources (in order of precedence):

1. **Environment Variables** (highest priority)
2. **TOML Configuration File**
3. **Default Values** (lowest priority)

**Important:** Environment variables always override file values, even when using `--config` or `NEXUS_CONFIG_PATH`. This ensures sensitive values like JWT secrets and TLS paths are never accidentally dropped.

## Quick Start

### Development

```bash
# Use default development configuration
cargo run

# Or specify a config file
NEXUS_CONFIG_PATH=config/default.toml cargo run
```

### Production

```bash
# Set required environment variables
export NEXUS_JWT_SECRET="your-secret-key"
export NEXUS_TLS_CERT_PATH="/etc/nexus/tls/cert.pem"
export NEXUS_TLS_KEY_PATH="/etc/nexus/tls/key.pem"

# Run with production config
NEXUS_CONFIG_PATH=config/production.toml ./nexus-sfu
```

## Configuration Sections

### Transport Configuration

Controls network I/O and packet processing.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `media_bind_addr` | SocketAddr | `127.0.0.1:10000` | UDP address for RTP/RTCP |
| `signaling_bind_addr` | SocketAddr | `127.0.0.1:8080` | WebSocket fallback address |
| `recv_buffer_size_bytes` | u32 | `8388608` | UDP receive buffer (8MB dev, 16MB prod) |
| `send_buffer_size_bytes` | u32 | `8388608` | UDP send buffer (8MB dev, 16MB prod) |
| `batch_size` | u32 | `32` | Packets per sendmmsg batch |
| `batch_flush_interval_us` | u32 | `1000` | Batch flush timeout (1ms) |

**Validation:**
- All buffer sizes must be > 0 and <= 1GB
- `batch_size` must be power of 2 and <= 64

### Memory Configuration

Controls pre-allocated memory pools.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `arena_size_mb` | u32 | `64` | Packet arena size (64MB dev, 1GB prod) |
| `ring_buffer_size` | u32 | `1024` | Packets per track ring buffer |

**Validation:**
- `arena_size_mb` must be > 0 and <= 4096
- `ring_buffer_size` must be power of 2
- Arena must accommodate `max_track_actors * ring_buffer_size * 1500 bytes`

### Worker Configuration

Controls CPU-pinned worker threads.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `num_workers` | u32 | `0` | Worker count (0 = auto-detect) |
| `cpu_affinity` | bool | `false` | Pin workers to CPU cores |
| `realtime_priority` | bool | `false` | Use SCHED_FIFO (requires CAP_SYS_NICE) |

**Validation:**
- `num_workers` should not exceed 2x CPU core count
- `realtime_priority` requires Linux and CAP_SYS_NICE capability

### Room Configuration

Controls room limits and timeouts.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_participants_per_room` | u32 | `100` | Maximum participants per room |
| `max_rooms` | u32 | `100` | Maximum concurrent rooms |
| `empty_room_timeout_ms` | u32 | `30000` | Empty room cleanup timeout (30s) |

**Validation:**
- All values must be > 0
- `max_participants_per_room` must be <= 10000
- `max_rooms` must be <= 100000

### Bandwidth Estimation Configuration

Controls adaptive bitrate parameters.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `initial_bandwidth_bps` | u32 | `1000000` | Initial bandwidth estimate (1 Mbps) |
| `min_bandwidth_bps` | u32 | `100000` | Minimum bandwidth (100 Kbps) |
| `max_bandwidth_bps` | u32 | `10000000` | Maximum bandwidth (10 Mbps dev, 50 Mbps prod) |
| `loss_threshold_percent` | u32 | `5` | Packet loss threshold for decrease |
| `decrease_factor` | f64 | `0.85` | Bandwidth decrease multiplier |
| `increase_bps` | u32 | `100000` | Bandwidth increase step (100 Kbps) |

**Validation:**
- All bandwidth values must be > 0
- Must satisfy: `min_bandwidth_bps <= initial_bandwidth_bps <= max_bandwidth_bps`
- `loss_threshold_percent` must be <= 100
- `decrease_factor` must be in range (0.0, 1.0)

### QUIC Configuration

Controls QUIC transport settings.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bind_addr` | String | `127.0.0.1:8443` | QUIC bind address |
| `enable_0rtt` | bool | `true` | Enable 0-RTT session resumption |
| `max_connections` | u32 | `1000` | Maximum concurrent connections |
| `idle_timeout_ms` | u32 | `30000` | Connection idle timeout (30s) |
| `keep_alive_interval_ms` | u32 | `5000` | Keep-alive interval (5s) |
| `cert_path` | String | `./certs/dev-cert.pem` | TLS certificate path |
| `key_path` | String | `./certs/dev-key.pem` | TLS private key path |

**Note:** Override `cert_path` and `key_path` with environment variables in production.

### Gossip Configuration

Controls distributed state synchronization.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bind_addr` | String | `127.0.0.1:7946` | Gossip protocol bind address |
| `seeds` | Vec<String> | `[]` | Seed nodes for cluster discovery |
| `fanout` | u32 | `3` | Number of nodes to gossip with |
| `probe_interval_ms` | u32 | `1000` | Probe interval (1s) |
| `ping_timeout_ms` | u32 | `500` | Ping timeout (500ms) |
| `suspect_timeout_ms` | u32 | `5000` | Suspect timeout (5s) |

### Actor Configuration

Controls actor system limits.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_track_actors` | u32 | `10000` | Maximum track actors (10K dev, 1M prod) |
| `max_participant_actors` | u32 | `1000` | Maximum participant actors |
| `max_room_actors` | u32 | `100` | Maximum room actors |
| `message_queue_size` | u32 | `1024` | Message queue size per actor |
| `migration_queue_size` | u32 | `10` | Migration queue size |
| `supervision_restart_limit` | u32 | `3` | Max restarts before escalation |

**Validation:**
- All values must be > 0
- `max_track_actors` must be <= 1,000,000
- `message_queue_size` must be power of 2

### Metrics Configuration

Controls Prometheus metrics collection.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bind_addr` | String | `127.0.0.1:9090` | Prometheus metrics endpoint |
| `collection_interval_ms` | u32 | `1000` | Collection interval (1s) |
| `enable_prometheus` | bool | `true` | Enable Prometheus metrics |

**Validation:**
- `bind_addr` must be valid socket address
- `collection_interval_ms` must be > 0 and <= 60000

### Security Configuration

Controls authentication and encryption.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `jwt_secret` | String | `dev-secret-change-in-production` | JWT signing secret |

**Validation:**
- `jwt_secret` must not be empty
- Warning issued if using default secret

### Logging Configuration

Controls logging behavior.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `level` | LogLevel | `debug` | Log level (trace/debug/info/warn/error) |
| `structured` | bool | `true` | Enable structured logging |
| `include_timestamps` | bool | `true` | Include timestamps in logs |
| `include_thread_ids` | bool | `true` | Include thread IDs in logs |

## Environment Variables

### Required in Production

- `NEXUS_JWT_SECRET` - JWT signing secret (must be set)
- `NEXUS_TLS_CERT_PATH` - Path to TLS certificate
- `NEXUS_TLS_KEY_PATH` - Path to TLS private key

### Optional Overrides

- `NEXUS_CONFIG_PATH` - Path to TOML config file
- `NEXUS_WORKER_COUNT` - Override worker count
- `NEXUS_ARENA_SIZE_MB` - Override arena size
- `NEXUS_LOG_LEVEL` - Override log level (trace|debug|info|warn|error)
- `NEXUS_METRICS_ADDR` - Override Prometheus bind address

## Hot-Reload

Nexus SFU supports hot-reloading of control plane settings without restart.

**How it works:**
- Watches the config file specified by `--config` or `NEXUS_CONFIG_PATH`
- On file modification, reloads and validates the new configuration
- Applies environment variable overrides to maintain precedence
- Only applies changes if validation passes (invalid configs are logged and skipped)
- Only updates control plane settings (data plane requires restart)

**Hot-reloadable:**
- Logging level and format
- Metrics collection interval
- Room cleanup timeouts
- BWE parameters

**NOT hot-reloadable (require restart):**
- Memory allocation (arena, ring buffers)
- Worker count and CPU pinning
- Transport bind addresses
- QUIC/TLS configuration

To trigger reload, modify the config file. Invalid configurations will be rejected with an error log.

## Validation

All configuration values are validated on load with comprehensive assertions:

- **Positive space:** values that must be > 0
- **Negative space:** values that must be <= max
- **Relationships:** cross-module invariants
- **Type constraints:** power of 2, valid enums, etc.

Validation errors include field name and detailed message.

## Examples

### Development Configuration

See `config/default.toml` for development-friendly defaults with:
- Smaller memory limits
- Verbose logging
- No CPU pinning
- Single-node setup

### Production Configuration

See `config/production.toml` for production-optimized settings with:
- Larger memory pools
- Performance tuning
- CPU pinning enabled
- Multi-node cluster setup

### Custom Configuration

```toml
# custom.toml - Custom configuration example

[transport]
media_bind_addr = "0.0.0.0:10000"
signaling_bind_addr = "0.0.0.0:8080"
recv_buffer_size_bytes = 16777216
send_buffer_size_bytes = 16777216
batch_size = 64
batch_flush_interval_us = 1000

[memory]
arena_size_mb = 512
ring_buffer_size = 2048

[worker]
num_workers = 4
cpu_affinity = true
realtime_priority = false

# ... (other sections)
```

Run with:
```bash
# File-based config with env overrides
export NEXUS_JWT_SECRET="production-secret"
NEXUS_CONFIG_PATH=custom.toml ./nexus-sfu

# Or using CLI flag
./nexus-sfu --config custom.toml
```

**Note:** Environment variables will override file values in both cases.

## Troubleshooting

### Configuration fails to load

Check that:
- TOML syntax is valid
- All required fields are present
- File path is correct

### Validation errors

Read the error message carefully - it includes:
- Field name that failed validation
- Reason for failure
- Expected constraints

### Hot-reload not working

Ensure:
- `--config` flag or `NEXUS_CONFIG_PATH` environment variable is set
- File watcher has read permissions on the config file
- Only control plane settings are modified
- Configuration passes validation (check logs for validation errors)
- Environment variables are set if they override file values

### Performance issues

Consider:
- Increasing `arena_size_mb` for high track counts
- Enabling `cpu_affinity` and `realtime_priority`
- Tuning `batch_size` and buffer sizes
- Adjusting worker count based on CPU cores
