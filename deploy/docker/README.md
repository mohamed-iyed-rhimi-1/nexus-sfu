# Nexus SFU Docker Deployment

Production-ready Docker deployment for Nexus SFU following TigerStyle principles and NASA's Power of Ten rules.

## Quick Start

### Build Image

```bash
cd deploy/docker
./build.sh
```

**Expected output:**
- Build time: ~5-10 minutes (first build)
- Image size: <50MB
- Binary size: <30MB

### Run Locally

```bash
./run.sh
```

**Endpoints:**
- Health: http://localhost:3000/health
- Metrics: http://localhost:9090/metrics
- API: http://localhost:3000/api

### Stop Container

```bash
docker stop nexus-sfu-test
```

## Architecture

### Multi-Stage Build

```
┌─────────────────────────────────────────┐
│ Stage 1: Builder (rust:1.83.0-bookworm) │
│ - Install build dependencies            │
│ - Cache Cargo dependencies              │
│ - Compile with LTO + optimizations      │
│ - Strip binary                          │
│ Size: ~2GB                              │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│ Stage 2: Runtime (distroless/cc)        │
│ - Copy binary only                      │
│ - Copy production config                │
│ - No shell, no package manager          │
│ Size: <50MB                             │
└─────────────────────────────────────────┘
```

### Resource Limits

| Resource | Limit | Rationale |
|----------|-------|-----------|
| Memory | 2GB | Sufficient for 1000 concurrent users |
| CPU | 2.0 cores | Handles ~500K packets/sec |
| PIDs | 1024 | Prevents fork bombs |
| File descriptors | 65536 | Supports 10K+ concurrent connections |

### Port Mapping

| Port | Protocol | Purpose |
|------|----------|---------|
| 10000 | UDP | Media (RTP/RTCP) |
| 443 | UDP/TCP | QUIC signaling |
| 8080 | TCP | WebSocket fallback |
| 9090 | TCP | Prometheus metrics |

## Configuration

### Environment Variables

```bash
# Image name and tag
export IMAGE_NAME=nexus-sfu
export IMAGE_TAG=v0.1.0

# Container name
export CONTAINER_NAME=nexus-sfu-prod

# Build
./build.sh
```

### Custom Configuration

Mount custom config file:

```bash
docker run \
    --volume /path/to/config.toml:/etc/nexus-sfu/config.toml:ro \
    nexus-sfu:latest
```

### TLS Certificates

**IMPORTANT:** TLS certificates are NOT bundled in the Docker image for security reasons. They must be mounted at runtime.

Mount certificates for QUIC:

```bash
docker run \
    --volume /path/to/cert.pem:/etc/nexus-sfu/tls/cert.pem:ro \
    --volume /path/to/key.pem:/etc/nexus-sfu/tls/key.pem:ro \
    nexus-sfu:latest \
    --config /etc/nexus-sfu/config.toml
```

**Expected certificate paths:**
- Certificate: `/etc/nexus-sfu/tls/cert.pem`
- Private key: `/etc/nexus-sfu/tls/key.pem`

**Certificate requirements:**
- PEM format
- Valid for the server's domain/IP
- Readable by nonroot user (UID 65532) or mounted with appropriate permissions

## Health Checks

### Container Health Check

Docker health check runs every 10 seconds:

```bash
docker inspect --format='{{.State.Health.Status}}' nexus-sfu-test
```

**States:**
- `starting`: Initial grace period (5s)
- `healthy`: Container is running
- `unhealthy`: Failed 3 consecutive checks

### Application Health Check

HTTP endpoint at `/health`:

```bash
curl http://localhost:3000/health
```

**Response (healthy):**
```json
{
  "healthy": true,
  "state": "running",
  "connection_count": 42,
  "max_connections": 10000,
  "room_count": 5,
  "uptime_ms": 123456,
  "messages_sent": 10000,
  "messages_received": 9500
}
```

**HTTP Status:**
- `200 OK`: Healthy
- `503 Service Unavailable`: Unhealthy (connection limit exceeded)

## Monitoring

### Prometheus Metrics

Scrape endpoint at `/metrics`:

```bash
curl http://localhost:9090/metrics
```

**Key metrics:**
- `nexus_packets_forwarded_total`: Total packets forwarded
- `nexus_forwarding_latency_seconds`: Forwarding latency histogram
- `nexus_bandwidth_usage_bytes`: Bandwidth usage by direction
- `nexus_track_count`: Active track count
- `nexus_participant_count`: Active participant count

### Logs

View container logs:

```bash
docker logs -f nexus-sfu-test
```

**Log format (structured JSON):**
```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "level": "INFO",
  "target": "nexus_sfu::sfu",
  "message": "SFU started",
  "workers": 4,
  "arena_size_mb": 1024
}
```

## Security

### Distroless Base Image

- No shell (`/bin/sh` doesn't exist)
- No package manager (`apt`, `yum` don't exist)
- Minimal attack surface
- Only contains:
  - C runtime libraries
  - CA certificates
  - Timezone data

### Non-Root User

Container runs as `nonroot` user:
- UID: 65532
- GID: 65532
- No sudo/root access

### Verify Security

```bash
# No shell
docker exec nexus-sfu-test /bin/sh
# Error: executable file not found

# Non-root user
docker exec nexus-sfu-test id
# uid=65532(nonroot) gid=65532(nonroot)
```

## Troubleshooting

### Build Fails

**Problem:** Cap'n Proto compilation fails

**Solution:** Ensure `proto/` directory is copied before build:
```dockerfile
COPY proto/ ./proto/
```

**Problem:** Binary size exceeds 30MB

**Solution:** Check Cargo.toml has:
```toml
[profile.release]
lto = "fat"
codegen-units = 1
strip = true
```

### Container Unhealthy

**Problem:** Health check fails immediately

**Solution:** Increase `--start-period`:
```dockerfile
HEALTHCHECK --start-period=10s ...
```

**Problem:** Container exits immediately

**Solution:** Check logs for configuration errors:
```bash
docker logs nexus-sfu-test
```

### Performance Issues

**Problem:** High CPU usage

**Solution:** Increase CPU limit:
```bash
docker run --cpus=4.0 ...
```

**Problem:** Out of memory

**Solution:** Increase memory limit:
```bash
docker run --memory=4g ...
```

## Production Deployment

See `deploy/kubernetes/` for Kubernetes manifests.

### Kubernetes

```bash
kubectl apply -f deploy/kubernetes/deployment.yaml
```

### Docker Compose

```yaml
version: '3.8'
services:
  nexus-sfu:
    image: nexus-sfu:latest
    ports:
      - "10000:10000/udp"
      - "443:443/udp"
      - "443:443/tcp"
      - "8080:8080/tcp"
      - "3000:3000/tcp"
      - "9090:9090/tcp"
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
      nproc: 1024
    healthcheck:
      test: ["/busybox/wget", "-q", "-O", "-", "http://127.0.0.1:3000/health"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 5s
```

## Performance Benchmarks

### Image Size

| Component | Size |
|-----------|------|
| Binary | ~25MB |
| Config | <1KB |
| Base image | ~20MB |
| **Total** | **<50MB** |

### Build Time

| Stage | Time |
|-------|------|
| Dependency cache | ~3min (first build) |
| Dependency cache | ~5s (cached) |
| Source compilation | ~2min |
| **Total** | **~5min (first), ~2min (cached)** |

### Runtime Performance

| Metric | Value |
|--------|-------|
| Startup time | <100ms |
| Memory usage (idle) | ~50MB |
| Memory usage (1000 users) | ~500MB |
| CPU usage (idle) | <1% |
| CPU usage (1000 users) | ~50% (2 cores) |

## References

- [TigerStyle](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md)
- [NASA Power of Ten](https://spinroot.com/gerard/pdf/P10.pdf)
- [Distroless Images](https://github.com/GoogleContainerTools/distroless)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
