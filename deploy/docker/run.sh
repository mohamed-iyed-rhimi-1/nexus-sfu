#!/usr/bin/env bash
# Run the Nexus SFU Docker image locally with config/production.toml.
# TigerStyle: explicit configuration, bounded resources, fail early.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

readonly IMAGE_NAME="${IMAGE_NAME:-nexus-sfu}"
readonly IMAGE_TAG="${IMAGE_TAG:-latest}"
readonly CONTAINER_NAME="${CONTAINER_NAME:-nexus-sfu-test}"

# TLS certificate and key (PEM). Defaults to the self-signed dev pair in
# certs/. The SFU refuses to start if they are missing or unreadable.
readonly TLS_CERT="${TLS_CERT:-${PROJECT_ROOT}/certs/dev-cert.pem}"
readonly TLS_KEY="${TLS_KEY:-${PROJECT_ROOT}/certs/dev-key.pem}"

# Resource limits (TigerStyle: explicit bounds)
readonly MEMORY_LIMIT="2g"
readonly CPU_LIMIT="2.0"
readonly PIDS_LIMIT="1024"
readonly NOFILE_LIMIT="65536"

# Host ports. Container ports are fixed by config/production.toml.
readonly MEDIA_PORT="${MEDIA_PORT:-10000}"       # RTP/RTCP, udp
readonly SIGNAL_PORT="${SIGNAL_PORT:-443}"       # WSS on tcp, QUIC on udp
readonly API_PORT="${API_PORT:-8081}"            # REST API, /health, /ready
readonly METRICS_PORT="${METRICS_PORT:-9090}"    # Prometheus

readonly READY_TIMEOUT_SECONDS=30

for f in "${TLS_CERT}" "${TLS_KEY}"; do
    if [[ ! -r "${f}" ]]; then
        echo "Error: TLS file not found or unreadable: ${f}" >&2
        echo "Set TLS_CERT and TLS_KEY, or create a self-signed dev pair:" >&2
        echo "  mkdir -p certs && openssl req -x509 -newkey rsa:2048 -nodes -days 365 \\" >&2
        echo "    -subj /CN=localhost -keyout certs/dev-key.pem -out certs/dev-cert.pem" >&2
        exit 1
    fi
done

# The SFU refuses to start without a JWT secret (min 32 chars). For a local
# test run, generate one if the caller did not provide it.
if [[ -z "${NEXUS_JWT_SECRET:-}" ]]; then
    NEXUS_JWT_SECRET="$(openssl rand -hex 32)"
    echo "NEXUS_JWT_SECRET not set: generated a random one for this run."
fi

if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Removing existing container ${CONTAINER_NAME}..."
    docker rm -f "${CONTAINER_NAME}" >/dev/null
fi

echo "Starting ${IMAGE_NAME}:${IMAGE_TAG} as ${CONTAINER_NAME}"
echo "  TLS: ${TLS_CERT}, ${TLS_KEY}"
echo "  Limits: memory=${MEMORY_LIMIT} cpus=${CPU_LIMIT} pids=${PIDS_LIMIT} nofile=${NOFILE_LIMIT}"

# No Docker health check: the image is distroless (no shell, no wget).
# Readiness is probed from the host below.
docker run \
    --name "${CONTAINER_NAME}" \
    --detach \
    --restart unless-stopped \
    --memory="${MEMORY_LIMIT}" \
    --cpus="${CPU_LIMIT}" \
    --pids-limit="${PIDS_LIMIT}" \
    --ulimit nofile="${NOFILE_LIMIT}:${NOFILE_LIMIT}" \
    --env NEXUS_JWT_SECRET="${NEXUS_JWT_SECRET}" \
    --volume "${TLS_CERT}:/etc/nexus/tls/cert.pem:ro" \
    --volume "${TLS_KEY}:/etc/nexus/tls/key.pem:ro" \
    --publish "${MEDIA_PORT}:10000/udp" \
    --publish "${SIGNAL_PORT}:443/udp" \
    --publish "${SIGNAL_PORT}:443/tcp" \
    --publish "${API_PORT}:8081/tcp" \
    --publish "${METRICS_PORT}:9090/tcp" \
    "${IMAGE_NAME}:${IMAGE_TAG}" >/dev/null

echo "Waiting for /ready..."
for ((elapsed = 0; elapsed < READY_TIMEOUT_SECONDS; elapsed++)); do
    # --restart hides a crash loop behind "running", so count restarts too.
    state="$(docker inspect --format '{{.State.Running}} {{.RestartCount}}' "${CONTAINER_NAME}")"
    if [[ "${state}" != "true 0" ]]; then
        echo "Error: container exited during startup. Last log lines:" >&2
        docker logs --tail 5 "${CONTAINER_NAME}" >&2
        docker rm -f "${CONTAINER_NAME}" >/dev/null
        exit 1
    fi
    if curl -fsS "http://localhost:${API_PORT}/ready" >/dev/null 2>&1; then
        echo "Ready."
        break
    fi
    sleep 1
done

if ((elapsed >= READY_TIMEOUT_SECONDS)); then
    echo "Error: not ready after ${READY_TIMEOUT_SECONDS}s. Check: docker logs ${CONTAINER_NAME}" >&2
    exit 1
fi

echo ""
echo "  Signaling: wss://localhost:${SIGNAL_PORT} (QUIC on udp/${SIGNAL_PORT})"
echo "  Health:    http://localhost:${API_PORT}/health"
echo "  Metrics:   http://localhost:${METRICS_PORT}/metrics"
echo "  Logs:      docker logs -f ${CONTAINER_NAME}"
echo "  Stop:      docker rm -f ${CONTAINER_NAME}"
echo ""
echo "Note: UDP socket buffers are capped by the host's net.core.rmem_max /"
echo "wmem_max (not settable per container). See README, 'Host tuning (Linux)'."
