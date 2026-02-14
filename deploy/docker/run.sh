#!/usr/bin/env bash
# Run Nexus SFU Docker container locally for testing
# TigerStyle: explicit configuration, bounded resources

set -euo pipefail

# Constants
readonly IMAGE_NAME="${IMAGE_NAME:-nexus-sfu}"
readonly IMAGE_TAG="${IMAGE_TAG:-latest}"
readonly CONTAINER_NAME="${CONTAINER_NAME:-nexus-sfu-test}"

# Resource limits (TigerStyle: explicit bounds)
readonly MEMORY_LIMIT="2g"
readonly CPU_LIMIT="2.0"
readonly PIDS_LIMIT="1024"
readonly NOFILE_LIMIT="65536"

# Port mappings
readonly MEDIA_PORT="10000"
readonly QUIC_PORT="443"
readonly WEBSOCKET_PORT="8080"
readonly API_PORT="3000"
readonly METRICS_PORT="9090"

# Stop and remove existing container if it exists
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Stopping existing container ${CONTAINER_NAME}..."
    docker stop "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    docker rm "${CONTAINER_NAME}" >/dev/null 2>&1 || true
fi

echo "Starting Nexus SFU container"
echo "  Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo "  Container: ${CONTAINER_NAME}"
echo "  Memory limit: ${MEMORY_LIMIT}"
echo "  CPU limit: ${CPU_LIMIT}"
echo "  PIDs limit: ${PIDS_LIMIT}"
echo "  File descriptors limit: ${NOFILE_LIMIT}"
echo ""

# Run container with resource limits
# TigerStyle: explicit resource bounds
docker run \
    --name "${CONTAINER_NAME}" \
    --detach \
    --restart unless-stopped \
    --memory="${MEMORY_LIMIT}" \
    --cpus="${CPU_LIMIT}" \
    --pids-limit="${PIDS_LIMIT}" \
    --ulimit nofile="${NOFILE_LIMIT}:${NOFILE_LIMIT}" \
    --publish "${MEDIA_PORT}:10000/udp" \
    --publish "${QUIC_PORT}:443/udp" \
    --publish "${QUIC_PORT}:443/tcp" \
    --publish "${WEBSOCKET_PORT}:8080/tcp" \
    --publish "${API_PORT}:3000/tcp" \
    --publish "${METRICS_PORT}:9090/tcp" \
    --health-cmd="/busybox/wget -q -O - http://127.0.0.1:3000/health" \
    --health-interval=10s \
    --health-timeout=3s \
    --health-retries=3 \
    "${IMAGE_NAME}:${IMAGE_TAG}" \
    --api-addr 0.0.0.0:3000

# Wait for container to be healthy
echo "Waiting for container to be healthy..."
TIMEOUT=30
ELAPSED=0
while [[ $ELAPSED -lt $TIMEOUT ]]; do
    HEALTH=$(docker inspect --format='{{.State.Health.Status}}' "${CONTAINER_NAME}" 2>/dev/null || echo "starting")
    if [[ "${HEALTH}" == "healthy" ]]; then
        echo "Container is healthy!"
        break
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

if [[ $ELAPSED -ge $TIMEOUT ]]; then
    echo "Warning: Container did not become healthy within ${TIMEOUT}s" >&2
fi

# Show container status
echo ""
docker ps --filter "name=${CONTAINER_NAME}"
echo ""
echo "Container started successfully!"
echo "  Health endpoint: http://localhost:${API_PORT}/health"
echo "  Metrics endpoint: http://localhost:${METRICS_PORT}/metrics"
echo "  API endpoint: http://localhost:${API_PORT}/api"
echo ""
echo "View logs: docker logs -f ${CONTAINER_NAME}"
echo "Stop container: docker stop ${CONTAINER_NAME}"
