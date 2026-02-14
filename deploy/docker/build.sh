#!/usr/bin/env bash
# Build production Docker image for Nexus SFU
# TigerStyle: explicit error handling, bounded execution

set -euo pipefail

# Constants (TigerStyle: explicit bounds)
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly IMAGE_NAME="${IMAGE_NAME:-nexus-sfu}"
readonly IMAGE_TAG="${IMAGE_TAG:-latest}"
readonly BUILD_TIMEOUT_SECONDS=600

# Precondition assertions
if [[ ! -f "${PROJECT_ROOT}/Cargo.toml" ]]; then
    echo "Error: Cargo.toml not found in ${PROJECT_ROOT}" >&2
    exit 1
fi

if [[ ! -f "${PROJECT_ROOT}/config/production.toml" ]]; then
    echo "Error: config/production.toml not found" >&2
    exit 1
fi

# Print build information
echo "Building Nexus SFU Docker image"
echo "  Project root: ${PROJECT_ROOT}"
echo "  Image name: ${IMAGE_NAME}:${IMAGE_TAG}"
echo "  Build timeout: ${BUILD_TIMEOUT_SECONDS}s"
echo ""

# Build image with timeout
# TigerStyle: bounded execution time
timeout "${BUILD_TIMEOUT_SECONDS}" docker build \
    --file "${SCRIPT_DIR}/Dockerfile" \
    --tag "${IMAGE_NAME}:${IMAGE_TAG}" \
    --build-arg BUILDKIT_INLINE_CACHE=1 \
    --progress=plain \
    "${PROJECT_ROOT}"

# Verify image was created
if ! docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" >/dev/null 2>&1; then
    echo "Error: Image ${IMAGE_NAME}:${IMAGE_TAG} was not created" >&2
    exit 1
fi

# Get image size
IMAGE_SIZE=$(docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" \
    --format='{{.Size}}' | awk '{print int($1/1024/1024)}')

echo ""
echo "Build successful!"
echo "  Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo "  Size: ${IMAGE_SIZE}MB"

# Assert image size is reasonable (<50MB target)
# TigerStyle: assert bounds
if [[ "${IMAGE_SIZE}" -gt 50 ]]; then
    echo "Error: Image size ${IMAGE_SIZE}MB exceeds target of <50MB" >&2
    exit 1
fi

# Postcondition: image exists and is tagged
docker images "${IMAGE_NAME}:${IMAGE_TAG}"
