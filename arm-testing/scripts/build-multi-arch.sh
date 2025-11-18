#!/bin/bash
# Build multi-architecture Docker images for clj-ebpf testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "========================================="
echo "Multi-Architecture Docker Build"
echo "========================================="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed"
    exit 1
fi

# Check if buildx is available
if ! docker buildx version &> /dev/null; then
    echo "Error: Docker buildx is not available"
    echo "Please install Docker Desktop or enable buildx"
    exit 1
fi

# Create buildx builder if it doesn't exist
if ! docker buildx ls | grep -q multiarch; then
    echo "Creating multiarch builder..."
    docker buildx create --name multiarch --use --driver docker-container
    docker buildx inspect --bootstrap
fi

# Use the multiarch builder
docker buildx use multiarch

cd "$PROJECT_ROOT"

# Parse arguments
BUILD_AMD64=true
BUILD_ARM64=true
PUSH=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --amd64-only)
            BUILD_ARM64=false
            shift
            ;;
        --arm64-only)
            BUILD_AMD64=false
            shift
            ;;
        --push)
            PUSH=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --amd64-only    Build only AMD64 image"
            echo "  --arm64-only    Build only ARM64 image"
            echo "  --push          Push images to registry"
            echo "  --help          Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Determine platforms to build
PLATFORMS=""
if [[ "$BUILD_AMD64" == "true" ]] && [[ "$BUILD_ARM64" == "true" ]]; then
    PLATFORMS="linux/amd64,linux/arm64"
elif [[ "$BUILD_AMD64" == "true" ]]; then
    PLATFORMS="linux/amd64"
elif [[ "$BUILD_ARM64" == "true" ]]; then
    PLATFORMS="linux/arm64"
fi

echo "Building for platforms: $PLATFORMS"

# Build arguments
BUILD_ARGS="--platform $PLATFORMS"
BUILD_ARGS="$BUILD_ARGS -f arm-testing/docker/Dockerfile.arm64"
BUILD_ARGS="$BUILD_ARGS -t clj-ebpf:latest"

if [[ "$PUSH" == "true" ]]; then
    BUILD_ARGS="$BUILD_ARGS --push"
else
    BUILD_ARGS="$BUILD_ARGS --load"
fi

# Build the images
echo "Building images..."
docker buildx build $BUILD_ARGS .

echo ""
echo "========================================="
echo "Build completed successfully!"
echo "========================================="
echo ""
echo "Images built for: $PLATFORMS"
echo ""
echo "To run tests:"
echo "  AMD64: docker run --rm --privileged -v \$(pwd):/workspace clj-ebpf:latest bash -c 'cd /workspace && clojure -M:test'"
echo "  ARM64: docker run --rm --privileged --platform linux/arm64 -v \$(pwd):/workspace clj-ebpf:latest bash -c 'cd /workspace && clojure -M:test'"
echo ""
