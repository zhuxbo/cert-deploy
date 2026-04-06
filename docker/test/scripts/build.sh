#!/bin/bash
# 构建 sslctl 二进制 + Docker 镜像
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
TEST_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building sslctl binary ==="
mkdir -p "$TEST_DIR/build"
cd "$PROJECT_ROOT"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$TEST_DIR/build/sslctl" ./cmd/
echo "Binary: $TEST_DIR/build/sslctl"

echo "=== Building Docker images ==="
cd "$TEST_DIR"
docker compose build
echo "=== Build complete ==="

