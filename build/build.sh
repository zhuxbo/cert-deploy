#!/usr/bin/env bash
# 仅负责从当前工作树构建 sslctl 的固定三平台产物。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="${1:-}"
OUTPUT_DIR="${2:-}"

if [[ -z "$VERSION" || -z "$OUTPUT_DIR" ]]; then
    echo "用法: $0 <x.y.z[-prerelease]> <output-dir>" >&2
    exit 2
fi
VERSION="${VERSION#v}"
python3 "$SCRIPT_DIR/release_helper.py" channel "$VERSION" >/dev/null

if ! command -v go >/dev/null 2>&1; then
    echo "错误: 未找到 Go" >&2
    exit 1
fi
if [[ -e "$OUTPUT_DIR" && -n "$(find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
    echo "错误: 输出目录必须为空，防止混入旧产物: $OUTPUT_DIR" >&2
    exit 1
fi
mkdir -p "$OUTPUT_DIR"

SOURCE_EPOCH="${SOURCE_DATE_EPOCH:-$(date +%s)}"
BUILD_TIME="$(python3 -c 'import datetime,sys; print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$SOURCE_EPOCH")"
LDFLAGS="-s -w -X main.version=$VERSION -X main.buildTime=$BUILD_TIME"

targets=("linux/amd64" "linux/arm64" "windows/amd64")
for target in "${targets[@]}"; do
    goos="${target%/*}"
    goarch="${target#*/}"
    name="sslctl-${goos}-${goarch}"
    [[ "$goos" == "windows" ]] && name+=".exe"
    echo "构建 $goos/$goarch -> $name"
    (
        cd "$PROJECT_DIR"
        CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
            go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$OUTPUT_DIR/$name" ./cmd/
    )
    gzip -n -9 -c "$OUTPUT_DIR/$name" >"$OUTPUT_DIR/$name.gz"
done

echo "构建完成: version=$VERSION build_time=$BUILD_TIME output=$OUTPUT_DIR"
