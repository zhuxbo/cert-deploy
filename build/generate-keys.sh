#!/bin/bash

# Ed25519 密钥对生成脚本
# 用于 sslctl 升级模块的数字签名验证
#
# 用法:
#   ./generate-keys.sh                              # 生成密钥对到当前目录（key ID: key-1）
#   ./generate-keys.sh /path/to/output              # 生成密钥对到指定目录
#   ./generate-keys.sh /path/to/output key-2        # 指定 key ID
#
# 输出文件:
#   release-key.pem     - 私钥（离线保管，用于签名发布包）
#   release-key.pub     - 公钥（硬编码到代码中）
#   public_key.go       - Go 源码片段（方便复制到 installer.go）

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${1:-.}"
KEY_ID="${2:-key-1}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# 检查 Go 是否可用
if ! command -v go &> /dev/null; then
    log_error "需要 Go 环境，请先安装 Go"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
for target in release-key.pem release-key.pub public_key.go; do
    if [[ -e "$OUTPUT_DIR/$target" ]]; then
        log_error "目标已存在，拒绝覆盖: $OUTPUT_DIR/$target"
        exit 1
    fi
done

# 使用 Go 生成 Ed25519 密钥对
log_info "生成 Ed25519 密钥对（Key ID: $KEY_ID）..."

KEY_TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sslctl-keygen.XXXXXX")"
KEY_PROGRAM="$KEY_TEMP_DIR/main.go"
trap 'rm -rf "$KEY_TEMP_DIR"' EXIT
cat >"$KEY_PROGRAM" <<'GOEOF'
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	outputDir := os.Args[1]
	keyID := os.Args[2]

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "生成密钥失败: %v\n", err)
		os.Exit(1)
	}

	privB64 := base64.StdEncoding.EncodeToString(priv.Seed())
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	created := make([]string, 0, 3)
	writeExclusive := func(path string, data []byte, mode os.FileMode) {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			for _, item := range created { _ = os.Remove(item) }
			fmt.Fprintf(os.Stderr, "拒绝覆盖密钥输出 %s: %v\n", path, err)
			os.Exit(1)
		}
		created = append(created, path)
		if _, err := file.Write(data); err != nil { _ = file.Close(); for _, item := range created { _ = os.Remove(item) }; panic(err) }
		if err := file.Chmod(mode); err != nil { _ = file.Close(); for _, item := range created { _ = os.Remove(item) }; panic(err) }
		if err := file.Close(); err != nil { for _, item := range created { _ = os.Remove(item) }; panic(err) }
	}

	// 写入私钥
	privPath := filepath.Join(outputDir, "release-key.pem")
	writeExclusive(privPath, []byte(privB64+"\n"), 0600)

	// 写入公钥
	pubPath := filepath.Join(outputDir, "release-key.pub")
	writeExclusive(pubPath, []byte(pubB64+"\n"), 0644)

	// 生成 Go 源码片段
	pubBytes := make([]string, 0, len(pub))
	for _, b := range pub {
		pubBytes = append(pubBytes, fmt.Sprintf("0x%02x", b))
	}

	goCode := fmt.Sprintf(`// releasePublicKeys Ed25519 公钥环（由 build/generate-keys.sh 生成）
// 将以下初始化代码添加到 pkg/upgrade/installer.go 的 init() 函数中
// Key ID: %s
func init() {
	releasePublicKeys["%s"] = ed25519.PublicKey{%s}
}
`, keyID, keyID, strings.Join(pubBytes, ", "))

	goPath := filepath.Join(outputDir, "public_key.go")
	writeExclusive(goPath, []byte(goCode), 0644)

	fmt.Printf("Key ID:       %s\n", keyID)
	fmt.Printf("公钥 (base64): %s\n", pubB64)
	fmt.Println("密钥对已生成")
}
GOEOF
go run "$KEY_PROGRAM" "$OUTPUT_DIR" "$KEY_ID"

log_success "密钥对生成完成"
echo ""
log_info "文件列表:"
echo "  $OUTPUT_DIR/release-key.pem  - 私钥（请离线安全保管）"
echo "  $OUTPUT_DIR/release-key.pub  - 公钥（base64 格式）"
echo "  $OUTPUT_DIR/public_key.go    - Go 源码片段（Key ID: $KEY_ID）"
echo ""
log_warning "重要安全提示:"
echo "  1. 私钥文件 release-key.pem 必须离线安全保管，切勿提交到代码仓库"
echo "  2. 将 public_key.go 中的 init() 函数复制到 pkg/upgrade/installer.go"
echo "  3. 重新编译发布 sslctl 二进制文件"
echo ""
log_info "密钥轮换时:"
echo "  1. 生成新密钥对: ./generate-keys.sh /path key-2"
echo "  2. 在 installer.go 的 init() 中同时保留旧公钥和新公钥"
echo "  3. 发布过渡版本（用旧私钥签名，内置新旧公钥）"
echo "  4. 后续版本用新私钥签名"
echo "  5. 错过过渡版本的用户通过 install.sh 重装即可"
