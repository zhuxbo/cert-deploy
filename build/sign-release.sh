#!/usr/bin/env bash
# 对固定正式资产集合签名，输出按公开文件名索引的 JSON；不修改 releases.json。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_FILE=""
KEY_ID=""
ASSETS_DIR=""
OUTPUT=""
VERIFY_SIGNATURES=""
TRUSTED_PUBLIC_KEY=""

while (($#)); do
    case "$1" in
        --key) KEY_FILE="${2:-}"; shift 2 ;;
        --key-id) KEY_ID="${2:-}"; shift 2 ;;
        --assets-dir) ASSETS_DIR="${2:-}"; shift 2 ;;
        --output) OUTPUT="${2:-}"; shift 2 ;;
        --verify-signatures) VERIFY_SIGNATURES="${2:-}"; shift 2 ;;
        --trusted-public-key) TRUSTED_PUBLIC_KEY="${2:-}"; shift 2 ;;
        -h|--help)
            echo "用法: $0 --key <seed-file> --key-id <id> [--trusted-public-key <file>] --assets-dir <dir> (--output <json> | --verify-signatures <json>)"
            exit 0
            ;;
        *) echo "未知参数: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "$KEY_ID" || -z "$ASSETS_DIR" || ( -z "$OUTPUT" && -z "$VERIFY_SIGNATURES" ) || ( -n "$OUTPUT" && -z "$KEY_FILE" ) ]]; then
    echo "错误: 缺少签名参数" >&2
    exit 2
fi
if [[ ! "$KEY_ID" =~ ^[0-9A-Za-z._-]+$ ]]; then
    echo "错误: key ID 格式无效" >&2
    exit 1
fi
if [[ -n "$OUTPUT" ]]; then
    [[ -f "$KEY_FILE" ]] || { echo "错误: 签名私钥不存在: $KEY_FILE" >&2; exit 1; }
    perms="$(stat -f '%Lp' "$KEY_FILE" 2>/dev/null || stat -c '%a' "$KEY_FILE" 2>/dev/null || true)"
    if [[ "$perms" != "600" ]]; then
        echo "错误: 签名私钥权限必须是 600，当前为 ${perms:-未知}" >&2
        exit 1
    fi
fi
command -v go >/dev/null 2>&1 || { echo "错误: 未找到 Go" >&2; exit 1; }

SIGN_TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sslctl-sign.XXXXXX")"
SIGN_PROGRAM="$SIGN_TEMP_DIR/main.go"
trap 'rm -rf "$SIGN_TEMP_DIR"' EXIT

if [[ -z "$TRUSTED_PUBLIC_KEY" ]]; then
    TRUSTED_PUBLIC_KEY="$SIGN_TEMP_DIR/trusted-public-key.txt"
    python3 - "$SCRIPT_DIR/../pkg/upgrade/installer.go" "$KEY_ID" "$TRUSTED_PUBLIC_KEY" <<'PY'
import base64, re, sys
source = open(sys.argv[1], encoding="utf-8").read()
pattern = r'releasePublicKeys\["' + re.escape(sys.argv[2]) + r'"\]\s*=\s*ed25519\.PublicKey\{([^}]*)\}'
match = re.search(pattern, source)
if not match:
    raise SystemExit(f"客户端公钥环中不存在 key ID: {sys.argv[2]}")
values = bytes(int(item, 16) for item in re.findall(r'0x([0-9a-fA-F]{2})', match.group(1)))
if len(values) != 32:
    raise SystemExit("客户端 Ed25519 公钥长度无效")
open(sys.argv[3], "w", encoding="utf-8").write(base64.b64encode(values).decode() + "\n")
PY
fi
[[ -f "$TRUSTED_PUBLIC_KEY" ]] || { echo "错误: 可信公钥不存在: $TRUSTED_PUBLIC_KEY" >&2; exit 1; }

cat >"$SIGN_PROGRAM" <<'GOEOF'
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	verifyMode := os.Args[4] == "verify"
	trustedText, err := os.ReadFile(os.Args[6])
	if err != nil { panic(err) }
	trustedKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(trustedText)))
	if err != nil || len(trustedKey) != ed25519.PublicKeySize {
		fmt.Fprintln(os.Stderr, "客户端内置公钥无效")
		os.Exit(1)
	}
	publicKey := ed25519.PublicKey(trustedKey)
	var privateKey ed25519.PrivateKey
	if !verifyMode {
		seedText, err := os.ReadFile(os.Args[1])
		if err != nil { panic(err) }
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seedText)))
		if err != nil || len(seed) != ed25519.SeedSize {
			fmt.Fprintln(os.Stderr, "签名私钥必须是 base64 编码的 32 字节 Ed25519 seed")
			os.Exit(1)
		}
		privateKey = ed25519.NewKeyFromSeed(seed)
		if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), trustedKey) {
			fmt.Fprintln(os.Stderr, "签名私钥与客户端内置公钥不匹配")
			os.Exit(1)
		}
	}
	names := []string{"sslctl-linux-amd64.gz", "sslctl-linux-arm64.gz", "sslctl-windows-amd64.exe.gz"}
	result := make(map[string]string, len(names))
	if verifyMode {
		encoded, err := os.ReadFile(os.Args[5])
		if err != nil { panic(err) }
		if err := json.Unmarshal(encoded, &result); err != nil { panic(err) }
		if len(result) != len(names) { fmt.Fprintln(os.Stderr, "签名集合数量无效"); os.Exit(1) }
	}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(os.Args[2], name))
		if err != nil { fmt.Fprintf(os.Stderr, "读取正式资产失败 %s: %v\n", name, err); os.Exit(1) }
		if verifyMode {
			prefix := "ed25519:" + os.Args[3] + ":"
			text, ok := result[name]
			if !ok || !strings.HasPrefix(text, prefix) { fmt.Fprintf(os.Stderr, "签名 key ID 不匹配: %s\n", name); os.Exit(1) }
			signature, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(text, prefix))
			if err != nil || !ed25519.Verify(publicKey, data, signature) { fmt.Fprintf(os.Stderr, "签名验证失败: %s\n", name); os.Exit(1) }
		} else {
			signature := ed25519.Sign(privateKey, data)
			if !ed25519.Verify(publicKey, data, signature) { fmt.Fprintln(os.Stderr, "签名自校验失败"); os.Exit(1) }
			result[name] = "ed25519:" + os.Args[3] + ":" + base64.StdEncoding.EncodeToString(signature)
		}
	}
	if verifyMode { return }
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil { panic(err) }
	temp := os.Args[5] + ".tmp"
	if err := os.WriteFile(temp, append(data, '\n'), 0600); err != nil { panic(err) }
	if err := os.Rename(temp, os.Args[5]); err != nil { panic(err) }
}
GOEOF

if [[ -n "$VERIFY_SIGNATURES" ]]; then
    go run "$SIGN_PROGRAM" "$KEY_FILE" "$ASSETS_DIR" "$KEY_ID" verify "$VERIFY_SIGNATURES" "$TRUSTED_PUBLIC_KEY"
    echo "签名验证完成"
else
    go run "$SIGN_PROGRAM" "$KEY_FILE" "$ASSETS_DIR" "$KEY_ID" sign "$OUTPUT" "$TRUSTED_PUBLIC_KEY"
    echo "签名完成: $OUTPUT"
fi
