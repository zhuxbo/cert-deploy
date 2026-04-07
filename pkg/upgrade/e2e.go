//go:build e2e

// e2e 测试构建覆盖：清除签名公钥（跳过签名验证）、允许 HTTP 升级地址。
// 仅在 build.sh 以 -tags e2e 编译时生效，生产构建不受影响。
package upgrade

import (
	"crypto/ed25519"
	"net/http"
	"time"
)

func init() {
	// 清除签名公钥 → VerifySignature 对空签名跳过验证
	releasePublicKeys = map[string]ed25519.PublicKey{}

	// 允许 HTTP（mock-api 仅提供 HTTP）
	validateReleaseURL = func(_ string) (*http.Client, error) {
		return &http.Client{Timeout: 5 * time.Minute}, nil
	}
}
