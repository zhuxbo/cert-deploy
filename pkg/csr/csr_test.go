// Package csr CSR 生成测试
package csr

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestGenerateKeyAndCSR_RSA 测试 RSA 密钥和 CSR 生成
func TestGenerateKeyAndCSR_RSA(t *testing.T) {
	tests := []struct {
		name    string
		keyOpt  KeyOptions
		csrOpt  CSROptions
		wantErr bool
	}{
		{
			name:   "RSA 2048 默认",
			keyOpt: KeyOptions{Type: "rsa", Size: 2048},
			csrOpt: CSROptions{CommonName: "example.com"},
		},
		{
			name:   "RSA 4096",
			keyOpt: KeyOptions{Type: "rsa", Size: 4096},
			csrOpt: CSROptions{CommonName: "example.com"},
		},
		{
			name:   "RSA 默认类型",
			keyOpt: KeyOptions{}, // 默认应该是 RSA 2048
			csrOpt: CSROptions{CommonName: "example.com"},
		},
		{
			name:   "未知类型回退到 RSA",
			keyOpt: KeyOptions{Type: "unknown"},
			csrOpt: CSROptions{CommonName: "example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPEM, csrPEM, hash, err := GenerateKeyAndCSR(tt.keyOpt, tt.csrOpt)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKeyAndCSR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// 验证私钥 PEM
			if !strings.Contains(keyPEM, "RSA PRIVATE KEY") {
				t.Error("keyPEM should contain RSA PRIVATE KEY header")
			}

			// 解析私钥
			block, _ := pem.Decode([]byte(keyPEM))
			if block == nil {
				t.Fatal("failed to decode key PEM")
			}

			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				t.Fatalf("failed to parse RSA private key: %v", err)
			}

			// 验证密钥长度
			expectedSize := tt.keyOpt.Size
			if expectedSize == 0 {
				expectedSize = 2048
			}
			if key.N.BitLen() != expectedSize {
				t.Errorf("RSA key size = %d, want %d", key.N.BitLen(), expectedSize)
			}

			// 验证 CSR PEM
			if !strings.Contains(csrPEM, "CERTIFICATE REQUEST") {
				t.Error("csrPEM should contain CERTIFICATE REQUEST header")
			}

			// 解析 CSR
			csrBlock, _ := pem.Decode([]byte(csrPEM))
			if csrBlock == nil {
				t.Fatal("failed to decode CSR PEM")
			}

			csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
			if err != nil {
				t.Fatalf("failed to parse CSR: %v", err)
			}

			// 验证 CommonName
			if csr.Subject.CommonName != tt.csrOpt.CommonName {
				t.Errorf("CSR CommonName = %s, want %s", csr.Subject.CommonName, tt.csrOpt.CommonName)
			}

			// 验证 hash 不为空
			if hash == "" {
				t.Error("hash should not be empty")
			}
			if len(hash) != 64 { // SHA256 hex 长度
				t.Errorf("hash length = %d, want 64", len(hash))
			}
		})
	}
}

// TestGenerateKeyAndCSR_ECDSA 测试 ECDSA 密钥和 CSR 生成
func TestGenerateKeyAndCSR_ECDSA(t *testing.T) {
	tests := []struct {
		name   string
		curve  string
		wantOK bool
	}{
		{"P256 prime256v1", "prime256v1", true},
		{"P384 secp384r1", "secp384r1", true},
		{"P521 secp521r1", "secp521r1", true},
		{"默认曲线", "", true}, // 默认 P256
		{"未知曲线回退 P256", "unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyOpt := KeyOptions{Type: "ecdsa", Curve: tt.curve}
			csrOpt := CSROptions{CommonName: "example.com"}

			keyPEM, csrPEM, hash, err := GenerateKeyAndCSR(keyOpt, csrOpt)

			if err != nil {
				t.Fatalf("GenerateKeyAndCSR() error = %v", err)
			}

			// 验证私钥 PEM
			if !strings.Contains(keyPEM, "EC PRIVATE KEY") {
				t.Error("keyPEM should contain EC PRIVATE KEY header")
			}

			// 解析私钥
			block, _ := pem.Decode([]byte(keyPEM))
			if block == nil {
				t.Fatal("failed to decode key PEM")
			}

			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				t.Fatalf("failed to parse EC private key: %v", err)
			}

			// 验证曲线
			curveName := key.Curve.Params().Name
			expectedCurves := map[string]string{
				"prime256v1": "P-256",
				"secp384r1":  "P-384",
				"secp521r1":  "P-521",
				"":           "P-256",
				"unknown":    "P-256",
			}
			expected := expectedCurves[tt.curve]
			if curveName != expected {
				t.Errorf("ECDSA curve = %s, want %s", curveName, expected)
			}

			// 验证 CSR
			if !strings.Contains(csrPEM, "CERTIFICATE REQUEST") {
				t.Error("csrPEM should contain CERTIFICATE REQUEST header")
			}

			if hash == "" {
				t.Error("hash should not be empty")
			}
		})
	}
}

// TestGenerateKeyAndCSR_OVFields 测试 OV 证书字段
func TestGenerateKeyAndCSR_OVFields(t *testing.T) {
	keyOpt := KeyOptions{Type: "rsa", Size: 2048}
	csrOpt := CSROptions{
		CommonName:   "example.com",
		Organization: "Test Org",
		Country:      "CN",
		State:        "Beijing",
		Locality:     "Haidian",
		Email:        "test@example.com",
	}

	_, csrPEM, _, err := GenerateKeyAndCSR(keyOpt, csrOpt)
	if err != nil {
		t.Fatalf("GenerateKeyAndCSR() error = %v", err)
	}

	// 解析 CSR
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("failed to decode CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}

	// 验证 Subject 字段
	if csr.Subject.CommonName != "example.com" {
		t.Errorf("CommonName = %s, want example.com", csr.Subject.CommonName)
	}

	if len(csr.Subject.Organization) == 0 || csr.Subject.Organization[0] != "Test Org" {
		t.Errorf("Organization = %v, want [Test Org]", csr.Subject.Organization)
	}

	if len(csr.Subject.Country) == 0 || csr.Subject.Country[0] != "CN" {
		t.Errorf("Country = %v, want [CN]", csr.Subject.Country)
	}

	if len(csr.Subject.Province) == 0 || csr.Subject.Province[0] != "Beijing" {
		t.Errorf("Province = %v, want [Beijing]", csr.Subject.Province)
	}

	if len(csr.Subject.Locality) == 0 || csr.Subject.Locality[0] != "Haidian" {
		t.Errorf("Locality = %v, want [Haidian]", csr.Subject.Locality)
	}

	// 验证 Email
	if len(csr.EmailAddresses) == 0 || csr.EmailAddresses[0] != "test@example.com" {
		t.Errorf("EmailAddresses = %v, want [test@example.com]", csr.EmailAddresses)
	}
}

// TestGenerateKeyAndCSR_MinimalCSR 测试最小 CSR（仅 CommonName）
func TestGenerateKeyAndCSR_MinimalCSR(t *testing.T) {
	keyOpt := KeyOptions{Type: "rsa", Size: 2048}
	csrOpt := CSROptions{CommonName: "example.com"}

	_, csrPEM, _, err := GenerateKeyAndCSR(keyOpt, csrOpt)
	if err != nil {
		t.Fatalf("GenerateKeyAndCSR() error = %v", err)
	}

	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}

	if csr.Subject.CommonName != "example.com" {
		t.Errorf("CommonName = %s, want example.com", csr.Subject.CommonName)
	}

	// 其他字段应为空
	if len(csr.Subject.Organization) != 0 {
		t.Errorf("Organization should be empty, got %v", csr.Subject.Organization)
	}

	if len(csr.EmailAddresses) != 0 {
		t.Errorf("EmailAddresses should be empty, got %v", csr.EmailAddresses)
	}
}

// TestGenerateKeyAndCSR_HashUniqueness 测试 hash 唯一性
func TestGenerateKeyAndCSR_HashUniqueness(t *testing.T) {
	keyOpt := KeyOptions{Type: "rsa", Size: 2048}
	csrOpt := CSROptions{CommonName: "example.com"}

	_, _, hash1, err := GenerateKeyAndCSR(keyOpt, csrOpt)
	if err != nil {
		t.Fatalf("first GenerateKeyAndCSR() error = %v", err)
	}

	_, _, hash2, err := GenerateKeyAndCSR(keyOpt, csrOpt)
	if err != nil {
		t.Fatalf("second GenerateKeyAndCSR() error = %v", err)
	}

	// 每次生成的密钥不同，所以 CSR 和 hash 也应该不同
	if hash1 == hash2 {
		t.Error("hash should be unique for each CSR generation")
	}
}

func TestGenerateKeyAndCSR_HashUsesDER(t *testing.T) {
	_, csrPEM, got, err := GenerateKeyAndCSR(
		KeyOptions{Type: "rsa", Size: 2048},
		CSROptions{CommonName: "example.com"},
	)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("failed to decode generated CSR")
	}
	want := fmt.Sprintf("%x", sha256.Sum256(block.Bytes))
	if got != want {
		t.Fatalf("CSR hash = %s, want DER SHA256 %s", got, want)
	}
}

func TestValidateOwnership(t *testing.T) {
	keyPEM, csrPEM, csrHash, err := GenerateKeyAndCSR(
		KeyOptions{Type: "rsa", Size: 2048},
		CSROptions{CommonName: "example.com"},
	)
	if err != nil {
		t.Fatal(err)
	}
	otherKeyPEM, _, _, err := GenerateKeyAndCSR(
		KeyOptions{Type: "rsa", Size: 2048},
		CSROptions{CommonName: "example.com"},
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid", func(t *testing.T) {
		if err := ValidateOwnership(csrPEM, keyPEM, csrHash, "example.com"); err != nil {
			t.Fatalf("ValidateOwnership() error = %v", err)
		}
	})

	t.Run("legacy PEM hash", func(t *testing.T) {
		legacyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(csrPEM)))
		serviceCSR := strings.ReplaceAll(csrPEM, "\n", "\r\n")
		if err := ValidateOwnership(serviceCSR, keyPEM, legacyHash, "example.com"); err != nil {
			t.Fatalf("legacy PEM hash should remain recoverable during upgrade: %v", err)
		}
	})

	tests := []struct {
		name       string
		keyPEM     string
		hash       string
		commonName string
	}{
		{name: "hash mismatch", keyPEM: keyPEM, hash: strings.Repeat("0", 64), commonName: "example.com"},
		{name: "private key mismatch", keyPEM: otherKeyPEM, hash: csrHash, commonName: "example.com"},
		{name: "common name mismatch", keyPEM: keyPEM, hash: csrHash, commonName: "other.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOwnership(csrPEM, tt.keyPEM, tt.hash, tt.commonName)
			if !errors.Is(err, ErrOwnershipMismatch) {
				t.Fatalf("ValidateOwnership() error = %v, want ErrOwnershipMismatch", err)
			}
		})
	}

	t.Run("invalid signature", func(t *testing.T) {
		block, _ := pem.Decode([]byte(csrPEM))
		if block == nil {
			t.Fatal("failed to decode CSR")
		}
		tampered := append([]byte(nil), block.Bytes...)
		tampered[len(tampered)-1] ^= 0xff
		tamperedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered})
		tamperedHash := fmt.Sprintf("%x", sha256.Sum256(tampered))
		err := ValidateOwnership(string(tamperedPEM), keyPEM, tamperedHash, "example.com")
		if !errors.Is(err, ErrInvalidCSR) {
			t.Fatalf("ValidateOwnership() error = %v, want ErrInvalidCSR", err)
		}
	})

	t.Run("unreadable private key is not mismatch proof", func(t *testing.T) {
		err := ValidateOwnership(csrPEM, "not-a-private-key", csrHash, "example.com")
		if err == nil || errors.Is(err, ErrOwnershipMismatch) {
			t.Fatalf("ValidateOwnership() error = %v, want unverifiable non-mismatch error", err)
		}
	})
}

// TestGenerateKeyAndCSR_KeyTypes 验证返回的密钥类型
func TestGenerateKeyAndCSR_KeyTypes(t *testing.T) {
	tests := []struct {
		name    string
		keyOpt  KeyOptions
		keyType string
	}{
		{"RSA", KeyOptions{Type: "rsa"}, "*rsa.PrivateKey"},
		{"ECDSA", KeyOptions{Type: "ecdsa"}, "*ecdsa.PrivateKey"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPEM, _, _, err := GenerateKeyAndCSR(tt.keyOpt, CSROptions{CommonName: "test.com"})
			if err != nil {
				t.Fatalf("GenerateKeyAndCSR() error = %v", err)
			}

			block, _ := pem.Decode([]byte(keyPEM))
			if block == nil {
				t.Fatal("failed to decode key PEM")
			}

			switch tt.keyOpt.Type {
			case "rsa":
				_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					t.Errorf("expected RSA key, parse error: %v", err)
				}
			case "ecdsa":
				key, err := x509.ParseECPrivateKey(block.Bytes)
				if err != nil {
					t.Errorf("expected ECDSA key, parse error: %v", err)
				}
				if _, ok := interface{}(key).(*ecdsa.PrivateKey); !ok {
					t.Error("key is not *ecdsa.PrivateKey")
				}
			}
		})
	}
}

// TestGenerateKeyAndCSR_CSRSignatureValid 验证 CSR 签名有效性
func TestGenerateKeyAndCSR_CSRSignatureValid(t *testing.T) {
	tests := []struct {
		name   string
		keyOpt KeyOptions
	}{
		{"RSA", KeyOptions{Type: "rsa", Size: 2048}},
		{"ECDSA", KeyOptions{Type: "ecdsa", Curve: "prime256v1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPEM, csrPEM, _, err := GenerateKeyAndCSR(tt.keyOpt, CSROptions{CommonName: "test.com"})
			if err != nil {
				t.Fatalf("GenerateKeyAndCSR() error = %v", err)
			}

			// 解析 CSR
			csrBlock, _ := pem.Decode([]byte(csrPEM))
			csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
			if err != nil {
				t.Fatalf("failed to parse CSR: %v", err)
			}

			// 验证 CSR 签名
			if err := csr.CheckSignature(); err != nil {
				t.Errorf("CSR signature invalid: %v", err)
			}

			// 解析私钥并验证公钥匹配
			keyBlock, _ := pem.Decode([]byte(keyPEM))

			switch tt.keyOpt.Type {
			case "rsa":
				key, _ := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
				pubKey, ok := csr.PublicKey.(*rsa.PublicKey)
				if !ok {
					t.Fatal("CSR public key is not RSA")
				}
				if !key.PublicKey.Equal(pubKey) {
					t.Error("CSR public key does not match private key")
				}

			case "ecdsa":
				key, _ := x509.ParseECPrivateKey(keyBlock.Bytes)
				pubKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
				if !ok {
					t.Fatal("CSR public key is not ECDSA")
				}
				if !key.PublicKey.Equal(pubKey) {
					t.Error("CSR public key does not match private key")
				}
			}
		})
	}
}
