// Package csr 提供本地私钥与 CSR 生成
package csr

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// KeyOptions 私钥生成参数
type KeyOptions struct {
	Type  string // rsa|ecdsa
	Size  int    // 2048|4096
	Curve string // prime256v1|secp384r1|secp521r1
}

// CSROptions CSR 生成参数（支持 OV 字段）
type CSROptions struct {
	CommonName   string
	Organization string
	Country      string
	State        string
	Locality     string
	Email        string
}

var (
	// ErrInvalidCSR 表示服务端 CSR 缺失、无法解析或签名无效，客户端不能据此判断归属。
	ErrInvalidCSR = errors.New("invalid CSR")
	// ErrOwnershipMismatch 表示 CSR 本身有效，但不属于本机持久化的逻辑尝试。
	ErrOwnershipMismatch = errors.New("CSR ownership mismatch")
)

// GenerateKeyAndCSR 生成私钥与 CSR（支持 RSA/ECDSA）
// 返回：keyPEM, csrPEM, csrHash(hex)
func GenerateKeyAndCSR(keyOpt KeyOptions, csrOpt CSROptions) (string, string, string, error) {
	// 默认 RSA 2048
	if keyOpt.Type == "" {
		keyOpt.Type = "rsa"
	}
	if keyOpt.Type == "rsa" && keyOpt.Size == 0 {
		keyOpt.Size = 2048
	}
	if keyOpt.Type == "ecdsa" && keyOpt.Curve == "" {
		keyOpt.Curve = "prime256v1"
	}

	var priv interface{}
	var err error
	switch keyOpt.Type {
	case "rsa":
		if keyOpt.Size < 2048 {
			return "", "", "", fmt.Errorf("RSA key size must be at least 2048, got %d", keyOpt.Size)
		}
		priv, err = rsa.GenerateKey(rand.Reader, keyOpt.Size)
	case "ecdsa":
		var curve elliptic.Curve
		switch keyOpt.Curve {
		case "prime256v1":
			curve = elliptic.P256()
		case "secp384r1":
			curve = elliptic.P384()
		case "secp521r1":
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		priv, err = ecdsa.GenerateKey(curve, rand.Reader)
	default:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return "", "", "", err
	}

	subj := pkix.Name{CommonName: csrOpt.CommonName}
	if csrOpt.Organization != "" {
		subj.Organization = []string{csrOpt.Organization}
	}
	if csrOpt.Country != "" {
		subj.Country = []string{csrOpt.Country}
	}
	if csrOpt.State != "" {
		subj.Province = []string{csrOpt.State}
	}
	if csrOpt.Locality != "" {
		subj.Locality = []string{csrOpt.Locality}
	}

	var emailAddresses []string
	if csrOpt.Email != "" {
		emailAddresses = []string{csrOpt.Email}
	}

	tpl := x509.CertificateRequest{
		Subject:        subj,
		EmailAddresses: emailAddresses,
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &tpl, priv)
	if err != nil {
		return "", "", "", err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	var keyPEM []byte
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	case *ecdsa.PrivateKey:
		b, e := x509.MarshalECPrivateKey(k)
		if e != nil {
			return "", "", "", e
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	}

	sum := sha256.Sum256(der)
	return string(keyPEM), string(csrPEM), hex.EncodeToString(sum[:]), nil
}

func parseAndVerifyCSR(csrPEM string) (*x509.CertificateRequest, []byte, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, nil, fmt.Errorf("%w: failed to decode PEM", ErrInvalidCSR)
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: failed to parse: %v", ErrInvalidCSR, err)
	}
	if err := request.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("%w: signature check failed: %v", ErrInvalidCSR, err)
	}
	return request, block.Bytes, nil
}

// DERHash 返回已验签 CSR 的 DER SHA256，供旧 PEM 哈希恢复成功后规范化 metadata。
func DERHash(csrPEM string) (string, error) {
	_, der, err := parseAndVerifyCSR(csrPEM)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// ValidateOwnership 验证服务端 CSR 是否属于本机已持久化的逻辑尝试。
// 判据固定为：CSR 可解析且签名有效、DER SHA256 与 metadata 一致、CSR 公钥与 pending
// 私钥一致、CN 与当前配置主域名一致。仅为升级中已在途的旧 metadata 兼容一次 PEM
// SHA256；验证通过后调用方应立即规范化为 DER 哈希。
func ValidateOwnership(csrPEM, privateKeyPEM, expectedHash, expectedCommonName string) error {
	request, der, err := parseAndVerifyCSR(csrPEM)
	if err != nil {
		return err
	}

	sum := sha256.Sum256(der)
	actualHash := hex.EncodeToString(sum[:])
	if strings.TrimSpace(expectedHash) == "" {
		return fmt.Errorf("expected CSR hash is missing")
	}
	if !strings.EqualFold(actualHash, strings.TrimSpace(expectedHash)) {
		// 一次性升级兼容：旧客户端保存的是 PEM 文本 SHA256。只有旧哈希也匹配时
		// 才继续公钥/CN 校验；调用方验证成功后立即改写为 DER 哈希。
		legacyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
		legacySum := sha256.Sum256(legacyPEM)
		legacyHash := hex.EncodeToString(legacySum[:])
		if !strings.EqualFold(legacyHash, strings.TrimSpace(expectedHash)) {
			return fmt.Errorf("%w: hash differs", ErrOwnershipMismatch)
		}
	}
	if strings.TrimSpace(expectedCommonName) == "" {
		return fmt.Errorf("expected common name is missing")
	}
	if !strings.EqualFold(strings.TrimSpace(request.Subject.CommonName), strings.TrimSpace(expectedCommonName)) {
		return fmt.Errorf("%w: common name differs", ErrOwnershipMismatch)
	}

	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return err
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("private key does not expose a public key")
	}
	requestPublicDER, err := x509.MarshalPKIXPublicKey(request.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal CSR public key: %w", err)
	}
	privatePublicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("failed to marshal private key public key: %w", err)
	}
	if !bytes.Equal(requestPublicDER, privatePublicDER) {
		return fmt.Errorf("%w: public key differs", ErrOwnershipMismatch)
	}
	return nil
}

func parsePrivateKey(keyPEM string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("failed to parse private key")
}
