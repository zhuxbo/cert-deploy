// Package certops 秒签 active 未部署续跑测试
package certops

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

// signingAPI 模拟"秒签"API：POST（提交 CSR）解析公钥、用测试 CA 立即签出与之配对的证书并返回 active；
// GET（查询订单）返回最近一次签出的证书。统计 POST/GET 次数以断言"是否提交了新 CSR"。
type signingAPI struct {
	t           *testing.T
	orderID     int
	caCert      *x509.Certificate
	caKey       *rsa.PrivateKey
	caPEM       string
	mu          sync.Mutex
	lastCertPEM string
	lastCSRPEM  string
	postCount   int
	getCount    int
}

func newSigningAPI(t *testing.T, orderID int) *signingAPI {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 CA 私钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Signing CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析 CA 证书失败: %v", err)
	}
	return &signingAPI{
		t:       t,
		orderID: orderID,
		caCert:  caCert,
		caKey:   caKey,
		caPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
}

// signCSR 解析提交的 CSR，用 CA 签出与其公钥配对的叶证书
func (a *signingAPI) signCSR(csrPEM string) string {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		a.t.Fatal("提交的 CSR 无法解码")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		a.t.Fatalf("解析 CSR 失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{csr.Subject.CommonName}, // CA 签发证书 SAN 必含 CN
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, a.caCert, csr.PublicKey, a.caKey)
	if err != nil {
		a.t.Fatalf("签发叶证书失败: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

func (a *signingAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	a.mu.Lock()
	defer a.mu.Unlock()

	if r.Method == http.MethodPost {
		a.postCount++
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var req struct {
			CSR string `json:"csr"`
		}
		_ = json.Unmarshal(body, &req)
		a.lastCSRPEM = req.CSR
		a.lastCertPEM = a.signCSR(req.CSR)
	} else {
		a.getCount++
	}

	resp := fmt.Sprintf(`{"code":1,"msg":"ok","data":{"order_id":%d,"status":"active","certificate":%q,"ca_certificate":%q,"csr":%q}}`,
		a.orderID, a.lastCertPEM, a.caPEM, a.lastCSRPEM)
	_, _ = w.Write([]byte(resp))
}

func (a *signingAPI) posts() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.postCount
}

func (a *signingAPI) gets() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.getCount
}

// TestPrepareLocalRenew_InstantIssue_AllDeployFail_ContinuesWithoutResign 复现并验证
// "秒签 active 未部署状态续跑"缺陷链的修复：
// 提交 CSR 后服务端秒签返回 active，当轮全部绑定部署失败。
// 修复前：秒签路径提前清零签发状态且 retry 复位，下轮因状态为空重新生成 CSR，
// 覆盖与已签发证书配对的 pending 私钥、旁路 MaxIssueRetryCount，每周期重签一次。
// 修复后：秒签保留状态为 active，下轮走查询+读 pending 部署（不再重签），retry 递增直至触顶停机。
func TestPrepareLocalRenew_InstantIssue_AllDeployFail_ContinuesWithoutResign(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	api := newSigningAPI(t, 3100)
	server := httptest.NewServer(api)
	defer server.Close()

	certPath := filepath.Join(tmpDir, "site", "cert.pem")
	keyPath := filepath.Join(tmpDir, "site", "key.pem")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	// 制造部署失败：cert 路径为目录，通用部署器写入必失败
	if err := os.Mkdir(certPath, 0700); err != nil {
		t.Fatalf("制造部署障碍失败: %v", err)
	}

	oldExpiry := time.Now().Add(5 * 24 * time.Hour).Truncate(time.Second)
	cert := &config.CertConfig{
		CertName:  "instant.example.com-3100",
		OrderID:   3100,
		Enabled:   true,
		RenewMode: config.RenewModeLocal,
		Domains:   []string{"instant.example.com"},
		API:       config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			CertExpiresAt: oldExpiry, // 旧证书临期，LastIssueState 为空 → 首轮生成 CSR + 秒签
		},
		Bindings: []config.SiteBinding{{
			ServerName: "instant-site",
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
			Paths:      config.BindingPaths{Certificate: certPath, PrivateKey: keyPath},
		}},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	// === round1：生成 CSR + 秒签 active + 全部署失败 ===
	cd1, pk1, err := svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if err != nil {
		t.Fatalf("round1 prepare 应成功（秒签 active）: %v", err)
	}
	if cd1 == nil {
		t.Fatal("round1 应返回证书数据")
	}
	if api.posts() != 1 {
		t.Fatalf("round1 应提交一次 CSR: posts=%d", api.posts())
	}
	dc1, _, derr1 := svc.deployCertToBindings(t.Context(), cert, cd1, pk1)
	if dc1 != 0 || derr1 == nil {
		t.Fatalf("round1 部署应全部失败: count=%d err=%v", dc1, derr1)
	}

	// 断言：状态为 active、pending 保留、retry 未复位
	if cert.Metadata.LastIssueState != "active" {
		t.Errorf("秒签全失败后 LastIssueState 应为 active，实际 %q", cert.Metadata.LastIssueState)
	}
	pendingAfter1, perr := readPendingKey(cm.GetWorkDir(), cert.CertName)
	if perr != nil {
		t.Fatalf("秒签全失败后 pending 私钥应保留: %v", perr)
	}
	if pendingAfter1 != pk1 {
		t.Error("pending 私钥应与本轮签发私钥一致")
	}
	if cert.Metadata.IssueRetryCount != 1 {
		t.Errorf("秒签提交 CSR 后 retry 应为 1（未复位），实际 %d", cert.Metadata.IssueRetryCount)
	}

	// === round2：不再生成新 CSR，走查询+读 pending 部署 ===
	cd2, pk2, err := svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if err != nil {
		t.Fatalf("round2 prepare 应成功（active 自愈）: %v", err)
	}
	if cd2 == nil {
		t.Fatal("round2 应返回证书数据走部署")
	}
	if api.posts() != 1 {
		t.Fatalf("round2 不应提交新 CSR: posts=%d", api.posts())
	}
	if api.gets() < 1 {
		t.Fatalf("round2 应查询订单: gets=%d", api.gets())
	}
	if pk2 != pendingAfter1 {
		t.Error("round2 应复用 pending 私钥")
	}
	pendingAfter2, _ := readPendingKey(cm.GetWorkDir(), cert.CertName)
	if pendingAfter2 != pendingAfter1 {
		t.Error("round2 不应覆盖 pending 私钥（未重新生成 CSR）")
	}
	// 计数分离（计划 3.1）：active 自愈只走部署，不再递增签发计数，
	// 签发计数仅在提交 CSR 时递增（round1 一次），故此处仍为 1。
	// 部署尝试计数（DeployAttemptCount）由编排层 runDeployAttempt 管理，见 TestCheckAndRenewAll_DeployCapStopsAfterTenAttempts。
	if cert.Metadata.IssueRetryCount != 1 {
		t.Errorf("round2 active 自愈不应递增签发计数（仍为 1），实际 %d", cert.Metadata.IssueRetryCount)
	}
	dc2, _, derr2 := svc.deployCertToBindings(t.Context(), cert, cd2, pk2)
	if dc2 != 0 || derr2 == nil {
		t.Fatalf("round2 部署应仍失败: count=%d", dc2)
	}

	// === 继续自愈若干轮：全程不重新提交 CSR，签发计数恒为 1（不污染） ===
	for round := 3; round <= 6; round++ {
		cd, pk, perr := svc.prepareLocalRenew(t.Context(), cert, cert.API)
		if perr != nil {
			t.Fatalf("round %d prepare 非预期失败: %v", round, perr)
		}
		if api.posts() != 1 {
			t.Fatalf("round %d 不应提交新 CSR: posts=%d", round, api.posts())
		}
		if cert.Metadata.IssueRetryCount != 1 {
			t.Errorf("round %d 自愈不应污染签发计数（应恒为 1），实际 %d", round, cert.Metadata.IssueRetryCount)
		}
		dc, _, _ := svc.deployCertToBindings(t.Context(), cert, cd, pk)
		if dc != 0 {
			t.Fatalf("round %d 部署应失败", round)
		}
	}
	// 全程只提交过一次 CSR（秒签当轮），后续全部走查询+读 pending
	if api.posts() != 1 {
		t.Errorf("全程应仅提交一次 CSR，实际 posts=%d", api.posts())
	}
}
