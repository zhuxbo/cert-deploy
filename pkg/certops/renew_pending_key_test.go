// Package certops pending 私钥转正时机与配对校验测试
package certops

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
	certs "github.com/zhuxbo/sslctl/testdata/certs"
)

// newQueryOrderServer 返回固定 QueryOrder 响应的本地 API 服务
func newQueryOrderServer(t *testing.T, orderID int, status, certPEM, intermediatePEM string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := fmt.Sprintf(`{"code":1,"msg":"ok","data":{"order_id":%d,"status":%q,"certificate":%q,"ca_certificate":%q}}`,
			orderID, status, certPEM, intermediatePEM)
		_, _ = w.Write([]byte(resp))
	}))
}

// TestPrepareLocalRenew_MismatchedCert_KeepsOnlineKeyAndPending 验证 processing→active
// 时服务端返回与 pending 私钥不配对的证书（旧证书/串单）：
// 按失败处理，线上私钥不被覆盖、pending 私钥保留（修复前 commitPendingKey 先执行，
// 线上配对私钥被不可逆销毁后校验才失败，磁盘留下错配对）。
func TestPrepareLocalRenew_MismatchedCert_KeepsOnlineKeyAndPending(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	// pending 私钥属于证书 A；服务端返回证书 B（不配对）
	certA, err := certs.GenerateValidCert("renew.example.com", []string{"renew.example.com"})
	if err != nil {
		t.Fatalf("生成证书 A 失败: %v", err)
	}
	certB, err := certs.GenerateValidCert("renew.example.com", []string{"renew.example.com"})
	if err != nil {
		t.Fatalf("生成证书 B 失败: %v", err)
	}
	intermediate, err := certs.GenerateValidCert("Test CA", nil)
	if err != nil {
		t.Fatalf("生成中间证书失败: %v", err)
	}

	// 线上私钥（正式位置）为旧内容
	keyPath := filepath.Join(tmpDir, "site", "key.pem")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	oldOnlineKey := "-----BEGIN RSA PRIVATE KEY-----\nold-online-key\n-----END RSA PRIVATE KEY-----"
	if err := os.WriteFile(keyPath, []byte(oldOnlineKey), 0600); err != nil {
		t.Fatalf("写入线上私钥失败: %v", err)
	}

	// pending 私钥为 A.Key
	if err := savePendingKey(cm.GetWorkDir(), "renew.example.com-100", certA.KeyPEM); err != nil {
		t.Fatalf("保存 pending 私钥失败: %v", err)
	}

	server := newQueryOrderServer(t, 100, "active", certB.CertPEM, intermediate.CertPEM)
	defer server.Close()

	cert := &config.CertConfig{
		CertName:  "renew.example.com-100",
		OrderID:   100,
		RenewMode: config.RenewModeLocal,
		Domains:   []string{"renew.example.com"},
		API:       config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			LastIssueState: "processing",
			CertExpiresAt:  time.Now().Add(5 * 24 * time.Hour),
		},
		Bindings: []config.SiteBinding{{
			ServerName: "renew-site",
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
			Paths: config.BindingPaths{
				Certificate: filepath.Join(tmpDir, "site", "cert.pem"),
				PrivateKey:  keyPath,
			},
		}},
	}

	_, _, err = svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if err == nil {
		t.Fatal("服务端返回不配对证书时应按失败处理")
	}

	// 线上私钥不得被覆盖
	got, readErr := os.ReadFile(keyPath)
	if readErr != nil {
		t.Fatalf("读取线上私钥失败: %v", readErr)
	}
	if string(got) != oldOnlineKey {
		t.Error("线上私钥被覆盖（应保持原内容，等待人工处理）")
	}

	// pending 私钥必须保留
	pendingKey, readErr := readPendingKey(cm.GetWorkDir(), "renew.example.com-100")
	if readErr != nil {
		t.Fatalf("pending 私钥应保留: %v", readErr)
	}
	if pendingKey != certA.KeyPEM {
		t.Error("pending 私钥内容不应改变")
	}
}

// TestRenew_PendingKeyCommittedAfterDeploy 验证正常场景：
// 服务端返回与 pending 私钥配对的证书 → prepare 通过（不动线上私钥）→
// 部署成功后 pending 私钥才转正（旧线上私钥已由部署路径备份）。
func TestRenew_PendingKeyCommittedAfterDeploy(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	// 新证书 A（与 pending 私钥配对）；线上现有旧证书 B
	certA, err := certs.GenerateValidCert("renew2.example.com", []string{"renew2.example.com"})
	if err != nil {
		t.Fatalf("生成证书 A 失败: %v", err)
	}
	certB, err := certs.GenerateValidCert("renew2.example.com", []string{"renew2.example.com"})
	if err != nil {
		t.Fatalf("生成证书 B 失败: %v", err)
	}
	intermediate, err := certs.GenerateValidCert("Test CA", nil)
	if err != nil {
		t.Fatalf("生成中间证书失败: %v", err)
	}

	certPath := filepath.Join(tmpDir, "site", "cert.pem")
	keyPath := filepath.Join(tmpDir, "site", "key.pem")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	// 预置线上旧证书 B（cert+key 成对，触发部署前备份）
	if err := os.WriteFile(certPath, []byte(certB.CertPEM), 0644); err != nil {
		t.Fatalf("写入线上证书失败: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(certB.KeyPEM), 0600); err != nil {
		t.Fatalf("写入线上私钥失败: %v", err)
	}

	// pending 私钥为 A.Key
	if err := savePendingKey(cm.GetWorkDir(), "renew2.example.com-200", certA.KeyPEM); err != nil {
		t.Fatalf("保存 pending 私钥失败: %v", err)
	}

	server := newQueryOrderServer(t, 200, "active", certA.CertPEM, intermediate.CertPEM)
	defer server.Close()

	cert := &config.CertConfig{
		CertName:  "renew2.example.com-200",
		OrderID:   200,
		RenewMode: config.RenewModeLocal,
		Domains:   []string{"renew2.example.com"},
		API:       config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			LastIssueState: "processing",
			CertExpiresAt:  time.Now().Add(5 * 24 * time.Hour),
		},
		Bindings: []config.SiteBinding{{
			ServerName: "renew2-site",
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
			Paths: config.BindingPaths{
				Certificate: certPath,
				PrivateKey:  keyPath,
			},
		}},
	}

	certData, privateKey, err := svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if err != nil {
		t.Fatalf("prepareLocalRenew 应成功: %v", err)
	}
	if privateKey != certA.KeyPEM {
		t.Fatal("应返回 pending 私钥内容")
	}

	// prepare 阶段不得动线上私钥（转正在部署成功后）
	got, _ := os.ReadFile(keyPath)
	if string(got) != certB.KeyPEM {
		t.Error("prepare 阶段不应改动线上私钥")
	}
	if _, err := readPendingKey(cm.GetWorkDir(), "renew2.example.com-200"); err != nil {
		t.Errorf("prepare 阶段 pending 私钥应保留: %v", err)
	}

	// 部署成功后 pending 才转正
	deployCount, _, deployErr := svc.deployCertToBindings(t.Context(), cert, certData, privateKey)
	if deployErr != nil || deployCount != 1 {
		t.Fatalf("部署应成功: count=%d err=%v", deployCount, deployErr)
	}

	// 线上私钥已更新为新私钥
	got, _ = os.ReadFile(keyPath)
	if string(got) != certA.KeyPEM {
		t.Error("部署成功后线上私钥应为新私钥")
	}
	// pending 私钥已清理（转正完成）
	if _, err := os.Lstat(getPendingKeyPath(cm.GetWorkDir(), "renew2.example.com-200")); !os.IsNotExist(err) {
		t.Error("部署成功后 pending 私钥应被清理")
	}
	// 旧线上私钥应有备份（部署路径覆盖前备份）
	backupSiteDir := filepath.Join(cm.GetBackupDir(), "renew2-site")
	entries, err := os.ReadDir(backupSiteDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("旧证书应有备份: %v", err)
	}
	backedKey, err := os.ReadFile(filepath.Join(backupSiteDir, entries[0].Name(), "key.pem"))
	if err != nil {
		t.Fatalf("读取备份私钥失败: %v", err)
	}
	if string(backedKey) != certB.KeyPEM {
		t.Error("备份内容应为旧线上私钥")
	}
}

// TestPrepareLocalRenew_ImmediateActive_MismatchKeepsPending 验证首次提交 CSR 后
// 服务端立即返回 active 但证书与本次 CSR 私钥不配对：按失败处理，pending 保留。
func TestPrepareLocalRenew_ImmediateActive_MismatchKeepsPending(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	// 服务端对提交（POST）立即返回 active + 一张与新 CSR 必然不配对的旧证书
	certOld, err := certs.GenerateValidCert("im.example.com", []string{"im.example.com"})
	if err != nil {
		t.Fatalf("生成旧证书失败: %v", err)
	}
	intermediate, err := certs.GenerateValidCert("Test CA", nil)
	if err != nil {
		t.Fatalf("生成中间证书失败: %v", err)
	}
	server := newQueryOrderServer(t, 300, "active", certOld.CertPEM, intermediate.CertPEM)
	defer server.Close()

	keyPath := filepath.Join(tmpDir, "site", "key.pem")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	oldOnlineKey := "-----BEGIN RSA PRIVATE KEY-----\nold-online\n-----END RSA PRIVATE KEY-----"
	if err := os.WriteFile(keyPath, []byte(oldOnlineKey), 0600); err != nil {
		t.Fatalf("写入线上私钥失败: %v", err)
	}

	cert := &config.CertConfig{
		CertName:  "im.example.com-300",
		OrderID:   300,
		RenewMode: config.RenewModeLocal,
		Domains:   []string{"im.example.com"},
		API:       config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			CertExpiresAt: time.Now().Add(5 * 24 * time.Hour),
		},
		Bindings: []config.SiteBinding{{
			ServerName: "im-site",
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
			Paths: config.BindingPaths{
				Certificate: filepath.Join(tmpDir, "site", "cert.pem"),
				PrivateKey:  keyPath,
			},
		}},
	}
	// 证书需存在于配置中（prepareLocalRenew 会持久化重试计数）
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书配置失败: %v", err)
	}

	_, _, err = svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if err == nil {
		t.Fatal("立即 active 但证书与新 CSR 不配对时应按失败处理")
	}

	// 线上私钥不得被覆盖
	got, _ := os.ReadFile(keyPath)
	if string(got) != oldOnlineKey {
		t.Error("线上私钥被覆盖（应保持原内容）")
	}
	// pending 私钥（本次生成）应保留
	if _, err := readPendingKey(cm.GetWorkDir(), "im.example.com-300"); err != nil {
		t.Errorf("pending 私钥应保留: %v", err)
	}
}
