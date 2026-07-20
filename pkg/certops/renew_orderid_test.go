// Package certops order_id 变更迁移 pending key 与 processing 自愈测试
package certops

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	certs "github.com/zhuxbo/sslctl/testdata/certs"
)

// TestSyncOrderID_MigratesPendingKey 验证 order_id 变更（订单续费）触发证书改名时
// pending 私钥一并迁移到新 certName 目录（原实现只改配置，pending key 留在旧路径，
// local 模式续签从此读不到 pending key）。
func TestSyncOrderID_MigratesPendingKey(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	keyPEM := "-----BEGIN RSA PRIVATE KEY-----\npending-content\n-----END RSA PRIVATE KEY-----"
	if err := savePendingKey(cm.GetWorkDir(), "mig.example.com-100", keyPEM); err != nil {
		t.Fatalf("保存 pending 私钥失败: %v", err)
	}

	cert := &config.CertConfig{
		CertName: "mig.example.com-100",
		OrderID:  100,
		Enabled:  true,
		Domains:  []string{"mig.example.com"},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	// 服务端返回新订单号（续费）
	svc.syncOrderID(cert, &fetcher.CertData{OrderID: 101})

	if cert.CertName != "mig.example.com-101" {
		t.Fatalf("certName 应更新为 mig.example.com-101，实际 %s", cert.CertName)
	}
	// pending 私钥应迁移到新路径
	got, err := readPendingKey(cm.GetWorkDir(), "mig.example.com-101")
	if err != nil {
		t.Fatalf("新 certName 路径应能读到 pending 私钥: %v", err)
	}
	if got != keyPEM {
		t.Error("迁移后 pending 私钥内容不应改变")
	}
	// 旧路径不应残留
	if _, err := os.Lstat(getPendingKeyPath(cm.GetWorkDir(), "mig.example.com-100")); !os.IsNotExist(err) {
		t.Error("旧路径 pending 私钥应已迁移走")
	}
}

// TestRenamePendingKey_NoPending 验证无 pending 私钥时迁移为空操作。
func TestRenamePendingKey_NoPending(t *testing.T) {
	tmpDir := t.TempDir()
	if err := renamePendingKey(tmpDir, "old-name", "new-name"); err != nil {
		t.Errorf("无 pending 私钥时应为空操作: %v", err)
	}
}

// TestFixCertName_ExportedMigratesPendingKey 验证导出的 FixCertName（CLI 部署链复用的
// 单一实现）改名时同步迁移 pending 私钥并重命名配置条目（nil log 场景不 panic）。
func TestFixCertName_ExportedMigratesPendingKey(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	keyPEM := "-----BEGIN RSA PRIVATE KEY-----\ncli-pending\n-----END RSA PRIVATE KEY-----"
	if err := savePendingKey(cm.GetWorkDir(), "cli.example.com-300", keyPEM); err != nil {
		t.Fatalf("保存 pending 私钥失败: %v", err)
	}

	cert := &config.CertConfig{
		CertName: "cli.example.com-300",
		OrderID:  301, // 订单已续费，名称待修正
		Enabled:  true,
		Domains:  []string{"cli.example.com"},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	FixCertName(cm, cert, nil)

	if cert.CertName != "cli.example.com-301" {
		t.Fatalf("certName 应修正为 cli.example.com-301，实际 %s", cert.CertName)
	}
	// pending 私钥应迁移到新路径
	got, err := readPendingKey(cm.GetWorkDir(), "cli.example.com-301")
	if err != nil || got != keyPEM {
		t.Errorf("pending 私钥应迁移到新 certName 路径: %v", err)
	}
	// 配置条目应已重命名
	if _, err := cm.GetCert("cli.example.com-301"); err != nil {
		t.Errorf("配置条目应已重命名: %v", err)
	}
	// 名称已一致时为空操作
	FixCertName(cm, cert, nil)
	if cert.CertName != "cli.example.com-301" {
		t.Error("名称一致时不应再改名")
	}
}

// TestPrepareLocalRenew_ProcessingPendingLost_ResetsForResubmit 验证 processing→active
// 但 pending 私钥缺失且正式私钥与服务端证书不配对时：重置签发状态走重新提交 CSR 路径
// （原实现每天走到相同失败且 retry 不递增，local 模式续签永久卡死）。
func TestPrepareLocalRenew_ProcessingPendingLost_ResetsForResubmit(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	// 服务端返回证书 A；线上正式私钥是 B 的（不配对）；无 pending 私钥
	certA, err := certs.GenerateValidCert("lost.example.com", []string{"lost.example.com"})
	if err != nil {
		t.Fatalf("生成证书 A 失败: %v", err)
	}
	certB, err := certs.GenerateValidCert("lost.example.com", []string{"lost.example.com"})
	if err != nil {
		t.Fatalf("生成证书 B 失败: %v", err)
	}
	intermediate, err := certs.GenerateValidCert("Test CA", nil)
	if err != nil {
		t.Fatalf("生成中间证书失败: %v", err)
	}

	keyPath := filepath.Join(tmpDir, "site", "key.pem")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(certB.KeyPEM), 0600); err != nil {
		t.Fatalf("写入线上私钥失败: %v", err)
	}

	server := newQueryOrderServer(t, 900, "active", certA.CertPEM, intermediate.CertPEM)
	defer server.Close()

	cert := &config.CertConfig{
		CertName:  "lost.example.com-900",
		OrderID:   900,
		Enabled:   true,
		RenewMode: config.RenewModeLocal,
		Domains:   []string{"lost.example.com"},
		API:       config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			LastIssueState: "processing",
			CertExpiresAt:  time.Now().Add(5 * 24 * time.Hour),
		},
		Bindings: []config.SiteBinding{{
			ServerName: "lost-site",
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
			Paths: config.BindingPaths{
				Certificate: filepath.Join(tmpDir, "site", "cert.pem"),
				PrivateKey:  keyPath,
			},
		}},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	_, _, err = svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if err == nil {
		t.Fatal("pending 缺失且正式私钥不配对时应返回错误")
	}

	// 签发状态应被重置（下轮走重新提交 CSR 而非再次卡 processing）
	saved, getErr := cm.GetCert("lost.example.com-900")
	if getErr != nil {
		t.Fatalf("获取证书失败: %v", getErr)
	}
	if saved.Metadata.LastIssueState != "" {
		t.Errorf("LastIssueState 应重置为空（走重新提交路径），实际 %q", saved.Metadata.LastIssueState)
	}
	// 线上私钥不受影响
	got, _ := os.ReadFile(keyPath)
	if string(got) != certB.KeyPEM {
		t.Error("线上私钥不应被改动")
	}
}

// TestPrepareLocalRenew_ProcessingPendingLost_FallbackKeyMatches 验证 pending 缺失
// 但正式私钥与服务端证书配对（上次部署成功但清状态失败的合法场景）：正常继续部署，不重置。
func TestPrepareLocalRenew_ProcessingPendingLost_FallbackKeyMatches(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	certA, err := certs.GenerateValidCert("match.example.com", []string{"match.example.com"})
	if err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}
	intermediate, err := certs.GenerateValidCert("Test CA", nil)
	if err != nil {
		t.Fatalf("生成中间证书失败: %v", err)
	}

	keyPath := filepath.Join(tmpDir, "site", "key.pem")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	// 正式私钥与服务端证书配对
	if err := os.WriteFile(keyPath, []byte(certA.KeyPEM), 0600); err != nil {
		t.Fatalf("写入线上私钥失败: %v", err)
	}

	server := newQueryOrderServer(t, 901, "active", certA.CertPEM, intermediate.CertPEM)
	defer server.Close()

	cert := &config.CertConfig{
		CertName:  "match.example.com-901",
		OrderID:   901,
		Enabled:   true,
		RenewMode: config.RenewModeLocal,
		Domains:   []string{"match.example.com"},
		API:       config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			LastIssueState: "processing",
			CertExpiresAt:  time.Now().Add(5 * 24 * time.Hour),
		},
		Bindings: []config.SiteBinding{{
			ServerName: "match-site",
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
			Paths: config.BindingPaths{
				Certificate: filepath.Join(tmpDir, "site", "cert.pem"),
				PrivateKey:  keyPath,
			},
		}},
	}

	certData, privateKey, err := svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if err != nil {
		t.Fatalf("正式私钥配对时应正常继续部署: %v", err)
	}
	if certData == nil || privateKey != certA.KeyPEM {
		t.Error("应返回证书数据与正式私钥")
	}
}
