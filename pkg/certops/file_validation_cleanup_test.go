// Package certops 验证文件放置失败反馈与清理测试
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
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	certs "github.com/zhuxbo/sslctl/testdata/certs"
)

// TestApplyValidationFiles_NoWebrootFails 验证文件挑战存在但无可用 webroot 时返回明确错误
// （原实现静默放弃，验证文件从未就位，签发每天停在 pending 无人知晓）。
func TestApplyValidationFiles_NoWebrootFails(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	cert := &config.CertConfig{
		CertName: "noroot.example.com-1",
		Bindings: []config.SiteBinding{{
			ServerName: "noroot-site",
			Enabled:    true,
			// 无 Webroot
		}},
	}
	file := &fetcher.FileChallenge{Path: "/.well-known/pki-validation/x.txt", Content: "token"}

	if err := svc.applyValidationFiles(cert, file, false); err == nil {
		t.Error("无可用 webroot 时应返回错误（反馈闭环），而非静默放弃")
	}

	// 无挑战时为空操作
	if err := svc.applyValidationFiles(cert, nil, false); err != nil {
		t.Errorf("无挑战时应为空操作: %v", err)
	}
}

// TestApplyValidationFiles_Placed 验证正常放置：文件写入 webroot 且记录到元数据。
func TestApplyValidationFiles_Placed(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	webroot := filepath.Join(tmpDir, "www")
	if err := os.MkdirAll(webroot, 0755); err != nil {
		t.Fatalf("创建 webroot 失败: %v", err)
	}

	cert := &config.CertConfig{
		CertName: "root.example.com-2",
		Bindings: []config.SiteBinding{{
			ServerName: "root-site",
			Enabled:    true,
			Paths:      config.BindingPaths{Webroot: webroot},
		}},
	}
	file := &fetcher.FileChallenge{Path: "/.well-known/pki-validation/y.txt", Content: "token-y"}

	if err := svc.applyValidationFiles(cert, file, false); err != nil {
		t.Fatalf("有可用 webroot 时应放置成功: %v", err)
	}
	if len(cert.Metadata.ValidationFiles) != 1 {
		t.Fatalf("应记录 1 个验证文件，实际 %d", len(cert.Metadata.ValidationFiles))
	}
	data, err := os.ReadFile(cert.Metadata.ValidationFiles[0])
	if err != nil || string(data) != "token-y" {
		t.Errorf("验证文件内容不正确: %v", err)
	}
}

// TestPrepareLocalRenew_ProcessingNoWebroot_ReturnsFailure 验证 processing 分支
// 验证文件放置失败作为失败结果反馈（不再静默 pending）。
func TestPrepareLocalRenew_ProcessingNoWebroot_ReturnsFailure(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	// 服务端返回 processing + 文件挑战
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := fmt.Sprintf(`{"code":1,"msg":"ok","data":{"order_id":1100,"status":"processing","file":{"path":%q,"content":"tok"}}}`,
			"/.well-known/pki-validation/z.txt")
		_, _ = w.Write([]byte(resp))
	}))
	defer server.Close()

	cert := &config.CertConfig{
		CertName:  "nofile.example.com-1100",
		OrderID:   1100,
		RenewMode: config.RenewModeLocal,
		Domains:   []string{"nofile.example.com"},
		API:       config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			LastIssueState: "processing",
			CertExpiresAt:  time.Now().Add(5 * 24 * time.Hour),
		},
		Bindings: []config.SiteBinding{{
			ServerName: "nofile-site",
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
			Paths: config.BindingPaths{
				PrivateKey: filepath.Join(tmpDir, "key.pem"),
				// 无 Webroot：验证文件无法放置
			},
		}},
	}

	_, _, err = svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if err == nil {
		t.Error("验证文件无法放置时应按失败处理（反馈闭环）")
	}
}

// TestDeployCertToBindings_CleansValidationFilesEvenIfDeployFails 验证签发完成后
// 验证文件清理不依赖部署成功（原实现 deployCount=0 时验证文件残留 webroot）。
func TestDeployCertToBindings_CleansValidationFilesEvenIfDeployFails(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	testCert, err := certs.GenerateValidCert("clean.example.com", []string{"clean.example.com"})
	if err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}

	// 预置已放置的验证文件
	valFile := filepath.Join(tmpDir, "www", ".well-known", "pki-validation", "v.txt")
	if err := os.MkdirAll(filepath.Dir(valFile), 0755); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	if err := os.WriteFile(valFile, []byte("tok"), 0644); err != nil {
		t.Fatalf("写入验证文件失败: %v", err)
	}

	cert := &config.CertConfig{
		CertName: "clean.example.com-1200",
		OrderID:  1200,
		Metadata: config.CertMetadata{
			ValidationFiles: []string{valFile},
		},
		// 无启用绑定：deployCount 必为 0
		Bindings: []config.SiteBinding{{
			ServerName: "clean-site",
			ServerType: config.ServerTypeNginx,
			Enabled:    false,
		}},
	}

	certData := &fetcher.CertData{Cert: testCert.CertPEM}
	deployCount, _, _ := svc.deployCertToBindings(t.Context(), cert, certData, testCert.KeyPEM)
	if deployCount != 0 {
		t.Fatalf("deployCount 应为 0，实际 %d", deployCount)
	}

	// 验证文件应已清理（签发完成后用途已尽，不依赖部署成功）
	if _, err := os.Lstat(valFile); !os.IsNotExist(err) {
		t.Error("deployCount=0 时验证文件也应被清理")
	}
	if len(cert.Metadata.ValidationFiles) != 0 {
		t.Error("元数据中的验证文件记录应清空")
	}
}
