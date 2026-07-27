// Package certops 单证书 panic 隔离测试
package certops

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/webserver"
	certs "github.com/zhuxbo/sslctl/testdata/certs"
)

// panicServerType 部署时 panic 的测试服务器类型
const panicServerType = "panic-server"

// panicDeployer 部署即 panic 的测试部署器
type panicDeployer struct{}

func (p *panicDeployer) Deploy(_ context.Context, _, _, _ string) error   { panic("deployer exploded") }
func (p *panicDeployer) Reload(_ context.Context) error                   { return nil }
func (p *panicDeployer) Test(_ context.Context) error                     { return nil }
func (p *panicDeployer) Rollback(_ context.Context, _, _, _ string) error { return nil }

func init() {
	webserver.RegisterDeployer(webserver.ServerType(panicServerType), func(_, _, _, _, _ string) webserver.Deployer {
		return &panicDeployer{}
	})
}

// TestProcessCertRenewal_PanicIsolated 验证单证书处理 panic 被隔离：
// 记为该证书 failure 并计入统计，后续证书继续正常处理（原实现整轮续签被 panic 拖垮，
// 全仓仅 daemon 顶层一处 recover）。
func TestProcessCertRenewal_PanicIsolated(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	liveCert, err := certs.GenerateValidCert("panic.example.com", []string{"panic.example.com"})
	if err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}
	intermediate, err := certs.GenerateValidCert("Test CA", nil)
	if err != nil {
		t.Fatalf("生成中间证书失败: %v", err)
	}

	// 记录回调的 mock：查询返回 active 证书
	rec := &callbackRecorder{queryResp: fmt.Sprintf(
		`{"code":1,"msg":"ok","data":{"order_id":1000,"status":"active","certificate":%q,"ca_certificate":%q}}`,
		liveCert.CertPEM, intermediate.CertPEM)}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	cfg := &config.Config{Schedule: config.ScheduleConfig{RenewBeforeDays: 14}}

	// 预置本地私钥（pull 模式从绑定私钥路径读取）
	for _, sub := range []string{"p", "n"} {
		if err := os.MkdirAll(filepath.Join(tmpDir, sub), 0700); err != nil {
			t.Fatalf("创建目录失败: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, sub, "key.pem"), []byte(liveCert.KeyPEM), 0600); err != nil {
			t.Fatalf("写入私钥失败: %v", err)
		}
	}

	// 证书 1：部署器 panic
	panicCert := config.CertConfig{
		CertName: "panic.example.com-1000",
		OrderID:  1000,
		Enabled:  true,
		Domains:  []string{"panic.example.com"},
		API:      config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			CertExpiresAt: time.Now().Add(3 * 24 * time.Hour), // 临期
		},
		Bindings: []config.SiteBinding{{
			ServerName: "panic-site",
			ServerType: panicServerType,
			Enabled:    true,
			Paths: config.BindingPaths{
				Certificate: filepath.Join(tmpDir, "p", "cert.pem"),
				PrivateKey:  filepath.Join(tmpDir, "p", "key.pem"),
			},
		}},
	}
	if err := cm.AddCert(&panicCert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	processedCount := 0
	result, madeAPICall := svc.processCertRenewal(t.Context(), cfg, panicCert, &processedCount)
	if result == nil {
		t.Fatal("panic 证书应产生结果（计入统计）而非丢失")
	}
	if result.Status != "failure" || result.Error == nil || !strings.Contains(result.Error.Error(), "panic") {
		t.Errorf("panic 应记为该证书 failure 且错误含 panic 信息: %+v", result)
	}
	if !madeAPICall {
		t.Error("panic 前已发起 API 请求，应返回 madeAPICall=true")
	}
	// panic 无干净部署结果：不上报回调（计划 1.2/spec 2.8），仅记 Error 日志与失败结果供统计
	if cbs := rec.recorded(); len(cbs) != 0 {
		t.Errorf("panic 恢复路径不应上报回调，实际 %+v", cbs)
	}

	// 证书 2：panic 之后继续正常处理（模拟外层循环的下一个证书）
	normalCert := config.CertConfig{
		CertName: "panic.example.com-1001",
		OrderID:  1001,
		Enabled:  true,
		Domains:  []string{"panic.example.com"},
		API:      config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			CertExpiresAt: time.Now().Add(3 * 24 * time.Hour),
		},
		Bindings: []config.SiteBinding{{
			ServerName: "normal-site",
			ServerType: config.ServerTypeNginx, // mock 部署器，正常成功
			Enabled:    true,
			Paths: config.BindingPaths{
				Certificate: filepath.Join(tmpDir, "n", "cert.pem"),
				PrivateKey:  filepath.Join(tmpDir, "n", "key.pem"),
			},
		}},
	}
	if err := cm.AddCert(&normalCert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	result2, _ := svc.processCertRenewal(t.Context(), cfg, normalCert, &processedCount)
	if result2 == nil || result2.Status != "success" {
		t.Errorf("panic 证书之后的证书应正常处理: %+v", result2)
	}
}
