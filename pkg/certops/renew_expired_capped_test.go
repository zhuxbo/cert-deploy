// Package certops 过期且触顶证书可见性测试
package certops

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

// TestCheckAndRenewAll_ExpiredAndCappedVisible 验证"既过期又触顶"的证书不再静默跳过：
// 应记 Error 日志、上报 failure 回调（message 说明过期+超限）、并计入本轮统计，
// 与"临期触顶"路径的可见性对齐（原实现对该证书静默 return，三者皆缺）。
func TestCheckAndRenewAll_ExpiredAndCappedVisible(t *testing.T) {
	logDir := t.TempDir()
	log, err := logger.New(logDir, "test")
	if err != nil {
		t.Fatalf("创建 logger 失败: %v", err)
	}

	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, log)

	// 该路径不应发起证书查询；若误查会命中此业务错误响应
	rec := &callbackRecorder{queryResp: `{"code":0,"msg":"should not be queried"}`}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	cert := &config.CertConfig{
		CertName:  "dead.example.com-800",
		OrderID:   800,
		Enabled:   true,
		RenewMode: config.RenewModeLocal,
		Domains:   []string{"dead.example.com"},
		API:       config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			CertExpiresAt:   time.Now().Add(-48 * time.Hour), // 已过期
			IssueRetryCount: MaxIssueRetryCount,              // 已触顶
		},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	results, err := svc.CheckAndRenewAll(t.Context())
	if err != nil {
		t.Fatalf("CheckAndRenewAll 失败: %v", err)
	}
	_ = log.Close()

	// 1. 计入本轮统计（failure），而非静默消失
	if len(results) != 1 || results[0].Status != "failure" {
		t.Fatalf("过期且触顶证书应产生 failure 结果: %+v", results)
	}

	// 2. failure 回调（mock）：仅一次，携带过期原因 message
	cbs := rec.recorded()
	if len(cbs) != 1 {
		t.Fatalf("应上报 1 次 failure 回调，实际 %d", len(cbs))
	}
	if cbs[0].Status != "failure" || cbs[0].OrderID != 800 {
		t.Errorf("回调应为 failure: %+v", cbs[0])
	}
	if !strings.Contains(cbs[0].Message, "过期") {
		t.Errorf("回调 message 应说明证书已过期: %q", cbs[0].Message)
	}

	// 3. Error 日志：包含证书名与"已过期"字样
	logData, rerr := os.ReadFile(filepath.Join(logDir, "test-"+time.Now().Format("2006-01-02")+".log"))
	if rerr != nil {
		t.Fatalf("读取日志失败: %v", rerr)
	}
	if !strings.Contains(string(logData), "已过期") || !strings.Contains(string(logData), "dead.example.com-800") {
		t.Errorf("应记录过期且触顶的 Error 日志，实际日志:\n%s", string(logData))
	}
}
