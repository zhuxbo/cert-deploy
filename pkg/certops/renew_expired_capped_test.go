// Package certops 过期/触顶证书静默测试
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

// TestCheckAndRenewAll_ExpiredSilentNoCallback 验证已过期证书静默终止（计划 1.1/spec 3.2）：
// 转 EXPIRED、仅留本地日志、不发起查询、不上报任何回调、不产生续签结果。
// "既过期又触顶"时过期优先（转 EXPIRED 而非 CAPPED），语义与单纯过期一致。
func TestCheckAndRenewAll_ExpiredSilentNoCallback(t *testing.T) {
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
			IssueRetryCount: MaxIssueRetryCount,              // 已触顶（过期优先转 EXPIRED）
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

	// 1. 静默：不产生续签结果
	if len(results) != 0 {
		t.Fatalf("过期证书应静默跳过，不产生结果: %+v", results)
	}

	// 2. 不上报任何回调
	if cbs := rec.recorded(); len(cbs) != 0 {
		t.Fatalf("过期证书不应上报回调，实际 %d 次: %+v", len(cbs), cbs)
	}

	// 3. 落盘 EXPIRED 状态（过期优先于触顶）
	updated, gerr := cm.GetCert("dead.example.com-800")
	if gerr != nil {
		t.Fatalf("获取证书失败: %v", gerr)
	}
	if updated.Metadata.LastIssueState != config.IssueStateExpired {
		t.Errorf("应转 EXPIRED，实际 %q", updated.Metadata.LastIssueState)
	}

	// 4. 本地 Error 日志可见（管理端/日志可见性，替代回调）
	logData, rerr := os.ReadFile(filepath.Join(logDir, "test-"+time.Now().Format("2006-01-02")+".log"))
	if rerr != nil {
		t.Fatalf("读取日志失败: %v", rerr)
	}
	if !strings.Contains(string(logData), "已过期") || !strings.Contains(string(logData), "dead.example.com-800") {
		t.Errorf("应记录过期 Error 日志，实际日志:\n%s", string(logData))
	}
}
