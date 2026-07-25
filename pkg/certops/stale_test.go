// Package certops 陈旧绑定兜底迁移与告警的测试（P2-2）
package certops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

func newStaleTestService(t *testing.T, certs []config.CertConfig) (*Service, *config.ConfigManager, string) {
	t.Helper()
	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	cfg, err := cm.Load()
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}
	cfg.Certificates = certs
	if err := cm.Save(cfg); err != nil {
		t.Fatalf("保存配置失败: %v", err)
	}
	return NewService(cm, logger.NewNopLogger()), cm, dir
}

// TestPersistTerminalState_MigratesFailedBindings 进入终止态时必须把待重试的绑定
// 迁入 stale：终止后不会再有人重试它们，不迁走等于静默丢弃。
func TestPersistTerminalState_MigratesFailedBindings(t *testing.T) {
	failedAt := time.Now().Add(-72 * time.Hour)
	svc, cm, _ := newStaleTestService(t, []config.CertConfig{{
		CertName: "cert-a",
		OrderID:  1,
		Enabled:  true,
		Bindings: []config.SiteBinding{
			{ServerName: "kept.example.com", Enabled: true},
			{ServerName: "also-kept.example.com", Enabled: false},
		},
		Metadata: config.CertMetadata{
			// ghost.example.com 已不在 Bindings 中（改绑到其它证书），必须被过滤掉，
			// 否则 ClearStaleBinding 永远收不到这个入参，告警无法消除
			FailedBindings:   []string{"kept.example.com", "also-kept.example.com", "ghost.example.com"},
			FailedBindingsAt: failedAt,
		},
	}})

	cert, err := cm.GetCert("cert-a")
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	svc.persistTerminalState(cert, config.IssueStateCapped, "deploy")

	got, err := cm.GetCert("cert-a")
	if err != nil {
		t.Fatalf("重新读取证书失败: %v", err)
	}
	if len(got.Metadata.FailedBindings) != 0 {
		t.Errorf("FailedBindings = %v, 期望已清空", got.Metadata.FailedBindings)
	}
	want := map[string]bool{"kept.example.com": true, "also-kept.example.com": true}
	if len(got.Metadata.StaleBindings) != len(want) {
		t.Fatalf("StaleBindings = %v, 期望 2 项（幽灵绑定被过滤）", got.Metadata.StaleBindings)
	}
	for _, name := range got.Metadata.StaleBindings {
		if !want[name] {
			t.Errorf("StaleBindings 含意外项 %q（幽灵绑定应被过滤）", name)
		}
	}
	if got.Metadata.StaleSince.IsZero() {
		t.Error("StaleSince 应被设置")
	}
	if !got.Metadata.StaleSince.Equal(failedAt.Truncate(time.Second)) &&
		got.Metadata.StaleSince.Sub(failedAt).Abs() > time.Second {
		t.Errorf("StaleSince = %v, 期望沿用 FailedBindingsAt %v", got.Metadata.StaleSince, failedAt)
	}
}

// TestPersistTerminalState_NoFailedBindingsUnchanged 无待重试绑定时不应凭空造出 stale
func TestPersistTerminalState_NoFailedBindingsUnchanged(t *testing.T) {
	svc, cm, _ := newStaleTestService(t, []config.CertConfig{{
		CertName: "cert-b",
		OrderID:  2,
		Enabled:  true,
		Bindings: []config.SiteBinding{{ServerName: "site.example.com", Enabled: true}},
	}})

	cert, err := cm.GetCert("cert-b")
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	svc.persistTerminalState(cert, config.IssueStateExpired, "")

	got, err := cm.GetCert("cert-b")
	if err != nil {
		t.Fatalf("重新读取证书失败: %v", err)
	}
	if len(got.Metadata.StaleBindings) != 0 {
		t.Errorf("StaleBindings = %v, 期望为空", got.Metadata.StaleBindings)
	}
	if !got.Metadata.StaleSince.IsZero() {
		t.Errorf("StaleSince = %v, 期望零值", got.Metadata.StaleSince)
	}
}

// TestCheckExpiry_AlertsStaleBindings 证书级到期日只反映最新签发的证书，
// 陈旧绑定仍挂着旧证书，必须单独持续告警。
func TestCheckExpiry_AlertsStaleBindings(t *testing.T) {
	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	cfg, err := cm.Load()
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}
	cfg.Certificates = []config.CertConfig{{
		CertName: "cert-c",
		OrderID:  3,
		Enabled:  true,
		Bindings: []config.SiteBinding{{ServerName: "stale.example.com", Enabled: true}},
		Metadata: config.CertMetadata{
			// 证书本身很新，按证书级判断完全看不出风险
			CertExpiresAt: time.Now().Add(80 * 24 * time.Hour),
			StaleBindings: []string{"stale.example.com"},
			StaleSince:    time.Now().Add(-30 * 24 * time.Hour),
		},
	}}
	if err := cm.Save(cfg); err != nil {
		t.Fatalf("保存配置失败: %v", err)
	}

	logDir := filepath.Join(dir, "logs")
	log, err := logger.New(logDir, "stale-test")
	if err != nil {
		t.Fatalf("创建日志器失败: %v", err)
	}
	NewService(cm, log).CheckExpiry()

	entries, err := os.ReadDir(logDir)
	if err != nil {
		t.Fatalf("读取日志目录失败: %v", err)
	}
	var combined string
	for _, e := range entries {
		data, readErr := os.ReadFile(filepath.Join(logDir, e.Name()))
		if readErr != nil {
			t.Fatalf("读取日志文件失败: %v", readErr)
		}
		combined += string(data)
	}
	if !strings.Contains(combined, "stale.example.com") {
		t.Errorf("陈旧绑定缺少告警，日志内容:\n%s", combined)
	}
	if !strings.Contains(combined, "ERROR") {
		t.Errorf("陈旧绑定告警应为 Error 级别，日志内容:\n%s", combined)
	}
}
