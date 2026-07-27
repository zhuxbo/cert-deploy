// Package certops 续签判定零值与参数边界测试
package certops

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
	certs "github.com/zhuxbo/sslctl/testdata/certs"
)

// TestTryUpdateRenewBeforeDays_Bounds 验证 renew_before_days 的边界处理：
// 非法值（≤0）与超上限值被拒绝并保留旧值，合法值正常更新。
func TestTryUpdateRenewBeforeDays_Bounds(t *testing.T) {
	tests := []struct {
		name  string
		value int
		want  int // 更新后的期望值（初始 14）
	}{
		{"零值忽略", 0, 14},
		{"负值忽略", -5, 14},
		{"合法值更新", 30, 30},
		{"上限值更新", MaxRenewBeforeDays, MaxRenewBeforeDays},
		{"超上限拒绝保留旧值", MaxRenewBeforeDays + 1, 14},
		{"极端异常值拒绝", 100000, 14},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cm, err := config.NewConfigManagerWithDir(tmpDir)
			if err != nil {
				t.Fatalf("创建配置管理器失败: %v", err)
			}
			if err := cm.UpdateSchedule(func(sc *config.ScheduleConfig) {
				sc.RenewBeforeDays = 14
			}); err != nil {
				t.Fatalf("初始化 schedule 失败: %v", err)
			}
			svc := NewService(cm, logger.NewNopLogger())

			svc.tryUpdateRenewBeforeDays(tt.value)

			cfg, err := cm.Load()
			if err != nil {
				t.Fatalf("加载配置失败: %v", err)
			}
			if cfg.Schedule.RenewBeforeDays != tt.want {
				t.Errorf("renew_before_days = %d, want %d", cfg.Schedule.RenewBeforeDays, tt.want)
			}
		})
	}
}

// TestIsExpired_NoTruncationDrift 验证过期判定按时间点比较：
// 过期不足 24 小时的证书也视为已过期（原整数天截断使判定偏移约 24h，
// 过期 1 小时的证书 days=0 仍会触发续签，违反"已过期不再自动操作"）。
func TestIsExpired_NoTruncationDrift(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{"零值未知不算过期", time.Time{}, false},
		{"过期 1 小时算已过期", time.Now().Add(-1 * time.Hour), true},
		{"过期 23 小时算已过期", time.Now().Add(-23 * time.Hour), true},
		{"过期 3 天算已过期", time.Now().Add(-72 * time.Hour), true},
		{"剩余 1 小时未过期", time.Now().Add(1 * time.Hour), false},
		{"剩余 30 天未过期", time.Now().Add(30 * 24 * time.Hour), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &config.CertConfig{Metadata: config.CertMetadata{CertExpiresAt: tt.expiresAt}}
			if got := c.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNeedsRenewal_ExpiredWithinOneDay 回归：过期不足 24 小时的证书不应触发续签。
func TestNeedsRenewal_ExpiredWithinOneDay(t *testing.T) {
	schedule := &config.ScheduleConfig{RenewBeforeDays: 14}

	expired1h := &config.CertConfig{Metadata: config.CertMetadata{
		CertExpiresAt: time.Now().Add(-1 * time.Hour),
	}}
	if expired1h.NeedsRenewal(schedule) {
		t.Error("过期 1 小时的证书不应触发续签（已过期等待人工处理）")
	}

	// 零值：未知需处理，由续签检查回填后判定，NeedsRenewal 本身返回 false
	zero := &config.CertConfig{}
	if zero.NeedsRenewal(schedule) {
		t.Error("到期时间未知时 NeedsRenewal 应返回 false（由调用方先回填）")
	}

	// 临期正常触发
	expiring := &config.CertConfig{Metadata: config.CertMetadata{
		CertExpiresAt: time.Now().Add(3 * 24 * time.Hour),
	}}
	if !expiring.NeedsRenewal(schedule) {
		t.Error("临期证书应触发续签")
	}
}

// TestCheckAndRenewAll_ZeroExpiryRefillsFromAPI 验证到期时间未知（零值）的证书
// 不再被静默跳过：续签检查会查询 API 回填元数据后按正常逻辑判定
// （原实现 DaysUntilExpiry 零值返回 999 → NeedsRenewal 恒 false → 永不续签）。
func TestCheckAndRenewAll_ZeroExpiryRefillsFromAPI(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	// 服务端返回有效期充足的证书（60 天）：回填后无需续签
	liveCert, err := certs.GenerateValidCert("zero.example.com", []string{"zero.example.com"})
	if err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}
	intermediate, err := certs.GenerateValidCert("Test CA", nil)
	if err != nil {
		t.Fatalf("生成中间证书失败: %v", err)
	}

	server := newQueryOrderServer(t, 700, "active", liveCert.CertPEM, intermediate.CertPEM)
	defer server.Close()

	cert := &config.CertConfig{
		CertName: "zero.example.com-700",
		OrderID:  700,
		Enabled:  true,
		Domains:  []string{"zero.example.com"},
		API:      config.APIConfig{URL: server.URL, Token: "test-token"},
		// CertExpiresAt 零值：模拟部署成功但元数据保存失败/带外换证
		// 回填路径要求证书有启用绑定：零绑定证书由闸门在回填之前拦截（零 API 请求）
		Bindings: []config.SiteBinding{{
			ServerName: "zero.example.com",
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
		}},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	results, err := svc.CheckAndRenewAll(t.Context())
	if err != nil {
		t.Fatalf("CheckAndRenewAll 失败: %v", err)
	}
	// 有效期充足：回填后不应产生续签结果
	if len(results) != 0 {
		t.Errorf("回填后有效期充足不应续签: %+v", results)
	}

	// 元数据应已回填持久化
	updated, err := cm.GetCert("zero.example.com-700")
	if err != nil {
		t.Fatalf("获取证书失败: %v", err)
	}
	if updated.Metadata.CertExpiresAt.IsZero() {
		t.Error("CertExpiresAt 应已从服务端回填")
	}
	if updated.Metadata.CertSerial == "" {
		t.Error("CertSerial 应已从服务端回填")
	}
}

// TestCheckAndRenewAll_ZeroExpiryQueryFailSkipsQuietly 验证回填查询失败时本轮跳过（下轮重试），
// 不产生 failure 结果（避免元数据缺失被当作续签失败反复告警）。
func TestCheckAndRenewAll_ZeroExpiryQueryFailSkipsQuietly(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	rec := &callbackRecorder{queryResp: `{"code":0,"msg":"query fail"}`}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	cert := &config.CertConfig{
		CertName: "zerofail.example.com-800",
		OrderID:  800,
		Enabled:  true,
		Domains:  []string{"zerofail.example.com"},
		API:      config.APIConfig{URL: server.URL, Token: "test-token"},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	results, err := svc.CheckAndRenewAll(t.Context())
	if err != nil {
		t.Fatalf("CheckAndRenewAll 失败: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("回填失败应本轮跳过而非计为续签失败: %+v", results)
	}
}
