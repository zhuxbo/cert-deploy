// Package certops 无进展时限（停更闸门）测试
package certops

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

func daysAgo(d int) time.Time { return time.Now().Add(-time.Duration(d) * 24 * time.Hour) }

// TestStalledTooLong 时限判定与时钟保守分支
func TestStalledTooLong(t *testing.T) {
	tests := []struct {
		name         string
		since        time.Time
		wantStalled  bool
		wantReanchor bool
	}{
		{"未锚定", time.Time{}, false, false},
		{"未到时限", daysAgo(config.MaxNoProgressDays - 1), false, false},
		{"刚到时限", daysAgo(config.MaxNoProgressDays), true, false},
		{"远超时限", daysAgo(config.MaxNoProgressDays + 10), true, false},
		// 时钟不可信一律重锚而非判停更：宁可多查几轮，也不把正常等待签发的证书误判停更
		{"时钟回拨（起点在未来）", time.Now().Add(48 * time.Hour), false, true},
		{"间隔超可信上限（时钟跳变）", daysAgo(config.ClockSanityMaxDays + 1), false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm, err := config.NewConfigManagerWithDir(t.TempDir())
			if err != nil {
				t.Fatalf("创建配置管理器失败: %v", err)
			}
			svc := NewService(cm, logger.NewNopLogger())
			cert := &config.CertConfig{CertName: "c-1", OrderID: 1}
			cert.Metadata.NoProgressSince = tt.since

			got := svc.stalledTooLong(cert)
			if got != tt.wantStalled {
				t.Errorf("stalledTooLong() = %v, want %v", got, tt.wantStalled)
			}
			if tt.wantReanchor {
				if cert.Metadata.NoProgressSince.Equal(tt.since) {
					t.Error("时钟不可信时应重新锚定，实际未变")
				}
				if time.Since(cert.Metadata.NoProgressSince) > time.Minute {
					t.Errorf("应重锚到当前时刻，实际 %v", cert.Metadata.NoProgressSince)
				}
			}
		})
	}
}

// TestNoProgressGateReachableWhenExpiryUnknown 闸门在「到期时间未知 + 查询持续失败」下必须可达。
//
// 这是无进展时限的主场景：新证书的 cert_expires_at 默认为空、只有部署成功才回填，
// 而到期闸门对零值恒返回 false。若停更判定排在回填之后，这条路径每轮都在
// refreshExpiryFromAPI 里 return，永远走不到闸门——每天空查询到永远。
func TestNoProgressGateReachableWhenExpiryUnknown(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	var queries int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		queries++
		w.Header().Set("Content-Type", "application/json")
		// 订单不存在：确定性失败，回填永远不会成功
		_, _ = fmt.Fprint(w, `{"code":0,"msg":"未找到匹配的订单","errors":{"error_code":"order_not_found"}}`)
	}))
	defer server.Close()

	cert := &config.CertConfig{
		CertName: "unknown-expiry-1",
		OrderID:  1,
		Enabled:  true,
		Domains:  []string{"unknown-expiry.example.com"},
		API:      config.APIConfig{URL: server.URL, Token: "t"},
		Bindings: []config.SiteBinding{{
			ServerName: "unknown-expiry.example.com",
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
		}},
	}
	// 到期时间未知 + 已无进展满时限
	cert.Metadata.NoProgressSince = daysAgo(config.MaxNoProgressDays)
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	cfg, err := cm.Load()
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}
	processed := 0
	result, madeAPICall := svc.processCertRenewal(t.Context(), cfg, *cert, &processed)

	if queries != 0 {
		t.Errorf("停更闸门应在任何 API 请求之前生效，实际查询 %d 次", queries)
	}
	if madeAPICall {
		t.Error("停更路径不应发起 API 请求")
	}
	if result != nil {
		t.Errorf("停更为静默终止，不应产生上报结果，实际 %+v", result)
	}

	stored, err := cm.GetCert(cert.CertName)
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	if stored.Metadata.LastIssueState != config.IssueStateCapped {
		t.Errorf("last_issue_state = %q, want %q", stored.Metadata.LastIssueState, config.IssueStateCapped)
	}
	if stored.Metadata.CappedPhase != config.CappedPhaseStalled {
		t.Errorf("capped_phase = %q, want %q", stored.Metadata.CappedPhase, config.CappedPhaseStalled)
	}
	if !stored.Metadata.NoProgressSince.IsZero() {
		t.Error("停更落定后应清空计时（已转入 CAPPED，不再需要）")
	}
}

// TestMarkStalledCleansInFlightArtifacts 停更时清理在途产物：
// 私钥不能因为一张永远签不出来的证书永久驻留磁盘
func TestMarkStalledCleansInFlightArtifacts(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	cert := &config.CertConfig{CertName: "stale-1", OrderID: 1, Enabled: true}
	cert.Metadata.NoProgressSince = daysAgo(config.MaxNoProgressDays)
	cert.Metadata.CSRSubmittedAt = daysAgo(config.MaxNoProgressDays)
	cert.Metadata.LastCSRHash = "deadbeef"
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}
	if err := savePendingKey(cm.GetWorkDir(), cert.CertName, "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"); err != nil {
		t.Fatalf("保存 pending 私钥失败: %v", err)
	}

	svc.markStalled(cert)

	if _, err := readPendingKey(cm.GetWorkDir(), cert.CertName); err == nil {
		t.Error("停更应清理 pending 私钥，实际仍可读")
	}
	if !cert.Metadata.CSRSubmittedAt.IsZero() || cert.Metadata.LastCSRHash != "" {
		t.Error("停更应清除在途 CSR 标记，否则会被误判为仍有在途提交")
	}
	if cert.Metadata.CappedPhase != config.CappedPhaseStalled {
		t.Errorf("capped_phase = %q, want %q", cert.Metadata.CappedPhase, config.CappedPhaseStalled)
	}
}

// TestSettleNoProgress 快照结算：状态前进则清零，纯查询则锚定首次
func TestSettleNoProgress(t *testing.T) {
	newSvc := func(t *testing.T) (*Service, *config.ConfigManager) {
		t.Helper()
		cm, err := config.NewConfigManagerWithDir(t.TempDir())
		if err != nil {
			t.Fatalf("创建配置管理器失败: %v", err)
		}
		return NewService(cm, logger.NewNopLogger()), cm
	}

	t.Run("未发起请求不结算", func(t *testing.T) {
		svc, _ := newSvc(t)
		cert := &config.CertConfig{CertName: "c", OrderID: 1}
		before := snapshotProgress(cert)
		svc.settleNoProgress(cert, before, false)
		if !cert.Metadata.NoProgressSince.IsZero() {
			t.Error("静默跳过的轮次不该计入无进展")
		}
	})

	t.Run("纯查询无进展则锚定", func(t *testing.T) {
		svc, cm := newSvc(t)
		cert := &config.CertConfig{CertName: "c", OrderID: 1, Enabled: true}
		if err := cm.AddCert(cert); err != nil {
			t.Fatalf("添加失败: %v", err)
		}
		before := snapshotProgress(cert)
		svc.settleNoProgress(cert, before, true)
		if cert.Metadata.NoProgressSince.IsZero() {
			t.Fatal("无进展应锚定起点")
		}

		// 锚定首次、不滑动：再来一轮不得刷新时间戳，否则永远达不到时限
		first := cert.Metadata.NoProgressSince
		svc.settleNoProgress(cert, snapshotProgress(cert), true)
		if !cert.Metadata.NoProgressSince.Equal(first) {
			t.Error("无进展起点必须锚定首次，不得每轮刷新")
		}
	})

	t.Run("部署发生即清零", func(t *testing.T) {
		svc, cm := newSvc(t)
		cert := &config.CertConfig{CertName: "c", OrderID: 1, Enabled: true}
		cert.Metadata.NoProgressSince = daysAgo(5)
		if err := cm.AddCert(cert); err != nil {
			t.Fatalf("添加失败: %v", err)
		}
		before := snapshotProgress(cert)
		cert.Metadata.LastDeployAt = time.Now()
		svc.settleNoProgress(cert, before, true)
		if !cert.Metadata.NoProgressSince.IsZero() {
			t.Error("部署发生应清零无进展计时")
		}
	})

	t.Run("CSR 被接受即清零", func(t *testing.T) {
		svc, cm := newSvc(t)
		cert := &config.CertConfig{CertName: "c", OrderID: 1, Enabled: true}
		cert.Metadata.NoProgressSince = daysAgo(5)
		if err := cm.AddCert(cert); err != nil {
			t.Fatalf("添加失败: %v", err)
		}
		before := snapshotProgress(cert)
		cert.Metadata.CSRSubmittedAt = time.Now()
		svc.settleNoProgress(cert, before, true)
		if !cert.Metadata.NoProgressSince.IsZero() {
			t.Error("CSR 被服务端接受应清零无进展计时")
		}
	})

	t.Run("到期时间回填即清零", func(t *testing.T) {
		svc, cm := newSvc(t)
		cert := &config.CertConfig{CertName: "c", OrderID: 1, Enabled: true}
		cert.Metadata.NoProgressSince = daysAgo(5)
		if err := cm.AddCert(cert); err != nil {
			t.Fatalf("添加失败: %v", err)
		}
		before := snapshotProgress(cert)
		cert.Metadata.CertExpiresAt = time.Now().Add(60 * 24 * time.Hour)
		svc.settleNoProgress(cert, before, true)
		if !cert.Metadata.NoProgressSince.IsZero() {
			t.Error("到期时间回填成功应清零无进展计时")
		}
	})

	t.Run("重置签发状态不算进展", func(t *testing.T) {
		svc, cm := newSvc(t)
		cert := &config.CertConfig{CertName: "c", OrderID: 1, Enabled: true}
		if err := cm.AddCert(cert); err != nil {
			t.Fatalf("添加失败: %v", err)
		}
		before := snapshotProgress(cert)
		// resetIssueStateForResubmit 的效果：清空签发状态以便下轮重新提交。
		// 那是本轮流程失效后的回退，不是前进——否则「pending 私钥反复缺失」会永远清零计时
		cert.Metadata.LastIssueState = ""
		cert.Metadata.LastOrderStatus = config.OrderStatusFailed
		svc.settleNoProgress(cert, before, true)
		if cert.Metadata.NoProgressSince.IsZero() {
			t.Error("重置签发状态与订单状态变化都不算进展，应锚定无进展起点")
		}
	})
}
