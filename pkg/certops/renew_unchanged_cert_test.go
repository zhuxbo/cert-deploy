// Package certops 证书未更替检测（伪成功循环）测试
package certops

import (
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

func newUnchangedSvc(t *testing.T) (*Service, *config.ConfigManager) {
	t.Helper()
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	return NewService(cm, logger.NewNopLogger()), cm
}

// TestTrackCertUnchanged 序列号比对与轮次升级
func TestTrackCertUnchanged(t *testing.T) {
	tests := []struct {
		name        string
		prevSerial  string
		newSerial   string
		startRounds int
		wantStale   bool
		wantRounds  int
	}{
		{"序列号变化则清零", "AAA", "BBB", 1, false, 0},
		{"首轮相同不升级", "AAA", "AAA", 0, false, 1},
		{"第二轮相同升级为失败", "AAA", "AAA", 1, true, config.CertUnchangedRounds},
		// 解析失败时序列号为空串，空串相等会让每次部署都误报
		{"旧序列号为空不判定", "", "", 0, false, 0},
		{"新序列号为空不判定", "AAA", "", 1, false, 0},
		{"旧空新有值不判定", "", "BBB", 0, false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := newUnchangedSvc(t)
			cert := &config.CertConfig{CertName: "c-1", OrderID: 1}
			cert.Metadata.CertSerial = tt.newSerial
			cert.Metadata.UnchangedCertRounds = tt.startRounds

			got := svc.trackCertUnchanged(cert, tt.prevSerial)
			if (got != "") != tt.wantStale {
				t.Errorf("trackCertUnchanged() = %q, wantStale %v", got, tt.wantStale)
			}
			if cert.Metadata.UnchangedCertRounds != tt.wantRounds {
				t.Errorf("UnchangedCertRounds = %d, want %d", cert.Metadata.UnchangedCertRounds, tt.wantRounds)
			}
			if tt.wantStale && got == "" {
				t.Error("升级为失败时必须返回可上报的原因文本")
			}
		})
	}
}

// TestUnchangedCertRoundsSurvivesDeploySuccess 回归：该计数**不得**被部署成功清零。
//
// 这是 sslbt 实现中的真实缺陷——它把 unchanged_cert_rounds 放进了
// DEPLOY_SUCCESS_RESET_KEYS，而检测又在清零之后执行，于是计数每轮先归零再递增到 1，
// 永远达不到升级阈值，整个机制从未生效。
//
// 正确的所有权：该计数只由 trackCertUnchanged 自己管理——序列号变化时清零、
// 相同时递增。部署成功恰恰是它要观测的事件，不能反过来清掉观测结果。
func TestUnchangedCertRoundsSurvivesDeploySuccess(t *testing.T) {
	svc, _ := newUnchangedSvc(t)
	cert := &config.CertConfig{CertName: "c-1", OrderID: 1}
	cert.Metadata.CertSerial = "SAME"

	// 第一轮：部署成功但证书未更替
	if got := svc.trackCertUnchanged(cert, "SAME"); got != "" {
		t.Fatalf("首轮不应升级，实际 %q", got)
	}
	if cert.Metadata.UnchangedCertRounds != 1 {
		t.Fatalf("首轮后轮次 = %d, want 1", cert.Metadata.UnchangedCertRounds)
	}

	// 第二轮：计数必须仍在，据此升级为失败
	got := svc.trackCertUnchanged(cert, "SAME")
	if got == "" {
		t.Fatal("第二轮必须升级为失败——若计数被部署成功清零，此处会永远返回空，机制失效")
	}
	if cert.Metadata.UnchangedCertRounds != config.CertUnchangedRounds {
		t.Errorf("轮次 = %d, want %d", cert.Metadata.UnchangedCertRounds, config.CertUnchangedRounds)
	}
}
