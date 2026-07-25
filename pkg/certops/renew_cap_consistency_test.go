// Package certops 触顶判定一致性与部署尝试标记清理测试
package certops

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
	certs "github.com/zhuxbo/sslctl/testdata/certs"
)

// TestCappedPhaseFor_MatchesWillMakeAPICall 锁定编排层触顶判定与延迟预估共用同一谓词。
// 两处各写一份时，在途（processing）与秒签待部署（active）的证书会被预估算作"不发请求"，
// 而编排层实际仍会查询订单；更要紧的是未来改一处漏一处会让已签发证书被误判停机。
func TestCappedPhaseFor_MatchesWillMakeAPICall(t *testing.T) {
	schedule := &config.ScheduleConfig{RenewBeforeDays: 14, RenewMode: config.RenewModeLocal}
	future := time.Now().Add(72 * time.Hour) // 已进入续签窗口且远超安全余量

	tests := []struct {
		name      string
		meta      config.CertMetadata
		wantPhase string
	}{
		{
			name:      "签发计数触顶且无在途状态：签发阶段触顶",
			meta:      config.CertMetadata{CertExpiresAt: future, IssueRetryCount: MaxIssueRetryCount},
			wantPhase: config.CappedPhaseIssue,
		},
		{
			name: "签发计数触顶但已在途 processing：不触顶，继续查询推进",
			meta: config.CertMetadata{
				CertExpiresAt:   future,
				IssueRetryCount: MaxIssueRetryCount,
				LastIssueState:  config.IssueStateProcessing,
			},
			wantPhase: "",
		},
		{
			name: "签发计数触顶但已秒签待部署 active：不触顶，由部署计数约束",
			meta: config.CertMetadata{
				CertExpiresAt:   future,
				IssueRetryCount: MaxIssueRetryCount,
				LastIssueState:  config.IssueStateActive,
			},
			wantPhase: "",
		},
		{
			name: "在途且部署计数触顶：部署阶段触顶",
			meta: config.CertMetadata{
				CertExpiresAt:      future,
				IssueRetryCount:    MaxIssueRetryCount,
				DeployAttemptCount: MaxDeployAttemptCount,
				LastIssueState:     config.IssueStateActive,
			},
			wantPhase: config.CappedPhaseDeploy,
		},
		{
			name:      "均未触顶",
			meta:      config.CertMetadata{CertExpiresAt: future, IssueRetryCount: 3, DeployAttemptCount: 3},
			wantPhase: "",
		},
	}

	svc := &Service{log: logger.NewNopLogger()}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &config.CertConfig{
				CertName: "cap.example.com-1",
				Enabled:  true,
				Domains:  []string{"cap.example.com"},
				Metadata: tt.meta,
			}

			if got := cappedPhaseFor(cert, schedule); got != tt.wantPhase {
				t.Fatalf("cappedPhaseFor = %q, want %q", got, tt.wantPhase)
			}

			// 预估必须与触顶判定一致：触顶即不发请求，未触顶且需续签则会发请求
			gotCall := svc.willMakeAPICall(cert, schedule)
			wantCall := tt.wantPhase == "" && cert.NeedsRenewal(schedule)
			if gotCall != wantCall {
				t.Fatalf("willMakeAPICall = %v, want %v（应与 cappedPhaseFor 一致）", gotCall, wantCall)
			}
		})
	}
}

// TestRetryFailedBindings_ClearsDeployStartedAt 回归：失败绑定重试同样是一次产生了明确结果的
// 部署尝试，必须清除崩溃安全标记。残留标记会让之后一次真正的 runDeployAttempt 被当成
// "重放同一意图"而不递增 DeployAttemptCount，削弱部署触顶保护。
func TestRetryFailedBindings_ClearsDeployStartedAt(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	pair, err := certs.GenerateValidCert("retrymark.example.com", []string{"retrymark.example.com"})
	if err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}
	intermediate, err := certs.GenerateValidCert("Intermediate CA", nil)
	if err != nil {
		t.Fatalf("生成中间证书失败: %v", err)
	}

	siteDir := filepath.Join(tmpDir, "site")
	if err := os.MkdirAll(siteDir, 0700); err != nil {
		t.Fatalf("创建站点目录失败: %v", err)
	}
	certPath := filepath.Join(siteDir, "cert.pem")
	keyPath := filepath.Join(siteDir, "key.pem")
	if err := os.WriteFile(certPath, []byte(pair.CertPEM), 0644); err != nil {
		t.Fatalf("写入证书失败: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(pair.KeyPEM), 0600); err != nil {
		t.Fatalf("写入私钥失败: %v", err)
	}

	server := newQueryOrderServer(t, 2400, "active", pair.CertPEM, intermediate.CertPEM)
	defer server.Close()

	cert := &config.CertConfig{
		CertName: "retrymark.example.com-2400",
		OrderID:  2400,
		Enabled:  true,
		Domains:  []string{"retrymark.example.com"},
		API:      config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			FailedBindings:   []string{"retrymark-site"},
			FailedBindingsAt: time.Now(),
			// 上一轮 runDeployAttempt 落盘了部署意图但崩溃未落盘结果
			DeployStartedAt: time.Now().Add(-time.Minute),
		},
		Bindings: []config.SiteBinding{{
			ServerName: "retrymark-site",
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
			Paths:      config.BindingPaths{Certificate: certPath, PrivateKey: keyPath},
		}},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	result := svc.retryFailedBindings(t.Context(), cert, cert.API)
	if result.Status != "success" {
		t.Fatalf("重试应成功: %+v (err=%v)", result, result.Error)
	}
	if !cert.Metadata.DeployStartedAt.IsZero() {
		t.Error("重试产生明确结果后应清除 DeployStartedAt 标记")
	}

	updated, err := cm.GetCert(cert.CertName)
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	if !updated.Metadata.DeployStartedAt.IsZero() {
		t.Error("清除后的 DeployStartedAt 应已落盘")
	}
}
