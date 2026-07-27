// Package certops 部署计数分离、触顶静默、崩溃重放与恢复归一测试
package certops

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
	certs "github.com/zhuxbo/sslctl/testdata/certs"
)

// newActiveWithKeyRecorder 返回记录回调、GET 查询固定返回 active（含 private_key）的服务
func newActiveWithKeyRecorder(t *testing.T, orderID int, certPEM, intermediatePEM, keyPEM string) *callbackRecorder {
	t.Helper()
	return &callbackRecorder{queryResp: fmt.Sprintf(
		`{"code":1,"msg":"ok","data":{"order_id":%d,"status":"active","certificate":%q,"ca_certificate":%q,"private_key":%q}}`,
		orderID, certPEM, intermediatePEM, keyPEM)}
}

// makeDeployFailBinding 构造一个部署必失败的绑定：证书路径为目录，通用部署器写入必失败
func makeDeployFailBinding(t *testing.T, tmpDir, serverName string) config.SiteBinding {
	t.Helper()
	certPath := filepath.Join(tmpDir, serverName, "cert.pem")
	keyPath := filepath.Join(tmpDir, serverName, "key.pem")
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	if err := os.Mkdir(certPath, 0700); err != nil {
		t.Fatalf("制造部署障碍失败: %v", err)
	}
	return config.SiteBinding{
		ServerName: serverName,
		ServerType: config.ServerTypeNginx,
		Enabled:    true,
		Paths:      config.BindingPaths{Certificate: certPath, PrivateKey: keyPath},
	}
}

// TestCheckAndRenewAll_DeployCapStopsAfterTenAttempts 验证部署连续失败触顶（必过场景 2/3）：
// 每轮一次部署尝试，第 10 次失败标注"已达重试上限"，之后进入 CAPPED(deploy) 静默、不再上报。
// 部署计数（DeployAttemptCount）与签发计数分离，绝无第 11 次尝试。
func TestCheckAndRenewAll_DeployCapStopsAfterTenAttempts(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	pair, err := certs.GenerateValidCert("cap.example.com", []string{"cap.example.com"})
	if err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}
	intermediate, err := certs.GenerateValidCert("Test CA", nil)
	if err != nil {
		t.Fatalf("生成中间证书失败: %v", err)
	}

	rec := newActiveWithKeyRecorder(t, 900, pair.CertPEM, intermediate.CertPEM, pair.KeyPEM)
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	cert := &config.CertConfig{
		CertName:  "cap.example.com-900",
		OrderID:   900,
		Enabled:   true,
		RenewMode: config.RenewModePull,
		Domains:   []string{"cap.example.com"},
		API:       config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata:  config.CertMetadata{CertExpiresAt: time.Now().Add(3 * 24 * time.Hour)}, // 临期
		Bindings:  []config.SiteBinding{makeDeployFailBinding(t, tmpDir, "cap-site")},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	// 连续 12 轮（每轮相当于一天的续签检查）
	for round := 1; round <= 12; round++ {
		if _, err := svc.CheckAndRenewAll(t.Context()); err != nil {
			t.Fatalf("round %d CheckAndRenewAll 失败: %v", round, err)
		}
	}

	updated, err := cm.GetCert("cap.example.com-900")
	if err != nil {
		t.Fatalf("获取证书失败: %v", err)
	}
	if updated.Metadata.DeployAttemptCount != MaxDeployAttemptCount {
		t.Errorf("部署计数应触顶于 %d（绝无第 11 次），实际 %d", MaxDeployAttemptCount, updated.Metadata.DeployAttemptCount)
	}
	if updated.Metadata.IssueRetryCount != 0 {
		t.Errorf("pull 模式不应污染签发计数（应为 0），实际 %d", updated.Metadata.IssueRetryCount)
	}
	if updated.Metadata.LastIssueState != config.IssueStateCapped {
		t.Errorf("应进入 CAPPED 状态，实际 %q", updated.Metadata.LastIssueState)
	}
	if updated.Metadata.CappedPhase != config.CappedPhaseDeploy {
		t.Errorf("触顶阶段应为 deploy，实际 %q", updated.Metadata.CappedPhase)
	}
	if !updated.Metadata.DeployStartedAt.IsZero() {
		t.Error("触顶后应清除部署已开始标记")
	}

	// 回调：每次部署失败各一次，触顶后静默 → 恰好 10 次
	cbs := rec.recorded()
	if len(cbs) != MaxDeployAttemptCount {
		t.Fatalf("应恰好上报 %d 次部署失败回调（触顶后静默），实际 %d", MaxDeployAttemptCount, len(cbs))
	}
	for i, cb := range cbs {
		if cb.Status != "failure" {
			t.Errorf("回调 %d 应为 failure: %+v", i, cb)
		}
	}
	// 最后一次（第 10 次）标注"已达重试上限"，前 9 次不标注
	if !strings.Contains(cbs[len(cbs)-1].Message, "已达重试上限") {
		t.Errorf("最后一次失败回调 message 应标注已达重试上限: %q", cbs[len(cbs)-1].Message)
	}
	for i := 0; i < len(cbs)-1; i++ {
		if strings.Contains(cbs[i].Message, "已达重试上限") {
			t.Errorf("第 %d 次失败回调不应标注已达重试上限: %q", i+1, cbs[i].Message)
		}
	}
}

// TestCheckAndRenewAll_DeployCrashReplayDoesNotIncrement 验证崩溃复验重放不盲增计数（必过场景 2/14）：
// 预置 DeployStartedAt（部署意图已落盘、结果未落盘的崩溃现场），重启后复验重放同一尝试、不再递增；
// 结果落盘后清除标记，下一轮才作为全新尝试递增。
func TestCheckAndRenewAll_DeployCrashReplayDoesNotIncrement(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	pair, err := certs.GenerateValidCert("crash.example.com", []string{"crash.example.com"})
	if err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}
	intermediate, err := certs.GenerateValidCert("Test CA", nil)
	if err != nil {
		t.Fatalf("生成中间证书失败: %v", err)
	}
	rec := newActiveWithKeyRecorder(t, 910, pair.CertPEM, intermediate.CertPEM, pair.KeyPEM)
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	cert := &config.CertConfig{
		CertName:  "crash.example.com-910",
		OrderID:   910,
		Enabled:   true,
		RenewMode: config.RenewModePull,
		Domains:   []string{"crash.example.com"},
		API:       config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			CertExpiresAt:      time.Now().Add(3 * 24 * time.Hour),
			DeployAttemptCount: 4,                            // 已进行到第 4 次尝试
			DeployStartedAt:    time.Now().Add(-time.Minute), // 第 4 次意图已落盘，结果未落盘（崩溃）
		},
		Bindings: []config.SiteBinding{makeDeployFailBinding(t, tmpDir, "crash-site")},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	// 第一轮：复验重放同一尝试，不递增（仍为 4）
	if _, err := svc.CheckAndRenewAll(t.Context()); err != nil {
		t.Fatalf("CheckAndRenewAll 失败: %v", err)
	}
	updated, err := cm.GetCert("crash.example.com-910")
	if err != nil {
		t.Fatalf("获取证书失败: %v", err)
	}
	if updated.Metadata.DeployAttemptCount != 4 {
		t.Errorf("崩溃复验重放不应递增计数（应仍为 4），实际 %d", updated.Metadata.DeployAttemptCount)
	}
	if !updated.Metadata.DeployStartedAt.IsZero() {
		t.Error("结果落盘后应清除 DeployStartedAt 标记")
	}
	// 复验重放仍是一次明确部署失败，上报一次回调
	if cbs := rec.recorded(); len(cbs) != 1 {
		t.Fatalf("复验重放应上报 1 次部署失败回调，实际 %d", len(cbs))
	}

	// 第二轮：标记已清除，作为全新尝试递增至 5
	if _, err := svc.CheckAndRenewAll(t.Context()); err != nil {
		t.Fatalf("CheckAndRenewAll 失败: %v", err)
	}
	updated2, err := cm.GetCert("crash.example.com-910")
	if err != nil {
		t.Fatalf("获取证书失败: %v", err)
	}
	if updated2.Metadata.DeployAttemptCount != 5 {
		t.Errorf("复验后下一轮应为全新尝试递增至 5，实际 %d", updated2.Metadata.DeployAttemptCount)
	}
}

// TestPrepareLocalRenew_ResponseLossKeepsPending 验证响应丢失恢复归一（必过场景 6）：
// 提交 CSR 时响应解析失败（不确定结果）→ 保留 pending key、归一为 processing，
// 不清理 pending、不重新生成 CSR；签发计数在提交前已递增一次。
func TestPrepareLocalRenew_ResponseLossKeepsPending(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	// POST（提交 CSR）返回 200 + 无法解析的响应体，模拟响应丢失 / 解析失败（不确定结果）
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte("network hiccup, not json"))
			return
		}
		// 首次 GET 是提交门禁，服务端必须明确 active 才允许 POST。
		// POST 响应不确定后，下轮 GET 仍缺少 CSR，客户端应保留本地意图并停止。
		_, _ = w.Write([]byte(`{"code":1,"msg":"ok","data":{"order_id":950,"status":"active"}}`))
	}))
	defer server.Close()

	keyPath := filepath.Join(tmpDir, "site", "key.pem")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	cert := &config.CertConfig{
		CertName:  "loss.example.com-950",
		OrderID:   950,
		Enabled:   true,
		RenewMode: config.RenewModeLocal,
		Domains:   []string{"loss.example.com"},
		API:       config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata:  config.CertMetadata{CertExpiresAt: time.Now().Add(5 * 24 * time.Hour)},
		Bindings: []config.SiteBinding{{
			ServerName: "loss-site",
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
			Paths:      config.BindingPaths{Certificate: filepath.Join(tmpDir, "site", "cert.pem"), PrivateKey: keyPath},
		}},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	cd, _, err := svc.prepareLocalRenew(t.Context(), cert, cert.API)
	// 不确定结果归一为 pending 等待：返回 nil 证书、nil 错误
	if err != nil {
		t.Fatalf("响应丢失应归一为 pending 等待，不应返回错误: %v", err)
	}
	if cd != nil {
		t.Fatal("响应丢失应返回 nil 证书数据（等待下轮查询）")
	}

	// pending key 保留（不因不确定结果清理，避免销毁与已签发证书配对的私钥）
	if _, e := readPendingKey(cm.GetWorkDir(), "loss.example.com-950"); e != nil {
		t.Errorf("响应丢失后 pending key 应保留: %v", e)
	}
	// 状态归一为 processing（下轮只查询、不重复 POST、不重生 CSR）
	if cert.Metadata.LastIssueState != config.IssueStateProcessing {
		t.Errorf("响应丢失应归一为 processing，实际 %q", cert.Metadata.LastIssueState)
	}
	// 签发计数在提交前已递增一次（一个逻辑提交意图）
	if cert.Metadata.IssueRetryCount != 1 {
		t.Errorf("提交意图应递增签发计数一次，实际 %d", cert.Metadata.IssueRetryCount)
	}

	// 下轮：processing 状态只查询、不重复提交 CSR，计数不再递增
	before := cert.Metadata.IssueRetryCount
	cd2, _, err2 := svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if err2 != nil {
		t.Fatalf("下轮查询不应报错: %v", err2)
	}
	if cd2 != nil {
		t.Fatal("服务端仍 processing，下轮应继续等待")
	}
	if cert.Metadata.IssueRetryCount != before {
		t.Errorf("processing 查询不应递增计数（应仍为 %d），实际 %d", before, cert.Metadata.IssueRetryCount)
	}
}

// TestCheckAndRenewAll_IssueCappedButActiveStillDeploys 验证边界：local 模式签发计数已达 10，
// 但证书已秒签为 active 待部署时，签发触顶不应拦截其部署（否则有效证书白白过期）。
// 签发触顶只拦截"即将提交新 CSR"的情形。
func TestCheckAndRenewAll_IssueCappedButActiveStillDeploys(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	pair, err := certs.GenerateValidCert("stuck.example.com", []string{"stuck.example.com"})
	if err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}
	intermediate, err := certs.GenerateValidCert("Test CA", nil)
	if err != nil {
		t.Fatalf("生成中间证书失败: %v", err)
	}
	server := newQueryOrderServer(t, 970, "active", pair.CertPEM, intermediate.CertPEM)
	defer server.Close()

	// pending key 与查询返回的 active 证书配对
	if err := savePendingKey(cm.GetWorkDir(), "stuck.example.com-970", pair.KeyPEM); err != nil {
		t.Fatalf("保存 pending 私钥失败: %v", err)
	}

	certPath := filepath.Join(tmpDir, "stuck-site", "cert.pem")
	keyPath := filepath.Join(tmpDir, "stuck-site", "key.pem")
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}

	cert := &config.CertConfig{
		CertName:  "stuck.example.com-970",
		OrderID:   970,
		Enabled:   true,
		RenewMode: config.RenewModeLocal,
		Domains:   []string{"stuck.example.com"},
		API:       config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			CertExpiresAt:   time.Now().Add(3 * 24 * time.Hour),
			IssueRetryCount: MaxIssueRetryCount,      // 签发计数已触顶
			LastIssueState:  config.IssueStateActive, // 但已秒签、等待部署
		},
		Bindings: []config.SiteBinding{{
			ServerName: "stuck-site",
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
			Paths:      config.BindingPaths{Certificate: certPath, PrivateKey: keyPath},
		}},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	results, err := svc.CheckAndRenewAll(t.Context())
	if err != nil {
		t.Fatalf("CheckAndRenewAll 失败: %v", err)
	}
	if len(results) != 1 || results[0].Status != "success" {
		t.Fatalf("已签发证书应正常部署成功，不被签发触顶拦截: %+v", results)
	}

	updated, err := cm.GetCert("stuck.example.com-970")
	if err != nil {
		t.Fatalf("获取证书失败: %v", err)
	}
	if updated.Metadata.LastIssueState == config.IssueStateCapped {
		t.Error("已签发证书不应被签发触顶误判为 CAPPED")
	}
	// 部署成功清零全部计数与状态
	if updated.Metadata.LastIssueState != "" || updated.Metadata.IssueRetryCount != 0 || updated.Metadata.DeployAttemptCount != 0 {
		t.Errorf("部署成功应清零状态与计数: state=%q issue=%d deploy=%d",
			updated.Metadata.LastIssueState, updated.Metadata.IssueRetryCount, updated.Metadata.DeployAttemptCount)
	}
}

// TestCheckAndRenewAll_IllegalIPPolicyBlocked 验证旧非法 IP 配置进入 policy_blocked（必过场景 15）：
// IP + pull 配置被阻断——不产生续签结果、不上报回调、不递增计数，落盘 policy_blocked_needs_setup。
func TestCheckAndRenewAll_IllegalIPPolicyBlocked(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	rec := &callbackRecorder{queryResp: `{"code":0,"msg":"should not be queried"}`}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	cert := &config.CertConfig{
		CertName:  "192.0.2.10-960",
		OrderID:   960,
		Enabled:   true,
		RenewMode: config.RenewModePull, // IP + pull = 非法
		Domains:   []string{"192.0.2.10"},
		API:       config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata:  config.CertMetadata{CertExpiresAt: time.Now().Add(3 * 24 * time.Hour)},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	results, err := svc.CheckAndRenewAll(t.Context())
	if err != nil {
		t.Fatalf("CheckAndRenewAll 失败: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("非法 IP 配置应被阻断，不产生续签结果: %+v", results)
	}
	if cbs := rec.recorded(); len(cbs) != 0 {
		t.Fatalf("非法 IP 配置不应上报回调，实际 %d 次", len(cbs))
	}

	updated, err := cm.GetCert("192.0.2.10-960")
	if err != nil {
		t.Fatalf("获取证书失败: %v", err)
	}
	if updated.Metadata.LastIssueState != config.IssueStatePolicyBlocked {
		t.Errorf("应进入 policy_blocked_needs_setup，实际 %q", updated.Metadata.LastIssueState)
	}
	if updated.Metadata.IssueRetryCount != 0 || updated.Metadata.DeployAttemptCount != 0 {
		t.Errorf("policy 阻断不应递增任何计数: issue=%d deploy=%d",
			updated.Metadata.IssueRetryCount, updated.Metadata.DeployAttemptCount)
	}
}
