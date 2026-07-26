// Package certops 环境阻断闸门（部署前 Web 配置校验）测试
package certops

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

// blockCallbackRecorder 记录阻断上报的回调
type blockCallbackRecorder struct {
	mu   sync.Mutex
	reqs []fetcher.CallbackRequest
}

func (r *blockCallbackRecorder) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.Method == http.MethodPost {
			body, _ := io.ReadAll(req.Body)
			var cb fetcher.CallbackRequest
			_ = json.Unmarshal(body, &cb)
			r.mu.Lock()
			r.reqs = append(r.reqs, cb)
			r.mu.Unlock()
		}
		_, _ = w.Write([]byte(`{"code":1,"msg":"ok"}`))
	}
}

func (r *blockCallbackRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reqs)
}

func (r *blockCallbackRecorder) last() fetcher.CallbackRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.reqs) == 0 {
		return fetcher.CallbackRequest{}
	}
	return r.reqs[len(r.reqs)-1]
}

func newGateSvc(t *testing.T, apiURL string) (*Service, *config.ConfigManager, config.APIConfig) {
	t.Helper()
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	return NewService(cm, logger.NewNopLogger()), cm, config.APIConfig{URL: apiURL, Token: "t"}
}

// gateCert 构造带指定 TestCommand 的证书。
// 用 "false"（必失败）/ "true"（必成功）模拟配置损坏与健康——两者都在 executor 白名单外，
// 故实际走的是「命令执行失败」路径，与 nginx -t 失败同构。
func gateCert(name string, testCmds ...string) *config.CertConfig {
	cert := &config.CertConfig{CertName: name, OrderID: 1, Enabled: true}
	for i, cmd := range testCmds {
		cert.Bindings = append(cert.Bindings, config.SiteBinding{
			ServerName: name + string(rune('a'+i)),
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
			Reload:     config.ReloadConfig{TestCommand: cmd},
		})
	}
	return cert
}

// stubConfigTest 替换配置测试执行钩子，返回已执行的命令序列
func stubConfigTest(t *testing.T, fail bool) *[]string {
	t.Helper()
	var executed []string
	orig := runConfigTestFunc
	runConfigTestFunc = func(_ context.Context, cmd string) error {
		executed = append(executed, cmd)
		if fail {
			return fmt.Errorf("nginx: [emerg] unknown directive in /etc/nginx/conf.d/other.conf:12")
		}
		return nil
	}
	t.Cleanup(func() { runConfigTestFunc = orig })
	return &executed
}

// TestProbeWebConfig_DedupesTestCommand 同一条 TestCommand 只执行一次。
// nginx -t 天然全局——任何无关站点的坏配置都会让它失败，一张证书绑 N 个站点无需重复执行。
func TestProbeWebConfig_DedupesTestCommand(t *testing.T) {
	svc, _, _ := newGateSvc(t, "")
	executed := stubConfigTest(t, false)

	cert := gateCert("dedupe", "nginx -t", "nginx -t", "nginx -t")
	if got := svc.probeWebConfig(t.Context(), cert); got != "" {
		t.Fatalf("健康配置应返回空，实际 %q", got)
	}
	if len(*executed) != 1 {
		t.Errorf("同一条命令应只执行一次，实际执行 %d 次: %v", len(*executed), *executed)
	}
}

// TestProbeWebConfig_ProbesEachDistinctCommand 不同命令各执行一次（多服务器类型共存）
func TestProbeWebConfig_ProbesEachDistinctCommand(t *testing.T) {
	svc, _, _ := newGateSvc(t, "")
	executed := stubConfigTest(t, false)

	cert := gateCert("mixed", "nginx -t", "apachectl -t", "nginx -t")
	_ = svc.probeWebConfig(t.Context(), cert)
	if len(*executed) != 2 {
		t.Errorf("应对每种不同命令各探测一次，实际 %v", *executed)
	}
}

// TestProbeWebConfig_SkipsDisabledBindings 禁用绑定不参与探测
func TestProbeWebConfig_SkipsDisabledBindings(t *testing.T) {
	svc, _, _ := newGateSvc(t, "")
	executed := stubConfigTest(t, true)

	cert := gateCert("disabled", "nginx -t")
	cert.Bindings[0].Enabled = false
	if got := svc.probeWebConfig(t.Context(), cert); got != "" {
		t.Errorf("禁用绑定不应参与探测，实际返回 %q", got)
	}
	if len(*executed) != 0 {
		t.Errorf("禁用绑定不应执行任何命令，实际 %v", *executed)
	}
}

// TestCompactBlockReason 多行输出压平限长，且经过脱敏
func TestCompactBlockReason(t *testing.T) {
	multiline := "nginx: [emerg] unknown directive\n  in /etc/nginx/conf.d/a.conf:12\n\nnginx: configuration file test failed"
	got := compactBlockReason(multiline)
	if strings.ContainsAny(got, "\n\r") {
		t.Errorf("原因应压平为单行，实际 %q", got)
	}
	if strings.Contains(got, "  ") {
		t.Errorf("原因应折叠连续空白，实际 %q", got)
	}

	long := strings.Repeat("我", blockReasonMaxLen+50)
	if n := len([]rune(compactBlockReason(long))); n != blockReasonMaxLen {
		t.Errorf("超长原因应按 rune 截断到 %d，实际 %d", blockReasonMaxLen, n)
	}
}

// TestProbeWebConfig_SkipsEmptyCommand 无 TestCommand 的绑定跳过：
// 无从判断配置健康与否，不能凭空报阻断
func TestProbeWebConfig_SkipsEmptyCommand(t *testing.T) {
	svc, _, _ := newGateSvc(t, "")
	cert := gateCert("empty", "", "   ")
	if got := svc.probeWebConfig(t.Context(), cert); got != "" {
		t.Errorf("无测试命令应视为健康（无从判断），实际 %q", got)
	}
}

// TestCheckDeployEnvironment_EdgeTriggeredReporting 边沿触发：原因未变化不重复上报
func TestCheckDeployEnvironment_EdgeTriggeredReporting(t *testing.T) {
	rec := &blockCallbackRecorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	svc, cm, api := newGateSvc(t, server.URL)
	cert := gateCert("edge", "definitely-not-a-real-command-xyz")
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	// 连续三轮同一原因：只上报一次
	for round := 1; round <= 3; round++ {
		reason := svc.checkDeployEnvironment(t.Context(), cert, api)
		if reason == "" {
			t.Fatalf("第 %d 轮应判定为环境阻断", round)
		}
	}
	if got := rec.count(); got != 1 {
		t.Errorf("同一原因应只上报一次（边沿触发），实际 %d 次", got)
	}
	if cert.Metadata.BlockReportCount != 1 {
		t.Errorf("上报计数 = %d, want 1", cert.Metadata.BlockReportCount)
	}
	if got := rec.last().Status; got != "failure" {
		t.Errorf("阻断应按明确部署失败上报，实际 status=%q", got)
	}
	if rec.last().Message == "" {
		t.Error("阻断上报应携带原因摘要")
	}
	if cert.Metadata.LastDeployBlockAt.IsZero() {
		t.Error("应记录阻断时间")
	}
}

// TestCheckDeployEnvironment_ReportCapStopsAtLimit 次数封顶后转静默。
//
// 「原因未变化才不上报」不足以构成边界：原因串含 PID / 路径 / 异常文本等可变内容时
// 每轮都算"变化"。阻断又不递增部署计数，故必须由本上限兜住整条回调路径。
func TestCheckDeployEnvironment_ReportCapStopsAtLimit(t *testing.T) {
	rec := &blockCallbackRecorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	svc, cm, api := newGateSvc(t, server.URL)
	cert := gateCert("cap", "definitely-not-a-real-command-xyz")
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	// 每轮伪造不同的历史原因，模拟「原因串每轮都变」的最坏情况
	for round := 1; round <= config.MaxBlockReportCount+5; round++ {
		cert.Metadata.LastDeployBlockReason = "prev-round-" + string(rune('a'+round))
		svc.checkDeployEnvironment(t.Context(), cert, api)
	}

	if got := rec.count(); got != config.MaxBlockReportCount {
		t.Errorf("上报次数 = %d, want %d（封顶后转静默）", got, config.MaxBlockReportCount)
	}
	if cert.Metadata.BlockReportCount != config.MaxBlockReportCount {
		t.Errorf("计数 = %d, want %d", cert.Metadata.BlockReportCount, config.MaxBlockReportCount)
	}
}

// TestCheckDeployEnvironment_RecoveryResetsQuota 环境恢复清零标记与额度：
// 恢复过就是新一轮故障，应当重新获得完整的上报额度
func TestCheckDeployEnvironment_RecoveryResetsQuota(t *testing.T) {
	rec := &blockCallbackRecorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	svc, cm, api := newGateSvc(t, server.URL)
	cert := gateCert("recover", "definitely-not-a-real-command-xyz")
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	// 先坏到封顶
	for round := 1; round <= config.MaxBlockReportCount; round++ {
		cert.Metadata.LastDeployBlockReason = "prev-" + string(rune('a'+round))
		svc.checkDeployEnvironment(t.Context(), cert, api)
	}
	if cert.Metadata.BlockReportCount != config.MaxBlockReportCount {
		t.Fatalf("前置条件失败：计数应达上限，实际 %d", cert.Metadata.BlockReportCount)
	}
	reportedWhileBroken := rec.count()

	// 环境恢复：清空 TestCommand 模拟配置修好（探测返回健康）
	for i := range cert.Bindings {
		cert.Bindings[i].Reload.TestCommand = ""
	}
	if reason := svc.checkDeployEnvironment(t.Context(), cert, api); reason != "" {
		t.Fatalf("配置恢复后不应阻断，实际 %q", reason)
	}
	if cert.Metadata.LastDeployBlockReason != "" || !cert.Metadata.LastDeployBlockAt.IsZero() {
		t.Error("恢复后应清除阻断标记，否则面板会一直显示已消失的旧原因")
	}
	if cert.Metadata.BlockReportCount != 0 {
		t.Errorf("恢复后应清零上报额度，实际 %d", cert.Metadata.BlockReportCount)
	}

	// 再次损坏：额度已重置，应能重新上报
	cert.Bindings[0].Reload.TestCommand = "definitely-not-a-real-command-xyz"
	if reason := svc.checkDeployEnvironment(t.Context(), cert, api); reason == "" {
		t.Fatal("再次损坏应重新阻断")
	}
	if rec.count() != reportedWhileBroken+1 {
		t.Errorf("恢复后再坏应重新获得上报额度，上报次数 %d → %d", reportedWhileBroken, rec.count())
	}
}

// TestRunDeployAttempt_BlockDoesNotConsumeDeployQuota 阻断不占用部署尝试配额。
//
// 若递增 DeployAttemptCount，一个无关站点的坏配置会在 10 轮后把所有证书静默推入
// CAPPED，且配置修好后还需人工解除；不计数则修好即自动恢复。
func TestRunDeployAttempt_BlockDoesNotConsumeDeployQuota(t *testing.T) {
	rec := &blockCallbackRecorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	svc, cm, _ := newGateSvc(t, server.URL)
	cert := gateCert("quota", "definitely-not-a-real-command-xyz")
	cert.API = config.APIConfig{URL: server.URL, Token: "t"}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	result := &RenewResult{CertName: cert.CertName}
	svc.runDeployAttempt(t.Context(), cert, &fetcher.CertData{}, "", result)

	if cert.Metadata.DeployAttemptCount != 0 {
		t.Errorf("环境阻断不应递增部署计数，实际 %d", cert.Metadata.DeployAttemptCount)
	}
	if !cert.Metadata.DeployStartedAt.IsZero() {
		t.Error("环境阻断不应留下部署意图标记")
	}
	if result.Status != "failure" {
		t.Errorf("本轮应按失败收敛（与已上报的 failure 口径一致），实际 %q", result.Status)
	}
	if result.Error == nil {
		t.Error("失败结果应携带阻断原因")
	}
}
