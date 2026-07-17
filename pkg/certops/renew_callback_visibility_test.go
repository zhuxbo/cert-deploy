// Package certops 续签失败回调补全与重试触顶可见性测试
package certops

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

// callbackRecorder 记录收到的回调请求（解析结构 + 原始 JSON），查询接口返回指定响应
type callbackRecorder struct {
	mu        sync.Mutex
	callbacks []fetcher.CallbackRequest
	rawBodies []string
	queryResp string // GET 查询响应（JSON）
}

func (r *callbackRecorder) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.Method == http.MethodPost && strings.Contains(req.URL.Path, "/callback") {
			body, _ := io.ReadAll(req.Body)
			var cb fetcher.CallbackRequest
			_ = json.Unmarshal(body, &cb)
			r.mu.Lock()
			r.callbacks = append(r.callbacks, cb)
			r.rawBodies = append(r.rawBodies, string(body))
			r.mu.Unlock()
			_, _ = w.Write([]byte(`{"code":1,"msg":"ok"}`))
			return
		}
		_, _ = w.Write([]byte(r.queryResp))
	}
}

func (r *callbackRecorder) recorded() []fetcher.CallbackRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]fetcher.CallbackRequest, len(r.callbacks))
	copy(out, r.callbacks)
	return out
}

func (r *callbackRecorder) raw() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.rawBodies))
	copy(out, r.rawBodies)
	return out
}

// TestCheckAndRenewAll_PrepareFailureSendsCallback 验证 prepare 阶段失败也上报 failure 回调
// （原实现 prepare 失败 continue 跳过了回调块，服务端无法感知失败）。
func TestCheckAndRenewAll_PrepareFailureSendsCallback(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	// 查询接口返回业务错误（不触发传输层重试），prepare 必失败
	rec := &callbackRecorder{queryResp: `{"code":0,"msg":"server boom"}`}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	cert := &config.CertConfig{
		CertName: "prep.example.com-400",
		OrderID:  400,
		Enabled:  true,
		Domains:  []string{"prep.example.com"},
		API:      config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			CertExpiresAt: time.Now().Add(3 * 24 * time.Hour), // 临期，需要续签
		},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	results, err := svc.CheckAndRenewAll(t.Context())
	if err != nil {
		t.Fatalf("CheckAndRenewAll 失败: %v", err)
	}
	if len(results) != 1 || results[0].Status != "failure" {
		t.Fatalf("应产生 1 个 failure 结果: %+v", results)
	}

	cbs := rec.recorded()
	if len(cbs) != 1 {
		t.Fatalf("prepare 失败应发送 1 次回调，实际 %d", len(cbs))
	}
	if cbs[0].Status != "failure" || cbs[0].OrderID != 400 {
		t.Errorf("回调内容不正确: %+v", cbs[0])
	}
	// 契约（spec 2.8）：failure 回调携带 message 原因摘要，且 ≤256 rune
	if cbs[0].Message == "" {
		t.Error("failure 回调应携带 message 原因摘要")
	}
	if n := len([]rune(cbs[0].Message)); n > callbackMessageMaxLen {
		t.Errorf("message 超过 %d rune 上限: %d", callbackMessageMaxLen, n)
	}
	if raw := rec.raw(); !strings.Contains(raw[0], `"message"`) {
		t.Errorf("failure 回调请求体应包含 message 字段: %s", raw[0])
	}
}

// TestCheckAndRenewAll_RetryFailedBindingsSendsCallback 验证失败绑定重试路径也发送回调。
func TestCheckAndRenewAll_RetryFailedBindingsSendsCallback(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	rec := &callbackRecorder{queryResp: `{"code":0,"msg":"query boom"}`}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	cert := &config.CertConfig{
		CertName: "retry.example.com-500",
		OrderID:  500,
		Enabled:  true,
		Domains:  []string{"retry.example.com"},
		API:      config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			CertExpiresAt:    time.Now().Add(60 * 24 * time.Hour), // 有效期充足，不续签
			FailedBindings:   []string{"retry-site"},
			FailedBindingsAt: time.Now(),
		},
		Bindings: []config.SiteBinding{{
			ServerName: "retry-site",
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
	if len(results) != 1 || results[0].Status != "failure" {
		t.Fatalf("应产生 1 个 failure 结果: %+v", results)
	}

	cbs := rec.recorded()
	if len(cbs) != 1 {
		t.Fatalf("重试失败绑定应发送 1 次回调，实际 %d", len(cbs))
	}
	if cbs[0].Status != "failure" || cbs[0].OrderID != 500 {
		t.Errorf("回调内容不正确: %+v", cbs[0])
	}
}

// TestCheckAndRenewAll_RetryCapVisible 验证重试触顶证书不再静默：
// Error 结果计入统计 + 上报 failure 带"重试超限"原因（原实现仅一条 Warn 且不产生结果）。
func TestCheckAndRenewAll_RetryCapVisible(t *testing.T) {
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
		CertName:  "capped.example.com-600",
		OrderID:   600,
		Enabled:   true,
		RenewMode: config.RenewModeLocal,
		Domains:   []string{"capped.example.com"},
		API:       config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			CertExpiresAt:   time.Now().Add(3 * 24 * time.Hour), // 临期
			IssueRetryCount: MaxIssueRetryCount,                 // 已触顶
		},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	results, err := svc.CheckAndRenewAll(t.Context())
	if err != nil {
		t.Fatalf("CheckAndRenewAll 失败: %v", err)
	}
	// 触顶证书应计入本轮统计（failure），而非静默消失
	if len(results) != 1 || results[0].Status != "failure" {
		t.Fatalf("触顶证书应产生 failure 结果: %+v", results)
	}
	if results[0].Error == nil || !strings.Contains(results[0].Error.Error(), "上限") {
		t.Errorf("结果错误应说明重试超限: %v", results[0].Error)
	}

	cbs := rec.recorded()
	if len(cbs) != 1 {
		t.Fatalf("触顶证书应上报 1 次 failure 回调，实际 %d", len(cbs))
	}
	if cbs[0].Status != "failure" || cbs[0].OrderID != 600 {
		t.Errorf("回调应为 failure: %+v", cbs[0])
	}
	// 契约（spec 2.8）：failure 回调 message 携带重试超限原因
	if !strings.Contains(cbs[0].Message, "上限") {
		t.Errorf("回调 message 应含重试超限原因: %q", cbs[0].Message)
	}
}

// TestSendDeployCallback_MessageContract 验证 message 契约：
// success 不携带 message（omitempty），failure 携带且已脱敏（不泄漏 Bearer token）。
func TestSendDeployCallback_MessageContract(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	rec := &callbackRecorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	cert := &config.CertConfig{
		CertName: "cb.example.com-700",
		OrderID:  700,
		Enabled:  true,
		API:      config.APIConfig{URL: server.URL, Token: "test-token"},
	}

	// success：不携带 message
	svc.sendDeployCallback(t.Context(), cert, &DeployResult{CertName: cert.CertName, Success: true})
	// failure：错误串内含 Bearer token，message 必须脱敏后携带
	svc.sendDeployCallback(t.Context(), cert, &DeployResult{
		CertName: cert.CertName,
		Success:  false,
		Error:    fmt.Errorf("部署失败，Authorization: Bearer secret-token-abc123 不应泄漏"),
	})

	cbs := rec.recorded()
	raw := rec.raw()
	if len(cbs) != 2 {
		t.Fatalf("应记录 2 次回调，实际 %d", len(cbs))
	}

	// success 回调：Status=success 且不含 message
	if cbs[0].Status != "success" || cbs[0].Message != "" {
		t.Errorf("success 回调不应携带 message: %+v", cbs[0])
	}
	if strings.Contains(raw[0], "message") {
		t.Errorf("success 回调请求体不应出现 message 字段: %s", raw[0])
	}

	// failure 回调：携带 message，且已脱敏（不含明文 token、含 REDACTED 标记）
	if cbs[1].Status != "failure" || cbs[1].Message == "" {
		t.Errorf("failure 回调应携带 message: %+v", cbs[1])
	}
	if strings.Contains(cbs[1].Message, "secret-token-abc123") {
		t.Errorf("message 泄漏了 Bearer token: %q", cbs[1].Message)
	}
	if !strings.Contains(cbs[1].Message, "REDACTED") {
		t.Errorf("message 应包含脱敏标记: %q", cbs[1].Message)
	}
}

// TestCallbackMessage_TruncatesToRuneLimit 验证 message 按 rune 截断且不劈开多字节字符。
func TestCallbackMessage_TruncatesToRuneLimit(t *testing.T) {
	// nil error 返回空
	if callbackMessage(nil) != "" {
		t.Error("nil error 应返回空 message")
	}

	// 300 个多字节字符，超过 256 rune 上限
	long := strings.Repeat("错", 300)
	msg := callbackMessage(fmt.Errorf("%s", long))
	if n := len([]rune(msg)); n != callbackMessageMaxLen {
		t.Errorf("超长 message 应截断到 %d rune，实际 %d", callbackMessageMaxLen, n)
	}
	if !utf8.ValidString(msg) {
		t.Error("截断后不应产生非法 UTF-8（劈开多字节字符）")
	}
}

// TestCallbackMessage_SanitizeBeforeTruncate 密钥材料在 256 截断点之内、END 标记在点外：
// 若实现改成"先截断后脱敏"，截断产物含 BEGIN+材料但无 END，私钥正则不命中即泄漏，本用例转红。
func TestCallbackMessage_SanitizeBeforeTruncate(t *testing.T) {
	raw := strings.Repeat("x", 150) + "-----BEGIN RSA PRIVATE KEY-----\nLEAKMATERIAL" + strings.Repeat("A", 80) + "\n-----END RSA PRIVATE KEY-----"
	msg := callbackMessage(fmt.Errorf("%s", raw))
	if strings.Contains(msg, "LEAKMATERIAL") {
		t.Errorf("跨界私钥不应泄漏任何片段: %q", msg)
	}
	if !strings.Contains(msg, "***REDACTED PRIVATE KEY***") {
		t.Errorf("私钥块应先于截断被整体脱敏: %q", msg)
	}
}
