// Package setup setup 部署结果上报的测试（项 I-b）
package setup

import (
	"context"
	"encoding/json"
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

// setupCallbackRecorder 记录 setup 发出的部署结果回调
type setupCallbackRecorder struct {
	mu   sync.Mutex
	reqs []fetcher.CallbackRequest
}

func (r *setupCallbackRecorder) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.Method == http.MethodPost && strings.Contains(req.URL.Path, "/callback") {
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

func (r *setupCallbackRecorder) recorded() []fetcher.CallbackRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]fetcher.CallbackRequest, len(r.reqs))
	copy(out, r.reqs)
	return out
}

func newCallbackTestParams(t *testing.T, apiURL string) *setupParams {
	t.Helper()
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	return &setupParams{
		apiURL:     apiURL,
		token:      "token",
		ctx:        t.Context(),
		cfgManager: cm,
		log:        logger.NewNopLogger(),
	}
}

// TestSendSetupDeployCallback 单证书 setup 按部署结果上报一次。
// 服务端此前收不到任何 setup 结果，只能等到下一个续签窗口才知道站点状态。
func TestSendSetupDeployCallback(t *testing.T) {
	tests := []struct {
		name       string
		success    int
		fail       int
		wantStatus string
		wantMsg    bool
	}{
		{"全部成功上报 success", 2, 0, "success", false},
		{"部分失败上报 failure", 1, 1, "failure", true},
		{"全部失败上报 failure", 0, 3, "failure", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &setupCallbackRecorder{}
			server := httptest.NewServer(rec.handler())
			defer server.Close()

			p := newCallbackTestParams(t, server.URL)
			sendSetupDeployCallback(p, fetcher.New(), 42, tt.success, tt.fail)

			got := rec.recorded()
			if len(got) != 1 {
				t.Fatalf("回调次数 = %d, 期望 1", len(got))
			}
			if got[0].OrderID != 42 {
				t.Errorf("order_id = %d, 期望 42", got[0].OrderID)
			}
			if got[0].Status != tt.wantStatus {
				t.Errorf("status = %q, 期望 %q", got[0].Status, tt.wantStatus)
			}
			if tt.wantMsg && got[0].Message == "" {
				t.Error("failure 回调应携带 message")
			}
			if !tt.wantMsg && got[0].Message != "" {
				t.Errorf("success 回调不应携带 message，实际 %q", got[0].Message)
			}
			if got[0].DeployedAt == "" {
				t.Error("回调应携带 deployed_at")
			}
		})
	}
}

// TestSendBatchDeployCallback 批量 setup 逐证书上报一次
func TestSendBatchDeployCallback(t *testing.T) {
	rec := &setupCallbackRecorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	p := newCallbackTestParams(t, server.URL)
	f := fetcher.New()
	sendBatchDeployCallback(p, f, 1, 2, 0)
	sendBatchDeployCallback(p, f, 2, 0, 1)

	got := rec.recorded()
	if len(got) != 2 {
		t.Fatalf("回调次数 = %d, 期望 2（逐证书一次）", len(got))
	}
	if got[0].OrderID != 1 || got[0].Status != "success" {
		t.Errorf("第一条 = order=%d status=%q, 期望 order=1 status=success", got[0].OrderID, got[0].Status)
	}
	if got[1].OrderID != 2 || got[1].Status != "failure" {
		t.Errorf("第二条 = order=%d status=%q, 期望 order=2 status=failure", got[1].OrderID, got[1].Status)
	}
}

// TestSendSetupDeployCallback_SurvivesCanceledContext setup 的 ctx 被取消后仍须送达。
// 与续签路径同构：回调是部署结果的唯一出口，不能随取消一起消失。
func TestSendSetupDeployCallback_SurvivesCanceledContext(t *testing.T) {
	rec := &setupCallbackRecorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	p := newCallbackTestParams(t, server.URL)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	p.ctx = ctx

	sendSetupDeployCallback(p, fetcher.New(), 7, 1, 0)

	if got := rec.recorded(); len(got) != 1 {
		t.Fatalf("回调次数 = %d, 期望 1（ctx 取消不得吞掉部署结果）", len(got))
	}
}
