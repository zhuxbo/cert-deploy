// Package certops 回调上下文脱离取消传播的测试
package certops

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

// TestCallbackContext_Branches 回调上下文四条分支：
// 已取消 → 固定兜底；余量不足 → 固定兜底；余量充裕 → 保留父 deadline；无 deadline → 不设限
func TestCallbackContext_Branches(t *testing.T) {
	const tolerance = 5 * time.Second

	t.Run("父 ctx 已取消但余量仍大时使用兜底预算", func(t *testing.T) {
		// cancel() 不改变 deadline：daemon 收到 SIGTERM 时父预算余量可能仍有几十分钟，
		// 若先判余量就会落进"保留父预算"分支，与设计相反
		parent, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		cancel()

		cbCtx, cbCancel := callbackContext(parent)
		defer cbCancel()

		if cbCtx.Err() != nil {
			t.Fatalf("回调上下文不应继承取消状态: %v", cbCtx.Err())
		}
		dl, ok := cbCtx.Deadline()
		if !ok {
			t.Fatal("已取消分支应设置兜底 deadline")
		}
		if budget := time.Until(dl); budget > CallbackFallbackBudget+tolerance {
			t.Errorf("预算 = %v, 期望约 %v", budget.Round(time.Second), CallbackFallbackBudget)
		}
	})

	t.Run("父 ctx 余量不足时使用兜底预算", func(t *testing.T) {
		parent, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cbCtx, cbCancel := callbackContext(parent)
		defer cbCancel()

		dl, ok := cbCtx.Deadline()
		if !ok {
			t.Fatal("余量不足分支应设置兜底 deadline")
		}
		budget := time.Until(dl)
		if budget < CallbackFallbackBudget-tolerance || budget > CallbackFallbackBudget+tolerance {
			t.Errorf("预算 = %v, 期望约 %v", budget.Round(time.Second), CallbackFallbackBudget)
		}
	})

	t.Run("父 ctx 余量充裕时不缩小", func(t *testing.T) {
		parent, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()

		cbCtx, cbCancel := callbackContext(parent)
		defer cbCancel()

		dl, ok := cbCtx.Deadline()
		if !ok {
			t.Fatal("应保留父 deadline")
		}
		if budget := time.Until(dl); budget < 19*time.Minute {
			t.Errorf("预算 = %v, 期望保留父 deadline 约 20m", budget.Round(time.Second))
		}
	})

	t.Run("父 ctx 无 deadline 时不设限", func(t *testing.T) {
		cbCtx, cbCancel := callbackContext(context.Background())
		defer cbCancel()

		if _, ok := cbCtx.Deadline(); ok {
			t.Error("无 deadline 的父 ctx 不应被强加 deadline，由 fetcher 单次超时与重试上限兜底")
		}
	})
}

// TestSendCallback_SurvivesCanceledParent 父 ctx 已取消时回调仍必须送达。
// 实测基线：改动前该场景发出 0 次回调，整轮部署结果凭空消失。
func TestSendCallback_SurvivesCanceledParent(t *testing.T) {
	rec := &callbackRecorder{queryResp: `{"code":1,"msg":"ok"}`}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	svc := &Service{
		fetcher: fetcher.New(),
		log:     logger.NewNopLogger(),
	}

	parent, cancel := context.WithCancel(context.Background())
	cancel()

	svc.sendCallback(parent, config.APIConfig{URL: server.URL, Token: "token"},
		&fetcher.CallbackRequest{OrderID: 1, Status: "success"})

	got := rec.recorded()
	if len(got) != 1 {
		t.Fatalf("回调次数 = %d, 期望 1（父 ctx 取消不得吞掉部署结果）", len(got))
	}
	if got[0].Status != "success" {
		t.Errorf("回调状态 = %q, 期望 success", got[0].Status)
	}
}
