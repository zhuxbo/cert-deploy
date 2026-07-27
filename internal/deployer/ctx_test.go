// Package deployer context 贯通的行为测试（P2-1）
package deployer

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestReloadService_RespectsCanceledContext 上游取消必须能中断重载命令，
// 否则 daemon 收到 SIGTERM 后只能等强杀窗口耗尽。
func TestReloadService_RespectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// 用白名单内的真实命令，确保走到 exec 而不是在解析阶段就被拒
	b := &Base{ReloadCommand: "nginx -s reload"}
	err := b.ReloadService(ctx)
	if err == nil {
		t.Fatal("已取消的 ctx 下 ReloadService 应返回错误")
	}
	// 必须是取消导致的失败，而不是"本机没装 nginx"之类的巧合
	if !errors.Is(err, context.Canceled) {
		t.Errorf("错误应源自 ctx 取消，实际: %v", err)
	}
}

// TestTestConfig_RespectsCanceledContext 配置测试同样受取消约束
func TestTestConfig_RespectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	b := &Base{TestCommand: "nginx -t"}
	err := b.TestConfig(ctx)
	if err == nil {
		t.Fatal("已取消的 ctx 下 TestConfig 应返回错误")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("错误应源自 ctx 取消，实际: %v", err)
	}
}

// TestTestConfig_EmptyCommandIgnoresContext 空命令是无操作，
// 不应因 ctx 已取消而凭空造出失败
func TestTestConfig_EmptyCommandIgnoresContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	b := &Base{}
	if err := b.TestConfig(ctx); err != nil {
		t.Errorf("空 TestCommand 应直接返回 nil，实际 %v", err)
	}
}

// TestWaitForApacheReload_AbortsOnCanceledContext 等待新 worker 的轮询必须响应取消，
// 否则单个绑定就能占满 15 秒
func TestWaitForApacheReload_AbortsOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := waitForApacheReload(ctx, 1, map[int]struct{}{}, 15*time.Second)
	if err == nil {
		t.Fatal("已取消的 ctx 下应立即返回错误")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("耗时 %v，取消未能中断轮询", elapsed)
	}
}
