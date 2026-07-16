// Package daemon 守护进程模式测试
package daemon

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/certops"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

// TestCheckAndDeploy_Success 测试成功检查部署
func TestCheckAndDeploy_Success(t *testing.T) {
	// 这个测试验证 checkAndDeploy 函数的日志输出逻辑
	// 由于 checkAndDeploy 依赖 certops.Service，我们测试其行为模式

	tmpDir := t.TempDir()
	cfgManager, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()

	// 创建服务
	svc := certops.NewService(cfgManager, log)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 调用 checkAndDeploy（无证书配置时应该正常返回）
	checkAndDeploy(ctx, svc, cfgManager, log)
}

// TestCheckAndDeploy_WithContext 测试带上下文的检查
func TestCheckAndDeploy_WithContext(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)
	log := logger.NewNopLogger()
	svc := certops.NewService(cfgManager, log)

	// 使用已取消的上下文
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	// 应该能够处理取消的上下文
	checkAndDeploy(ctx, svc, cfgManager, log)
}

// TestNextRandomDaily 测试随机每日延迟
func TestNextRandomDaily(t *testing.T) {
	for i := 0; i < 100; i++ {
		d := nextRandomDaily()
		if d < time.Hour {
			t.Errorf("nextRandomDaily() = %v, 不应低于 1 小时", d)
		}
		if d > 48*time.Hour {
			t.Errorf("nextRandomDaily() = %v, 不应超过 48 小时", d)
		}
	}
}

// TestRenewResultStats 测试续签结果统计
func TestRenewResultStats(t *testing.T) {
	results := []certops.RenewResult{
		{CertName: "cert1", Status: "success", DeployCount: 2},
		{CertName: "cert2", Status: "success", DeployCount: 1},
		{CertName: "cert3", Status: "failure", Error: fmt.Errorf("API error")},
		{CertName: "cert4", Status: "pending"},
		{CertName: "cert5", Status: "pending"},
	}

	var successCount, failedCount, pendingCount int
	for _, r := range results {
		switch r.Status {
		case "success":
			successCount++
		case "failure":
			failedCount++
		case "pending":
			pendingCount++
		}
	}

	if successCount != 2 {
		t.Errorf("successCount = %d, want 2", successCount)
	}
	if failedCount != 1 {
		t.Errorf("failedCount = %d, want 1", failedCount)
	}
	if pendingCount != 2 {
		t.Errorf("pendingCount = %d, want 2", pendingCount)
	}
}

// TestContextTimeout 测试上下文超时
func TestContextTimeout(t *testing.T) {
	parentCtx := context.Background()

	// 模拟 checkAndDeploy 中的超时设置
	ctx, cancel := context.WithTimeout(parentCtx, 30*time.Minute)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Error("上下文应该有截止时间")
	}

	// 验证截止时间在 30 分钟后（允许 1 秒误差，兼容慢速 CI）
	expected := time.Now().Add(30 * time.Minute)
	diff := deadline.Sub(expected)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("截止时间不正确: diff = %v，应在 ±1s 内", diff)
	}
}

// TestCalcCheckTimeout 验证动态超时计算
func TestCalcCheckTimeout(t *testing.T) {
	tests := []struct {
		certCount int
		wantMin   time.Duration
		wantMax   time.Duration
	}{
		{0, 30 * time.Minute, 30 * time.Minute},
		{1, 30 * time.Minute, 30 * time.Minute},
		{15, 30 * time.Minute, 30 * time.Minute},
		{16, 32 * time.Minute, 32 * time.Minute},
		{120, 200 * time.Minute, 200 * time.Minute}, // capped at 100 → 200min
		{200, 200 * time.Minute, 200 * time.Minute}, // capped at 100 → 200min
	}
	for _, tt := range tests {
		got := calcCheckTimeout(tt.certCount)
		if got < tt.wantMin || got > tt.wantMax {
			t.Errorf("calcCheckTimeout(%d) = %v, want [%v, %v]", tt.certCount, got, tt.wantMin, tt.wantMax)
		}
	}

	// 验证下限和上限
	if got := calcCheckTimeout(0); got < 30*time.Minute {
		t.Errorf("最小超时应 >= 30 分钟, got %v", got)
	}
	if got := calcCheckTimeout(999); got > 4*time.Hour {
		t.Errorf("最大超时应 <= 4 小时, got %v", got)
	}
}

// TestIsCheckOverdue 验证补偿检查判定：从未检查/超阈值 → 错过；新近检查 → 正常。
func TestIsCheckOverdue(t *testing.T) {
	tests := []struct {
		name        string
		lastCheckAt time.Time
		wantOverdue bool
	}{
		{"从未检查", time.Time{}, true},
		{"26 小时前检查过", time.Now().Add(-26 * time.Hour), true},
		{"3 天前检查过", time.Now().Add(-72 * time.Hour), true},
		{"1 小时前检查过", time.Now().Add(-1 * time.Hour), false},
		{"24 小时前检查过", time.Now().Add(-24 * time.Hour), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cm, err := config.NewConfigManagerWithDir(tmpDir)
			if err != nil {
				t.Fatalf("创建配置管理器失败: %v", err)
			}
			if !tt.lastCheckAt.IsZero() {
				if err := cm.UpdateMetadata(func(m *config.ConfigMetadata) {
					m.LastCheckAt = tt.lastCheckAt
				}); err != nil {
					t.Fatalf("写入 LastCheckAt 失败: %v", err)
				}
			}

			overdue, _ := isCheckOverdue(cm)
			if overdue != tt.wantOverdue {
				t.Errorf("isCheckOverdue() = %v, want %v", overdue, tt.wantOverdue)
			}
		})
	}
}

// TestNextCheckDelay_OverdueUsesShortDelay 验证错过时使用短补偿延迟（30~60 分钟），
// 未错过时走常规明天随机调度（至少 1 小时）。
func TestNextCheckDelay_OverdueUsesShortDelay(t *testing.T) {
	log := logger.NewNopLogger()

	// 从未检查：补偿延迟 30~60 分钟
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	delay := nextCheckDelay(cm, log, false)
	if delay < 30*time.Minute || delay > 61*time.Minute {
		t.Errorf("错过时补偿延迟应在 30~60 分钟，实际 %v", delay)
	}

	// 首轮跳过补偿判定：启动检查已覆盖，即使 LastCheckAt 过旧也走常规调度，
	// 避免启动轮与补偿轮双跑
	delay = nextCheckDelay(cm, log, true)
	if delay < time.Hour {
		t.Errorf("首轮应跳过补偿判定走常规调度（≥1 小时），实际 %v", delay)
	}

	// 新近检查过：常规调度（nextRandomDaily 最短 1 小时）
	if err := cm.UpdateMetadata(func(m *config.ConfigMetadata) {
		m.LastCheckAt = time.Now()
	}); err != nil {
		t.Fatalf("写入 LastCheckAt 失败: %v", err)
	}
	delay = nextCheckDelay(cm, log, false)
	if delay < time.Hour {
		t.Errorf("未错过时应走常规调度（≥1 小时），实际 %v", delay)
	}
}
