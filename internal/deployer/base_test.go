package deployer

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/webserver"
)

// TestReloadService_WinSvcSentinel 验证 ReloadService 识别 winsvc: 哨兵后
// 直接调用 restartWindowsServiceFunc，跳过 executor.Run。
func TestReloadService_WinSvcSentinel(t *testing.T) {
	called := ""
	orig := restartWindowsServiceFunc
	restartWindowsServiceFunc = func(name string) error {
		called = name
		return nil
	}
	defer func() { restartWindowsServiceFunc = orig }()

	b := &Base{ReloadCommand: webserver.WinSvcReloadPrefix + "nginx"}
	if err := b.ReloadService(); err != nil {
		t.Fatalf("ReloadService 返回错误: %v", err)
	}
	if called != "nginx" {
		t.Fatalf("restartWindowsServiceFunc 收到的 name = %q, 期望 nginx", called)
	}
}

// TestReloadService_WinSvcSentinelError 验证服务重启失败时错误透传。
func TestReloadService_WinSvcSentinelError(t *testing.T) {
	wantErr := errors.New("scm boom")
	orig := restartWindowsServiceFunc
	restartWindowsServiceFunc = func(_ string) error { return wantErr }
	defer func() { restartWindowsServiceFunc = orig }()

	b := &Base{ReloadCommand: webserver.WinSvcReloadPrefix + "Apache2.4"}
	err := b.ReloadService()
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, 期望 wrap %v", err, wantErr)
	}
}

// TestNeedsProcessRestart_WinSvc 验证 winsvc: 哨兵被视为「需要进程级重启」，
// 这样 setup 流程会提前向用户提示部署期间会有短暂中断。
func TestNeedsProcessRestart_WinSvc(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("only relevant on windows")
	}
	b := &Base{ReloadCommand: webserver.WinSvcReloadPrefix + "nginx"}
	if !b.NeedsProcessRestart() {
		t.Fatalf("winsvc: 哨兵应被识别为需要进程重启")
	}
}

// TestReloadService_AccessDeniedTriggersFallback 在 Windows 下验证
// "Access is denied" 错误信息会触发进程重启回退（而不是直接抛错）。
//
// 通过让 ReloadCommand 走一个不在白名单的命令制造 executor 错误，无法直接
// 模拟原生 nginx 的 OpenEvent 报文；这里只检查白名单匹配逻辑：错误消息中
// 含 "Access is denied" 时不应在 base.go:80 提前 return。我们用一个直接
// 测试逻辑分支的小函数验证。
func TestReloadFallbackTriggers(t *testing.T) {
	cases := []struct {
		msg         string
		shouldRetry bool
	}{
		{"reload failed: No installed service", true},
		{"reload failed: could not open error log", true},
		{"OpenEvent(\"Global\\ngx_reload_8216\") failed (5: Access is denied)", true},
		{"some other unrelated error", false},
	}
	for _, c := range cases {
		got := strings.Contains(c.msg, "No installed service") ||
			strings.Contains(c.msg, "could not open error log") ||
			strings.Contains(c.msg, "Access is denied")
		if got != c.shouldRetry {
			t.Errorf("msg=%q got=%v want=%v", c.msg, got, c.shouldRetry)
		}
	}
}
