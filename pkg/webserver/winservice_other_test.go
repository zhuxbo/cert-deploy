//go:build !windows

package webserver

import (
	"context"
	"strings"
	"testing"
)

func TestFindWebServerService_AlwaysEmptyOnNonWindows(t *testing.T) {
	if got := FindWebServerService("nginx", "nginx.exe"); got != "" {
		t.Errorf("非 Windows 上应返回空，得到 %q", got)
	}
	if got := FindWebServerService("", ""); got != "" {
		t.Errorf("空 needle 应返回空，得到 %q", got)
	}
}

func TestRestartWindowsService_NotSupportedOnNonWindows(t *testing.T) {
	err := RestartWindowsService(context.Background(), "nginx")
	if err == nil {
		t.Fatalf("非 Windows 上必须返回错误")
	}
	if !strings.Contains(err.Error(), "only available on windows") {
		t.Errorf("错误信息应说明仅 Windows 可用，得到 %v", err)
	}
}

// TestDetectNginxCommands_NonWindowsNoSentinel 在非 Windows 下不应出现
// winsvc: 哨兵，避免 detector 把 ReloadCmd 设成跨平台不可用的形态。
func TestDetectNginxCommands_NonWindowsNoSentinel(t *testing.T) {
	cmds := DetectNginxCommands()
	if strings.HasPrefix(cmds.ReloadCmd, WinSvcReloadPrefix) {
		t.Errorf("非 Windows 上 ReloadCmd 不应是 winsvc 哨兵: %q", cmds.ReloadCmd)
	}
}
