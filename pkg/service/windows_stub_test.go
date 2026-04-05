//go:build !windows

package service

import (
	"context"
	"strings"
	"testing"
)

// TestWindowsStub_AllMethods 验证非 Windows 平台上所有 Windows stub 方法的返回值
func TestWindowsStub_AllMethods(t *testing.T) {
	cfg := &ServiceConfig{
		Name:        "test-svc",
		DisplayName: "Test",
		Description: "Test",
		ExecPath:    "/usr/bin/test",
		WorkDir:     "/tmp",
	}

	mgr := NewWindowsManager(cfg)
	errMsg := "仅在 Windows 系统上可用"

	// 所有有副作用的方法应返回 "仅在 Windows 系统上可用" 错误
	t.Run("Install", func(t *testing.T) {
		err := mgr.Install()
		if err == nil {
			t.Fatal("Install() 应返回错误")
		}
		if !strings.Contains(err.Error(), errMsg) {
			t.Errorf("错误信息 %q 不包含 %q", err.Error(), errMsg)
		}
	})

	t.Run("Uninstall", func(t *testing.T) {
		err := mgr.Uninstall()
		if err == nil {
			t.Fatal("Uninstall() 应返回错误")
		}
		if !strings.Contains(err.Error(), errMsg) {
			t.Errorf("错误信息 %q 不包含 %q", err.Error(), errMsg)
		}
	})

	t.Run("Start", func(t *testing.T) {
		err := mgr.Start()
		if err == nil {
			t.Fatal("Start() 应返回错误")
		}
		if !strings.Contains(err.Error(), errMsg) {
			t.Errorf("错误信息 %q 不包含 %q", err.Error(), errMsg)
		}
	})

	t.Run("Stop", func(t *testing.T) {
		err := mgr.Stop()
		if err == nil {
			t.Fatal("Stop() 应返回错误")
		}
		if !strings.Contains(err.Error(), errMsg) {
			t.Errorf("错误信息 %q 不包含 %q", err.Error(), errMsg)
		}
	})

	t.Run("Restart", func(t *testing.T) {
		err := mgr.Restart()
		if err == nil {
			t.Fatal("Restart() 应返回错误")
		}
		if !strings.Contains(err.Error(), errMsg) {
			t.Errorf("错误信息 %q 不包含 %q", err.Error(), errMsg)
		}
	})

	t.Run("Status", func(t *testing.T) {
		status, err := mgr.Status()
		if err == nil {
			t.Fatal("Status() 应返回错误")
		}
		if status != nil {
			t.Error("Status() 应返回 nil status")
		}
		if !strings.Contains(err.Error(), errMsg) {
			t.Errorf("错误信息 %q 不包含 %q", err.Error(), errMsg)
		}
	})

	t.Run("Enable", func(t *testing.T) {
		err := mgr.Enable()
		if err == nil {
			t.Fatal("Enable() 应返回错误")
		}
		if !strings.Contains(err.Error(), errMsg) {
			t.Errorf("错误信息 %q 不包含 %q", err.Error(), errMsg)
		}
	})

	t.Run("Disable", func(t *testing.T) {
		err := mgr.Disable()
		if err == nil {
			t.Fatal("Disable() 应返回错误")
		}
		if !strings.Contains(err.Error(), errMsg) {
			t.Errorf("错误信息 %q 不包含 %q", err.Error(), errMsg)
		}
	})
}

// TestWindowsStub_IsWindowsService 验证 IsWindowsService 在非 Windows 上返回 false
func TestWindowsStub_IsWindowsService(t *testing.T) {
	if IsWindowsService() {
		t.Error("IsWindowsService() 在非 Windows 平台应返回 false")
	}
}

// TestWindowsStub_RunAsService 验证 RunAsService 在非 Windows 上返回错误
func TestWindowsStub_RunAsService(t *testing.T) {
	err := RunAsService("test-svc", func(ctx context.Context) {
		t.Fatal("handler 不应被调用")
	})
	if err == nil {
		t.Fatal("RunAsService() 应返回错误")
	}
	if !strings.Contains(err.Error(), "仅在 Windows 系统上可用") {
		t.Errorf("错误信息 %q 不包含预期子串", err.Error())
	}
}

// TestWindowsStub_ImplementsManager 验证 WindowsManager 实现了 Manager 接口
func TestWindowsStub_ImplementsManager(t *testing.T) {
	cfg := &ServiceConfig{
		Name:        "test",
		DisplayName: "Test",
		Description: "Test",
		ExecPath:    "/usr/bin/test",
		WorkDir:     "/tmp",
	}

	var _ Manager = NewWindowsManager(cfg)
}
