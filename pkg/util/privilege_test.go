// Package util 权限检查测试
package util

import (
	"os"
	"runtime"
	"testing"
)

// TestCheckRootPrivilege 测试 root 权限检查
func TestCheckRootPrivilege(t *testing.T) {
	err := CheckRootPrivilege()

	if runtime.GOOS == "windows" {
		// Windows 下总是返回 nil
		if err != nil {
			t.Errorf("CheckRootPrivilege() on Windows should return nil, got: %v", err)
		}
		return
	}

	// Unix 系统：根据实际 euid 判断预期结果
	if os.Geteuid() == 0 {
		if err != nil {
			t.Errorf("CheckRootPrivilege() as root should return nil, got: %v", err)
		}
	} else {
		if err == nil {
			t.Error("CheckRootPrivilege() as non-root should return error")
		}
	}
}
