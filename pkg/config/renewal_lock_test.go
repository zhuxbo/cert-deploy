// Package config 续签互斥锁测试
package config

import (
	"testing"
)

// TestAcquireRenewalLock_MutualExclusion 验证续签锁互斥：
// 持有期间再次获取失败，释放后可再次获取（daemon 与手动 deploy/setup 共用此锁）。
func TestAcquireRenewalLock_MutualExclusion(t *testing.T) {
	workDir := t.TempDir()

	release1, acquired1, err := AcquireRenewalLock(workDir)
	if err != nil {
		t.Fatalf("首次获取锁失败: %v", err)
	}
	if !acquired1 {
		t.Fatal("首次获取锁应成功")
	}

	// 持有期间再次获取（模拟手动 deploy 与 daemon 并发）应失败
	release2, acquired2, err := AcquireRenewalLock(workDir)
	if err != nil {
		t.Fatalf("二次获取不应报系统错误: %v", err)
	}
	if acquired2 {
		release2()
		t.Fatal("锁被持有时二次获取应失败（互斥）")
	}

	// 释放后可再次获取
	release1()
	release3, acquired3, err := AcquireRenewalLock(workDir)
	if err != nil {
		t.Fatalf("释放后获取锁失败: %v", err)
	}
	if !acquired3 {
		t.Fatal("释放后应能再次获取锁")
	}
	release3()
}

// TestAcquireRenewalLock_BadWorkDir 验证锁文件创建失败时返回错误（调用方可降级）。
func TestAcquireRenewalLock_BadWorkDir(t *testing.T) {
	_, acquired, err := AcquireRenewalLock("/nonexistent-dir-for-renewal-lock-test")
	if err == nil {
		t.Error("不存在的目录应返回错误")
	}
	if acquired {
		t.Error("失败时 acquired 应为 false")
	}
}
