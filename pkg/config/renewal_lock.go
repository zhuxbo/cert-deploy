// Package config 续签/部署互斥锁
package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// RenewalLockFile 续签互斥锁文件名（daemon 续签检查与手动 deploy/setup 共用）
const RenewalLockFile = "renewal.lock"

// AcquireRenewalLock 非阻塞获取续签/部署互斥锁（进程级文件锁）。
// daemon 续签检查与手动 deploy/setup 共用同一把锁，防止两者并发操作同一证书目录与配置。
// 返回值：
//   - release：释放函数（acquired 为 true 时必须调用；false 时为空操作）
//   - acquired：是否获取到锁（false 且 err 为 nil 表示另一进程正持有锁）
//   - err：锁文件创建或加锁系统调用失败（调用方可选择降级继续，与 daemon 既有行为一致）
func AcquireRenewalLock(workDir string) (release func(), acquired bool, err error) {
	release = func() {}
	lockPath := filepath.Join(workDir, RenewalLockFile)
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return release, false, fmt.Errorf("创建锁文件失败: %w", err)
	}
	locked, lockErr := TryLockFile(f)
	if lockErr != nil {
		_ = f.Close()
		return release, false, fmt.Errorf("获取文件锁失败: %w", lockErr)
	}
	if !locked {
		_ = f.Close()
		return release, false, nil
	}
	// 关闭文件描述符自动释放锁
	return func() { _ = f.Close() }, true, nil
}
