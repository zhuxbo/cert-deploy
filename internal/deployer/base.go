// Package deployer 提供部署器公共功能
package deployer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/internal/executor"
	"github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/util"
)

// Config 部署器配置
type Config struct {
	CertPath      string // 证书文件路径
	KeyPath       string // 私钥文件路径
	ChainPath     string // 中间证书链路径（仅 Apache）
	TestCommand   string // 配置测试命令
	ReloadCommand string // 服务重载命令
}

// Base 部署器基础功能
type Base struct {
	TestCommand   string
	ReloadCommand string
}

// TestConfig 测试配置
func (b *Base) TestConfig() error {
	if b.TestCommand == "" {
		return nil
	}
	return executor.Run(b.TestCommand)
}

// NeedsProcessRestart 检测是否需要通过进程重启方式重载（Windows 非服务模式）
// 返回 true 时部署过程会短暂中断服务
func (b *Base) NeedsProcessRestart() bool {
	if runtime.GOOS != "windows" || b.ReloadCommand == "" {
		return false
	}
	// 尝试执行 reload 命令的 dry run：解析命令但不执行，
	// 通过命令特征判断是否依赖服务注册（-k graceful / -s reload）
	cmd := b.ReloadCommand
	return strings.Contains(cmd, "-k ") || strings.Contains(cmd, "-s reload")
}

// ReloadService 重载服务
// 优先使用服务管理命令；失败时尝试回退策略：
// - Linux 容器环境（无 systemd）：回退到 kill -USR1（Apache graceful）或 nginx -s reload
// - Windows 非服务模式：回退到进程重启
func (b *Base) ReloadService() error {
	if b.ReloadCommand == "" {
		return nil
	}
	err := executor.Run(b.ReloadCommand)
	if err == nil {
		return nil
	}

	errMsg := err.Error()

	// Linux 容器环境：httpd -k graceful 可能因无 systemd 失败
	// 回退到发送 USR1 信号（Apache graceful reload）
	if runtime.GOOS != "windows" && strings.Contains(errMsg, "systemd") {
		return b.reloadFallbackLinux(err)
	}

	// Windows 非服务模式：回退到进程重启
	if runtime.GOOS != "windows" {
		return err
	}
	if !strings.Contains(errMsg, "No installed service") &&
		!strings.Contains(errMsg, "could not open error log") {
		return err
	}

	exe, _ := executor.ParseCommand(b.ReloadCommand)
	if exe == "" {
		return err
	}

	return restartProcessWindows(exe, err)
}

// reloadFallbackLinux 在 Linux 容器中 reload 失败时的回退策略
// httpd -k graceful 在无 systemd 容器中可能失败，回退到发送 SIGUSR1 信号
func (b *Base) reloadFallbackLinux(origErr error) error {
	exe, _ := executor.ParseCommand(b.ReloadCommand)
	if exe == "" {
		return origErr
	}
	processName := filepath.Base(exe)

	// 通过 /proc 扫描查找进程 PID（不依赖 pidof 等外部命令）
	pid := findPIDByName(processName)
	if pid <= 0 {
		return origErr
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return origErr
	}

	// 发送 SIGUSR1（Apache: graceful restart）
	if err := signalUSR1(proc); err != nil {
		return origErr
	}
	return nil
}

// findPIDByName 通过扫描 /proc 查找指定进程名的 PID
func findPIDByName(name string) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) == name {
			return pid
		}
	}
	return 0
}

// restartProcessWindows 通过终止进程+重启实现重载（适用于 Apache/Nginx 非服务模式）
// 流程：终止进程 → 等待退出 → 等守护进程自动拉起 → 否则手动启动
func restartProcessWindows(exe string, origErr error) error {
	// 提取进程名（如 httpd.exe、nginx.exe）
	processName := filepath.Base(exe)

	// 终止进程树
	fmt.Fprintf(os.Stderr, "正在停止 %s 进程...\n", processName)
	_ = executor.Run(fmt.Sprintf("taskkill /F /T /IM %s", processName))

	// 等待进程退出（最多 10 秒）
	for i := 0; i < 20; i++ {
		time.Sleep(500 * time.Millisecond)
		if !isProcessRunning(processName) {
			break
		}
	}

	// 等待守护进程自动拉起（面板等管理工具），最多 10 秒
	fmt.Fprintf(os.Stderr, "等待 %s 重新启动...\n", processName)
	for i := 0; i < 10; i++ {
		time.Sleep(time.Second)
		if isProcessRunning(processName) {
			fmt.Fprintf(os.Stderr, "%s 已恢复运行\n", processName)
			return nil
		}
	}

	// 守护进程未拉起，手动启动
	fmt.Fprintf(os.Stderr, "守护进程未自动拉起，手动启动 %s...\n", processName)
	var args []string
	if strings.Contains(strings.ToLower(processName), "httpd") {
		// Apache 需要 -d 指定 ServerRoot
		serverRoot := filepath.Dir(filepath.Dir(exe))
		args = []string{"-d", serverRoot}
	}
	if startErr := executor.RunDetached(exe, args...); startErr != nil {
		return fmt.Errorf("重启失败: %w（原始错误: %v）", startErr, origErr)
	}

	// 确认启动成功
	time.Sleep(2 * time.Second)
	if !isProcessRunning(processName) {
		return fmt.Errorf("进程启动后退出（原始错误: %v）", origErr)
	}
	return nil
}

// TestAndReload 测试配置并重载服务
func (b *Base) TestAndReload() error {
	if err := b.TestConfig(); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorConfig, errors.PhaseTest,
			"config test failed", err,
		)
	}
	if err := b.ReloadService(); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorReload, errors.PhaseReload,
			"reload failed", err,
		)
	}
	return nil
}

// TestAndReloadForRollback 回滚后测试配置并重载服务
func (b *Base) TestAndReloadForRollback() error {
	if b.TestCommand != "" {
		if err := executor.Run(b.TestCommand); err != nil {
			return errors.NewStructuredDeployError(
				errors.DeployErrorConfig, errors.PhaseRollback,
				"config test failed after rollback", err,
			)
		}
	}
	if b.ReloadCommand != "" {
		if err := b.ReloadService(); err != nil {
			return errors.NewStructuredDeployError(
				errors.DeployErrorReload, errors.PhaseRollback,
				"reload failed after rollback", err,
			)
		}
	}
	return nil
}

// isProcessRunning 检测指定名称的进程是否仍在运行（Windows）
func isProcessRunning(name string) bool {
	out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("IMAGENAME eq %s", name), "/NH").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), strings.ToLower(name))
}

// RestoreFile 恢复单个文件
func RestoreFile(backupPath, targetPath string) error {
	return util.CopyFile(backupPath, targetPath)
}
