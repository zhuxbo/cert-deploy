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
// - Linux 容器环境（无 systemd）：先发送 SIGUSR1 再执行 reload 命令
// - Windows 非服务模式：回退到进程重启
func (b *Base) ReloadService() error {
	if b.ReloadCommand == "" {
		return nil
	}

	// Linux 容器环境预检：如果 systemd 不可用且命令涉及 httpd/apache，
	// 先尝试通过 SIGUSR1 信号 reload（避免 httpd -k graceful 因无 dbus 导致进程异常退出）
	if runtime.GOOS != "windows" && !isSystemdAvailable() && b.isApacheReload() {
		if err := b.reloadFallbackLinux(); err == nil {
			return nil
		}
	}

	err := executor.Run(b.ReloadCommand)
	if err == nil {
		return nil
	}

	// Windows 非服务模式：回退到进程重启
	if runtime.GOOS != "windows" {
		return err
	}
	msg := err.Error()
	if !strings.Contains(msg, "No installed service") &&
		!strings.Contains(msg, "could not open error log") {
		return err
	}

	exe, _ := executor.ParseCommand(b.ReloadCommand)
	if exe == "" {
		return err
	}

	return restartProcessWindows(exe, err)
}

// isSystemdAvailable 检测 systemd 是否可用（通过 /run/systemd/system 目录判断）
func isSystemdAvailable() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// isApacheReload 检查 reload 命令是否与 Apache 相关
func (b *Base) isApacheReload() bool {
	cmd := strings.ToLower(b.ReloadCommand)
	return strings.Contains(cmd, "httpd") || strings.Contains(cmd, "apache")
}

// reloadFallbackLinux 在 Linux 容器中通过 SIGUSR1 信号实现 Apache graceful reload
func (b *Base) reloadFallbackLinux() error {
	exe, _ := executor.ParseCommand(b.ReloadCommand)
	if exe == "" {
		return fmt.Errorf("cannot parse reload command: %s", b.ReloadCommand)
	}
	// apachectl/apache2ctl 是 shell wrapper，实际进程名是 httpd/apache2
	processName := apacheProcessName(filepath.Base(exe))

	// 通过 /proc 扫描查找 master 进程 PID（不依赖 pidof 等外部命令）
	pid := findMasterPIDByName(processName)
	if pid <= 0 {
		return fmt.Errorf("process %s not found", processName)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}

	// 发送 SIGUSR1（Apache: graceful restart）
	if err := signalUSR1(proc); err != nil {
		return fmt.Errorf("send SIGUSR1 to %d: %w", pid, err)
	}
	return nil
}

// apacheProcessName 将 apachectl/apache2ctl 等 wrapper 脚本名映射到实际进程名
func apacheProcessName(name string) string {
	switch name {
	case "apachectl", "apache2ctl":
		// 尝试 httpd 和 apache2 两种可能的进程名
		if findMasterPIDByName("httpd") > 0 {
			return "httpd"
		}
		return "apache2"
	default:
		return name
	}
}

// findMasterPIDByName 通过扫描 /proc 查找指定进程名的 master 进程 PID
// 优先返回 PPID=1 的进程（master），否则返回最小 PID（通常是 master）
func findMasterPIDByName(name string) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}

	minPID := 0
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
		if strings.TrimSpace(string(comm)) != name {
			continue
		}

		// 检查 PPID：master 进程的 PPID 通常是 1（init/容器入口）
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err == nil {
			for _, line := range strings.Split(string(status), "\n") {
				if strings.HasPrefix(line, "PPid:") {
					ppidStr := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
					if ppid, _ := strconv.Atoi(ppidStr); ppid <= 1 {
						return pid // PPID=0 或 1，确定是 master
					}
					break
				}
			}
		}

		// 记录最小 PID 作为后备
		if minPID == 0 || pid < minPID {
			minPID = pid
		}
	}
	return minPID
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
