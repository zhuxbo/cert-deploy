// Package upgrade 升级执行逻辑
package upgrade

import (
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/pkg/service"
)

// installFunc 安装函数，可在测试中替换
var installFunc = Install

// validateReleaseURL 验证升级地址并返回 HTTP 客户端
// 生产构建强制 HTTPS + TLS 1.2+，e2e 测试构建可通过 build tag 覆盖
var validateReleaseURL = func(releaseURL string) (*http.Client, error) {
	if !strings.HasPrefix(releaseURL, "https://") {
		return nil, &ErrReleaseSource{Msg: "升级地址必须使用 HTTPS 协议"}
	}
	return secureHTTPClient(), nil
}

// Options 升级选项
type Options struct {
	Channel        string // 更新通道 (main/dev)
	TargetVersion  string // 指定版本
	Force          bool   // 强制重新安装
	CheckOnly      bool   // 仅检查更新
	CurrentVersion string // 当前版本
	ReleaseURL     string // 发布地址（必需，从配置文件读取）
}

// Result 升级结果
type Result struct {
	FromVersion string // 升级前版本
	ToVersion   string // 升级后版本
	Channel     string // 使用的通道
	Restarted   bool   // 是否重启了服务
	NeedUpgrade bool   // 是否需要升级
}

// Execute 执行升级
// 返回升级结果和日志回调（用于输出进度信息）
func Execute(opts Options, logFunc func(format string, args ...interface{})) (*Result, error) {
	// 统一处理末尾斜杠，避免拼接出错
	opts.ReleaseURL = strings.TrimRight(strings.TrimSpace(opts.ReleaseURL), "/")
	if opts.ReleaseURL == "" {
		return nil, &ErrReleaseSource{Msg: "未配置升级地址，请运行 sslctl upgrade 在交互终端中输入，或使用安装脚本升级"}
	}
	// 安全校验 + 创建 HTTP 客户端（生产环境强制 HTTPS，e2e 可覆盖）
	client, err := validateReleaseURL(opts.ReleaseURL)
	if err != nil {
		return nil, err
	}
	return executeWithClient(opts, logFunc, opts.ReleaseURL+"/releases.json", client)
}

// executeWithClient 内部实现，接受 URL 和 client 参数（便于测试）
func executeWithClient(opts Options, logFunc func(format string, args ...interface{}), releaseURL string, client *http.Client) (*Result, error) {
	if logFunc == nil {
		logFunc = func(format string, args ...interface{}) {}
	}

	// 1. 获取远程版本信息
	logFunc("检查更新...")
	index, err := fetchReleaseInfoFrom(releaseURL, client)
	if err != nil {
		return nil, err
	}

	// 2. 确定目标版本和通道
	target, channel, err := ResolveTarget(opts.TargetVersion, opts.Channel, index)
	if err != nil {
		return nil, err
	}

	// 3. 比较版本
	current := NormalizeVersion(opts.CurrentVersion)
	logFunc("当前版本: %s", current)
	logFunc("最新版本: %s (%s)", target, channel)

	cmp := CompareVersions(target, current)
	result := &Result{
		FromVersion: current,
		ToVersion:   target,
		Channel:     channel,
		NeedUpgrade: cmp > 0 || opts.Force,
	}

	if !result.NeedUpgrade {
		if cmp < 0 {
			logFunc("当前版本高于远程版本，无需降级（如需降级请使用 --force）")
		} else {
			logFunc("已是最新版本")
		}
		return result, nil
	}

	baseURL := strings.TrimSuffix(releaseURL, "/releases.json")
	// 从 baseURL 提取域名+路径部分（去掉 https:// 前缀和 /sslctl 后缀）
	hostPath := strings.TrimPrefix(baseURL, "https://")
	hostPath = strings.TrimSuffix(hostPath, "/sslctl")
	installHint := fmt.Sprintf("curl -fsSL %s/install.sh | sudo bash -s -- %s", baseURL, hostPath)

	// 4. 如果只是检查，返回结果
	if opts.CheckOnly {
		logFunc("\n有新版本可用，运行 'sslctl upgrade' 进行升级")
		return result, nil
	}

	// 5. 下载安装并重启服务（平台差异化）
	var restarted bool
	if runtime.GOOS == "windows" {
		// Windows: 先停服务释放 exe 文件句柄，再替换，再启动
		restarted, err = upgradeWithStopFirst(logFunc, target, channel, index, client, baseURL, installHint)
	} else {
		// Linux/macOS: 先替换二进制（运行中进程持有旧 inode 不受影响），再重启服务
		restarted, err = upgradeWithRestartAfter(logFunc, target, channel, index, client, baseURL, installHint)
	}
	if err != nil {
		return nil, err
	}
	result.Restarted = restarted

	logFunc("\n升级完成: %s → %s", current, target)
	return result, nil
}

// downloadVerifyInstall 下载、验证签名/校验和、安装
// baseURL 为下载基础 URL，格式如 https://release.cnssl.com/sslctl
// installHint 为重新安装提示命令
func downloadVerifyInstall(target, channel string, index ReleaseIndex, logFunc func(format string, args ...interface{}), client *http.Client, baseURL, installHint string) error {
	logFunc("\n开始升级到 %s...", target)

	filename := GetDownloadFilename()
	downloadURL := GetDownloadURL(baseURL, channel, target)

	logFunc("下载 %s...", filename)
	var gzData []byte
	var err error
	dlStart := time.Now()
	if client != nil {
		gzData, err = downloadBinaryWithClient(downloadURL, client)
	} else {
		gzData, err = DownloadBinary(downloadURL)
	}
	if err != nil {
		return err
	}
	dlSec := time.Since(dlStart).Seconds()
	sizeMB := float64(len(gzData)) / 1024 / 1024
	logFunc("下载完成 (%.2f MB, %.1f 秒, %.1f MB/s)", sizeMB, dlSec, sizeMB/dlSec)

	// 验证签名（优先于校验和，防止供应链攻击）
	expectedSignature := index.GetSignature(channel, target, filename)
	logFunc("验证数字签名...")
	if err := VerifySignature(gzData, expectedSignature); err != nil {
		var keyNotFound *ErrKeyNotFound
		var noPublicKeys *ErrNoPublicKeys
		if errors.As(err, &keyNotFound) || errors.As(err, &noPublicKeys) {
			return fmt.Errorf("签名密钥已更新，请重新安装以获取最新版本:\n  %s", installHint)
		}
		return fmt.Errorf("数字签名验证失败: %w", err)
	}
	logFunc("签名验证通过")

	// 验证校验和
	expectedChecksum := index.GetChecksum(channel, target, filename)
	if expectedChecksum != "" {
		logFunc("验证文件完整性...")
		if err := VerifyChecksum(gzData, expectedChecksum); err != nil {
			return fmt.Errorf("文件完整性验证失败: %w", err)
		}
		logFunc("校验通过")
	}

	// 安装
	if _, err := installFunc(gzData); err != nil {
		return err
	}
	logFunc("安装完成")
	return nil
}

// upgradeWithStopFirst Windows 升级策略：停止服务 → 下载安装 → 启动服务
// Windows 上运行中的 exe 文件被锁定，必须先停止服务释放句柄才能替换
func upgradeWithStopFirst(logFunc func(format string, args ...interface{}), target, channel string, index ReleaseIndex, client *http.Client, baseURL, installHint string) (bool, error) {
	svcWasRunning := stopServiceBeforeUpgrade(logFunc)

	if err := downloadVerifyInstall(target, channel, index, logFunc, client, baseURL, installHint); err != nil {
		if svcWasRunning {
			startServiceAfterUpgrade(logFunc)
		}
		return false, err
	}

	if svcWasRunning {
		return startServiceAfterUpgrade(logFunc), nil
	}
	return false, nil
}

// upgradeWithRestartAfter Linux/macOS 升级策略：下载安装 → 重启服务
// Unix 上覆盖二进制文件不影响运行中的进程（持有旧 inode），下载期间服务不中断
func upgradeWithRestartAfter(logFunc func(format string, args ...interface{}), target, channel string, index ReleaseIndex, client *http.Client, baseURL, installHint string) (bool, error) {
	if err := downloadVerifyInstall(target, channel, index, logFunc, client, baseURL, installHint); err != nil {
		return false, err
	}

	return restartServiceIfRunning(logFunc), nil
}

// stopServiceBeforeUpgrade Windows 升级前停止服务，返回是否原本在运行
func stopServiceBeforeUpgrade(logFunc func(format string, args ...interface{})) bool {
	svcMgr, err := service.New(nil)
	if err != nil {
		return false
	}

	status, _ := svcMgr.Status()
	if status == nil || !status.Running {
		return false
	}

	logFunc("停止服务...")
	if err := svcMgr.Stop(); err != nil {
		logFunc("停止服务失败: %v", err)
		return false
	}
	return true
}

// restartServiceIfRunning Linux 升级后重启服务（如果运行中）
func restartServiceIfRunning(logFunc func(format string, args ...interface{})) bool {
	svcMgr, err := service.New(nil)
	if err != nil {
		return false
	}

	status, _ := svcMgr.Status()
	if status == nil || !status.Running {
		return false
	}

	logFunc("重启服务...")
	if err := svcMgr.Restart(); err != nil {
		logFunc("重启服务失败: %v", err)
		return false
	}

	logFunc("服务已重启")
	return true
}

// startServiceAfterUpgrade Windows 升级后启动服务
func startServiceAfterUpgrade(logFunc func(format string, args ...interface{})) bool {
	svcMgr, err := service.New(nil)
	if err != nil {
		return false
	}

	// 检查是否已在运行（恢复机制可能已自动拉起）
	if st, _ := svcMgr.Status(); st != nil && st.Running {
		logFunc("服务已在运行")
		return true
	}

	logFunc("启动服务...")
	if err := svcMgr.Start(); err != nil {
		// 再次检查：可能在 Status 和 Start 之间被恢复机制拉起
		if st, _ := svcMgr.Status(); st != nil && st.Running {
			logFunc("服务已启动")
			return true
		}
		logFunc("启动服务失败: %v", err)
		return false
	}

	logFunc("服务已启动")
	return true
}
