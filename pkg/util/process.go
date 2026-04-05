// Package util 进程相关工具函数
package util

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/zhuxbo/sslctl/internal/executor"
)

// isSelfInContainer 缓存当前进程是否在容器内的检测结果
var isSelfInContainer = sync.OnceValue(func() bool {
	// Docker 创建的标识文件
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	// 检查自身 cgroup
	return IsContainerProcess("self")
})

// IsSelfInContainer 检查当前进程是否运行在容器内
// 当 sslctl 自身在容器中运行时，不应跳过同容器的 Web 服务器进程
func IsSelfInContainer() bool {
	return isSelfInContainer()
}

// IsContainerProcess 检查进程是否运行在容器内
// 通过检查 /proc/<pid>/cgroup 判断是否为容器进程
func IsContainerProcess(pid string) bool {
	cgroupPath := fmt.Sprintf("/proc/%s/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return false
	}

	content := string(data)
	// 检查常见的容器运行时标识
	containerPatterns := []string{
		"/docker/",
		"/containerd/",
		"/lxc/",
		"/kubepods/",
	}
	for _, pattern := range containerPatterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}

	return false
}

// ShouldSkipContainerProcess 判断是否应该跳过容器进程
// 仅在宿主机上运行时跳过容器进程（交给 Docker 扫描器处理）
// 当 sslctl 自身在容器内时，不跳过（同容器的进程应当扫描）
func ShouldSkipContainerProcess(pid string) bool {
	if IsSelfInContainer() {
		return false
	}
	return IsContainerProcess(pid)
}

// FindBinaryFromPort 通过端口查找进程的可执行文件路径
// processName: 进程名（如 nginx、httpd、apache2）
// 返回可执行文件的完整路径，如果未找到则返回空字符串
// 在宿主机上运行时跳过容器进程，在容器内运行时不跳过
func FindBinaryFromPort(processName string) string {
	// 尝试 ss 命令
	output, err := executor.RunOutput("ss -tlnp")
	if err != nil {
		// 尝试 netstat
		output, err = executor.RunOutput("netstat -tlnp")
		if err != nil {
			return ""
		}
	}

	// 查找包含 :80 或 :443 且包含进程名的行
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if !strings.Contains(line, processName) {
			continue
		}
		if !strings.Contains(line, ":80") && !strings.Contains(line, ":443") {
			continue
		}

		// 提取 PID
		// ss 格式: users:(("nginx",pid=1234,fd=6))
		// netstat 格式: 1234/nginx
		pidRe := regexp.MustCompile(`pid=(\d+)|(\d+)/` + regexp.QuoteMeta(processName))
		matches := pidRe.FindStringSubmatch(line)
		if len(matches) > 1 {
			pid := matches[1]
			if pid == "" {
				pid = matches[2]
			}
			if pid != "" {
				// 宿主机上跳过容器进程（交给 Docker 扫描器），容器内不跳过
				if ShouldSkipContainerProcess(pid) {
					continue
				}

				exePath := fmt.Sprintf("/proc/%s/exe", pid)
				if realPath, err := os.Readlink(exePath); err == nil {
					// 验证路径存在
					if _, statErr := os.Stat(realPath); statErr == nil {
						return realPath
					}
				}
			}
		}
	}

	return ""
}
