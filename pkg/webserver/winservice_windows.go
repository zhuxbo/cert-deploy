//go:build windows

package webserver

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// FindWebServerService 在 Windows 服务管理器中查找一个二进制路径包含 matchSubstr
// 的服务。匹配大小写不敏感。命中时返回服务名，未命中或出错时返回 ""。
//
// 该函数用于检测 nginx/apache 是否被注册为 Windows 服务（含 nssm/winsw/自带 wrapper），
// 命中后调用方可通过 RestartWindowsService 走标准 SCM 控制路径，避免与 SYSTEM 主进程
// 之间的 OpenEvent 权限错配问题。
func FindWebServerService(matchSubstr string) string {
	if matchSubstr == "" {
		return ""
	}
	needle := strings.ToLower(matchSubstr)

	m, err := mgr.Connect()
	if err != nil {
		return ""
	}
	defer func() { _ = m.Disconnect() }()

	names, err := m.ListServices()
	if err != nil {
		return ""
	}

	// 优先精确名匹配（性能 + 稳定）：常见服务名直接命中即可返回
	lowerNames := make(map[string]string, len(names))
	for _, n := range names {
		lowerNames[strings.ToLower(n)] = n
	}
	if exact, ok := lowerNames[needle]; ok {
		if isServiceMatching(m, exact, needle) {
			return exact
		}
	}

	// 其次扫描所有服务的 BinaryPathName
	for _, name := range names {
		if isServiceMatching(m, name, needle) {
			return name
		}
	}
	return ""
}

// isServiceMatching 打开服务并判断其 BinaryPathName 是否包含 needle（小写）
func isServiceMatching(m *mgr.Mgr, name, needle string) bool {
	s, err := m.OpenService(name)
	if err != nil {
		return false
	}
	defer func() { _ = s.Close() }()
	cfg, err := s.Config()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(cfg.BinaryPathName), needle)
}

// RestartWindowsService 通过 SCM 重启指定服务：先 Stop 并轮询至 Stopped，再 Start。
//
// 等待 Stopped 最多 30 秒，避免 wrapper（如 nginxservice.exe）回收 nginx master 较慢
// 时直接 Start 失败。若服务原本已停止则跳过停止步骤，直接尝试启动。
func RestartWindowsService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("open service %q: %w", name, err)
	}
	defer func() { _ = s.Close() }()

	// 查询当前状态
	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("query service %q: %w", name, err)
	}

	// 若不是 Stopped，则发送 Stop 并轮询
	if st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			// 再次查询，可能恰好已停止
			if st2, qErr := s.Query(); qErr == nil && st2.State == svc.Stopped {
				// fall through to start
			} else {
				return fmt.Errorf("stop service %q: %w", name, err)
			}
		}
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			st, err = s.Query()
			if err != nil {
				return fmt.Errorf("query service %q during stop: %w", name, err)
			}
			if st.State == svc.Stopped {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if st.State != svc.Stopped {
			return fmt.Errorf("service %q did not stop within 30s (state=%d)", name, st.State)
		}
	}

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service %q: %w", name, err)
	}
	return nil
}
