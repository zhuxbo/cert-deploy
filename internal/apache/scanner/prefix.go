package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/zhuxbo/sslctl/pkg/util"
)

// prefixOverride 由 CLI 层通过 SetPrefixOverride 设置，对应 --apache-prefix
// 仅在当前进程内生效，不写入配置文件
var (
	prefixOverride   string
	prefixOverrideMu sync.RWMutex
)

// SetPrefixOverride 设置 Apache ServerRoot 显式覆盖值
// 由 CLI 层在解析 --apache-prefix 后调用。传入空字符串等价于清除。
func SetPrefixOverride(prefix string) {
	prefixOverrideMu.Lock()
	defer prefixOverrideMu.Unlock()
	prefixOverride = prefix
}

func getPrefixOverride() string {
	prefixOverrideMu.RLock()
	defer prefixOverrideMu.RUnlock()
	return prefixOverride
}

// processTimeout 进程查找命令超时
const processTimeout = 10 * time.Second

// prefixCandidates 返回 Apache 常见 ServerRoot 候选路径
// 基于 httpd 可执行文件的目录推导（bin/httpd → install 目录 + conf 子目录）
func prefixCandidates(binaryPath string) []string {
	if !filepath.IsAbs(binaryPath) {
		return nil
	}
	binDir := filepath.Dir(binaryPath)             // <install>/bin
	installDir := filepath.Dir(binDir)             // <install>
	return []string{
		installDir + string(filepath.Separator),
		filepath.Join(installDir, "conf") + string(filepath.Separator),
	}
}

// getApachePrefix 以多策略探测 Apache ServerRoot
// 返回：
//   - prefix: 推测的 ServerRoot 目录（空表示未知）
//   - candidates: 常见候选路径（失败时供提示）
//   - ok: 是否可信地确定了 prefix
//
// 策略优先级：显式 override > Scanner 已检测到的 ServerRoot > httpd -V HTTPD_ROOT >
//              运行进程 -d 参数 > error_log 启发式
func (s *Scanner) getApachePrefix(binaryPath string) (prefix string, candidates []string, ok bool) {
	// 1. 显式 override（--apache-prefix）
	if p := getPrefixOverride(); p != "" {
		return p, nil, true
	}

	// 2. Scanner 结构体已填充的 serverRoot（DetectApache 从 httpd -V 读到的）
	if s.serverRoot != "" && filepath.IsAbs(s.serverRoot) {
		return s.serverRoot, nil, true
	}

	// 3. httpd -V HTTPD_ROOT（作为独立入口，适配 scanWithApacheCtl 场景）
	if p := getServerRootFromVersion(); p != "" {
		return p, nil, true
	}

	// 4. 运行进程命令行的 -d 参数
	if p := getServerRootFromProcessCmdline(); p != "" {
		return p, nil, true
	}

	// Linux 走到这里已经无救（httpd -V 都失败），直接报 unknown
	if runtime.GOOS != "windows" {
		return "", nil, false
	}

	candidates = prefixCandidates(binaryPath)
	if len(candidates) == 0 {
		return "", nil, false
	}

	// 5. error_log 启发式探测（Windows 上的兜底）
	//    Apache 启动即创建 logs/error.log，其路径同样受 ServerRoot 影响
	binDir := filepath.Dir(binaryPath)
	installDir := filepath.Dir(binDir)
	if _, err := os.Stat(filepath.Join(installDir, "logs", "error.log")); err == nil {
		return installDir + string(filepath.Separator), candidates, true
	}
	if _, err := os.Stat(filepath.Join(installDir, "logs", "error_log")); err == nil {
		return installDir + string(filepath.Separator), candidates, true
	}
	if _, err := os.Stat(filepath.Join(installDir, "conf", "logs", "error.log")); err == nil {
		return filepath.Join(installDir, "conf") + string(filepath.Separator), candidates, true
	}

	// 全部策略失败
	return "", candidates, false
}

// getServerRootFromVersion 通过 httpd -V 输出解析 HTTPD_ROOT
func getServerRootFromVersion() string {
	binary := findApacheBinary()
	if binary == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), processTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, "-V").CombinedOutput()
	if err != nil && len(output) == 0 {
		return ""
	}
	re := regexp.MustCompile(`HTTPD_ROOT="([^"]+)"`)
	matches := re.FindSubmatch(output)
	if len(matches) <= 1 {
		return ""
	}
	p := strings.TrimSpace(string(matches[1]))
	if p == "" || !filepath.IsAbs(p) {
		return ""
	}
	return p
}

// getServerRootFromProcessCmdline 从运行中的 httpd/apache2 进程命令行解析 -d 参数
// Windows 用 PowerShell Get-CimInstance，Linux 用 /proc/<pid>/cmdline
func getServerRootFromProcessCmdline() string {
	if runtime.GOOS == "windows" {
		return getServerRootFromProcessWindows()
	}
	return getServerRootFromProcessLinux()
}

func getServerRootFromProcessWindows() string {
	ctx, cancel := context.WithTimeout(context.Background(), processTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-CimInstance Win32_Process -Filter \"Name='httpd.exe'\" | Select-Object -ExpandProperty CommandLine -First 1")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return parseServerRootFromCmdline(string(output))
}

func getServerRootFromProcessLinux() string {
	// 通过 ps 拿第一个 httpd/apache2 进程的 pid，然后读 /proc/<pid>/cmdline
	for _, name := range []string{"httpd", "apache2"} {
		ctx, cancel := context.WithTimeout(context.Background(), processTimeout)
		out, err := exec.CommandContext(ctx, "ps", "-C", name, "-o", "pid=").Output()
		cancel()
		if err != nil || len(out) == 0 {
			continue
		}
		pids := strings.Fields(string(out))
		if len(pids) == 0 {
			continue
		}
		pid := pids[0]
		// 宿主机上跳过容器进程（交给 Docker 扫描器），容器内不跳过
		if util.ShouldSkipContainerProcess(pid) {
			continue
		}
		data, err := os.ReadFile("/proc/" + pid + "/cmdline")
		if err != nil {
			continue
		}
		// /proc cmdline 用 NUL 分隔
		cmdline := strings.ReplaceAll(string(data), "\x00", " ")
		if p := parseServerRootFromCmdline(cmdline); p != "" {
			return p
		}
	}
	return ""
}

// parseServerRootFromCmdline 从完整命令行解析 -d 参数值
// 支持 -d value、-d"value"、-d "value" 三种形式
func parseServerRootFromCmdline(cmdline string) string {
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
		return ""
	}
	tokens := tokenizeCmdline(cmdline)
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "-d" && i+1 < len(tokens) {
			return strings.Trim(tokens[i+1], `"'`)
		}
		if strings.HasPrefix(tok, "-d") && len(tok) > 2 {
			return strings.Trim(tok[2:], `"'`)
		}
	}
	return ""
}

// tokenizeCmdline 按空白切分命令行，尊重双引号
func tokenizeCmdline(s string) []string {
	var tokens []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQuote:
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

// hasRelativeCertPath 判断站点的证书/私钥/证书链路径是否存在相对路径
func hasRelativeCertPath(site *Site) bool {
	if site.CertificatePath != "" && !filepath.IsAbs(site.CertificatePath) {
		return true
	}
	if site.PrivateKeyPath != "" && !filepath.IsAbs(site.PrivateKeyPath) {
		return true
	}
	if site.ChainPath != "" && !filepath.IsAbs(site.ChainPath) {
		return true
	}
	return false
}
