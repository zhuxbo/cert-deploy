// Package installer 为 Apache 站点安装 HTTPS 配置
package installer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/internal/executor"
	"github.com/zhuxbo/sslctl/pkg/matcher"
)

// ApacheInstaller Apache HTTPS 安装器
type ApacheInstaller struct {
	configPath  string // 站点配置文件路径
	certPath    string // 证书路径
	keyPath     string // 私钥路径
	chainPath   string // 证书链路径
	serverName  string // 服务器名称
	testCommand string // 测试命令
}

// NewApacheInstaller 创建 Apache 安装器
func NewApacheInstaller(configPath, certPath, keyPath, chainPath, serverName, testCommand string) *ApacheInstaller {
	return &ApacheInstaller{
		configPath:  configPath,
		certPath:    certPath,
		keyPath:     keyPath,
		chainPath:   chainPath,
		serverName:  matcher.StripPort(serverName),
		testCommand: testCommand,
	}
}

// InstallResult 安装结果
type InstallResult struct {
	BackupPath string // 备份路径
	Modified   bool   // 是否修改了配置
}

// Install 安装 HTTPS 配置
// 基于现有 :80 VirtualHost 创建 :443 VirtualHost
func (i *ApacheInstaller) Install() (*InstallResult, error) {
	// 1. 读取配置文件
	content, err := os.ReadFile(i.configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	originalContent := string(content)

	// 2. 检查是否已配置 SSL
	if i.hasSSLConfig(originalContent) {
		return &InstallResult{Modified: false}, nil
	}

	// 3. 备份原配置
	backupPath, err := i.backup(originalContent)
	if err != nil {
		return nil, fmt.Errorf("备份配置失败: %w", err)
	}

	// 4. 生成新配置
	newContent, err := i.addSSLVirtualHost(originalContent)
	if err != nil {
		return nil, fmt.Errorf("生成 SSL 配置失败: %w", err)
	}

	// 5. 写入新配置
	if err := os.WriteFile(i.configPath, []byte(newContent), 0600); err != nil {
		return nil, fmt.Errorf("写入配置失败: %w", err)
	}

	// 6. 测试配置
	if err := i.testConfig(); err != nil {
		// 回滚
		if rollbackErr := os.WriteFile(i.configPath, []byte(originalContent), 0600); rollbackErr != nil {
			return nil, fmt.Errorf("配置测试失败且回滚失败: test=%v, rollback=%v", err, rollbackErr)
		}
		return nil, fmt.Errorf("配置测试失败，已回滚: %w", err)
	}

	return &InstallResult{
		BackupPath: backupPath,
		Modified:   true,
	}, nil
}

// hasSSLConfig 检查目标 VirtualHost 是否已配置 SSL
// 只检查匹配 serverName 的 :443 VirtualHost，而不是整个文件
func (i *ApacheInstaller) hasSSLConfig(content string) bool {
	lines := strings.Split(content, "\n")

	// 正则表达式
	vhostStartRe := regexp.MustCompile(`(?i)^\s*<VirtualHost\s+[^>]*:443[^>]*>`)
	vhostEndRe := regexp.MustCompile(`(?i)^\s*</VirtualHost>`)
	serverNameRe := regexp.MustCompile(`(?i)^\s*ServerName\s+(.+)$`)
	serverAliasRe := regexp.MustCompile(`(?i)^\s*ServerAlias\s+(.+)$`)

	inVhost := false
	serverNames := []string{}

	for _, line := range lines {
		// 检测 :443 VirtualHost 开始
		if vhostStartRe.MatchString(line) {
			inVhost = true
			serverNames = nil
			continue
		}

		if !inVhost {
			continue
		}

		// 解析 ServerName（剥离端口）
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
			name := strings.TrimSpace(matches[1])
			name = matcher.StripPort(strings.Trim(name, `"'`))
			serverNames = append(serverNames, name)
		}

		// 解析 ServerAlias
		if matches := serverAliasRe.FindStringSubmatch(line); len(matches) > 1 {
			aliases := strings.Fields(matches[1])
			for _, alias := range aliases {
				alias = matcher.StripPort(strings.Trim(alias, `"'`))
				serverNames = append(serverNames, alias)
			}
		}

		// VirtualHost 结束
		if vhostEndRe.MatchString(line) {
			// 检查这个 VirtualHost 是否包含目标域名
			for _, name := range serverNames {
				if name == i.serverName {
					return true
				}
			}
			inVhost = false
		}
	}

	return false
}

// backup 备份配置文件
func (i *ApacheInstaller) backup(content string) (string, error) {
	backupDir := filepath.Dir(i.configPath)
	timestamp := time.Now().Format("20060102-150405")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("%s.%s.bak", filepath.Base(i.configPath), timestamp))

	if err := os.WriteFile(backupPath, []byte(content), 0600); err != nil {
		return "", err
	}

	return backupPath, nil
}

// addSSLVirtualHost 添加 SSL VirtualHost
func (i *ApacheInstaller) addSSLVirtualHost(content string) (string, error) {
	// 查找该站点端口恰为 80 的 HTTP VirtualHost
	vhostHTTP, err := i.extractHTTPVirtualHost(content)
	if err != nil {
		return "", err
	}

	if vhostHTTP == "" {
		return "", fmt.Errorf("未找到可安装 HTTPS 的 VirtualHost（需要端口为 80 且 ServerName 匹配 %s 的 VirtualHost）", i.serverName)
	}

	// 生成 :443 VirtualHost
	vhost443 := i.generateSSLVirtualHost(vhostHTTP)

	// 在文件末尾添加
	return content + "\n" + vhost443, nil
}

// extractHTTPVirtualHost 提取该站点端口恰为 80 的 HTTP VirtualHost。
// 仅接受含 :80 地址的 VirtualHost：generateSSLVirtualHost 只把端口 80 改写为 443，
// 若基于 *:8080 等自定义端口生成，会得到端口未改写的伪 SSL 块（SSL 挂在非 443 端口且无 :443 监听），
// 因此非 80 端口一律跳过，找不到时由调用方返回明确错误（与 Nginx 安装器无 80 块即报错的行为一致）。
func (i *ApacheInstaller) extractHTTPVirtualHost(content string) (string, error) {
	lines := strings.Split(content, "\n")
	var result []string
	inVhost := false
	depth := 0

	vhostEndRe := regexp.MustCompile(`(?i)^\s*</VirtualHost>`)
	serverNameRe := regexp.MustCompile(`(?i)^\s*ServerName\s+(.+)$`)

	var currentVhost []string
	foundServerName := false

	for _, line := range lines {
		// 仅接受端口恰为 80 的 VirtualHost 开始标签（复用 swapAddrPort80 的端口判定）
		if !inVhost && virtualHostHasPort80(line) {
			inVhost = true
			depth = 1
			currentVhost = []string{line}
			foundServerName = false
			continue
		}

		if inVhost {
			currentVhost = append(currentVhost, line)

			// 检查嵌套
			if strings.Contains(line, "<") && !strings.Contains(line, "</") {
				depth++
			}
			if strings.Contains(line, "</") {
				depth--
			}

			// 检查 ServerName（剥离端口后比较）
			if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
				serverName := strings.TrimSpace(matches[1])
				serverName = matcher.StripPort(strings.Trim(serverName, `"'`))
				if serverName == i.serverName {
					foundServerName = true
				}
			}

			// VirtualHost 结束
			if vhostEndRe.MatchString(line) {
				if foundServerName {
					result = currentVhost
					break
				}
				inVhost = false
				currentVhost = nil
			}
		}
	}

	return strings.Join(result, "\n"), nil
}

// vhostOpenTagRe 拆分 <VirtualHost ...> 开始标签为前缀、地址列表、后缀三段
var vhostOpenTagRe = regexp.MustCompile(`(?i)^(\s*<VirtualHost\s+)([^>]*?)(\s*>.*)$`)

// replaceVirtualHostPort80 将 <VirtualHost> 开始标签地址列表中端口恰为 80 的地址改为 443，
// 其余端口（如 8080）保持不变；非 VirtualHost 开始行原样返回。
func replaceVirtualHostPort80(line string) string {
	m := vhostOpenTagRe.FindStringSubmatch(line)
	if m == nil {
		return line
	}
	tokens := strings.Fields(m[2])
	for idx, tok := range tokens {
		tokens[idx] = swapAddrPort80(tok)
	}
	return m[1] + strings.Join(tokens, " ") + m[3]
}

// virtualHostHasPort80 判断 <VirtualHost ...> 开始标签的地址列表中是否存在端口恰为 80 的地址。
// 复用 swapAddrPort80 的端口判定：仅端口恰为 80 的地址会被改写，故 swap 后有变化即含 80 端口。
// 非 VirtualHost 开始行返回 false。
func virtualHostHasPort80(line string) bool {
	m := vhostOpenTagRe.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	for _, tok := range strings.Fields(m[2]) {
		if swapAddrPort80(tok) != tok {
			return true
		}
	}
	return false
}

// swapAddrPort80 若地址 token 的端口恰为 80 则替换为 443，否则原样返回。
// 支持 *:80、1.2.3.4:80、[2001:db8::1]:80、example.com:80；*:8080、裸 IPv6 等不受影响。
func swapAddrPort80(token string) string {
	// IPv6 带方括号：端口在 "]:" 之后
	if idx := strings.LastIndex(token, "]:"); idx >= 0 {
		if token[idx+2:] == "80" {
			return token[:idx+2] + "443"
		}
		return token
	}
	// 其余：仅单冒号才视为 host:port（裸 IPv6 多冒号无端口，不动）
	if idx := strings.LastIndex(token, ":"); idx >= 0 && strings.Count(token, ":") == 1 {
		if token[idx+1:] == "80" {
			return token[:idx+1] + "443"
		}
	}
	return token
}

// generateSSLVirtualHost 生成 SSL VirtualHost
func (i *ApacheInstaller) generateSSLVirtualHost(vhost80 string) string {
	lines := strings.Split(vhost80, "\n")
	var result []string

	vhostStartRe := regexp.MustCompile(`(?i)^\s*<VirtualHost`)
	sslInserted := false

	for _, line := range lines {
		// 将 <VirtualHost> 开始标签中端口恰为 80 的地址改为 443（*:8080 等非 80 端口不受影响）
		if vhostStartRe.MatchString(line) {
			line = replaceVirtualHostPort80(line)
		}
		result = append(result, line)

		// 在 VirtualHost 开始后插入 SSL 配置
		if vhostStartRe.MatchString(line) && !sslInserted {
			indent := i.getIndent(line) + "    "
			sslConfig := []string{
				fmt.Sprintf("%sSSLEngine on", indent),
				fmt.Sprintf("%sSSLCertificateFile %s", indent, i.certPath),
				fmt.Sprintf("%sSSLCertificateKeyFile %s", indent, i.keyPath),
			}
			if i.chainPath != "" {
				sslConfig = append(sslConfig, fmt.Sprintf("%sSSLCertificateChainFile %s", indent, i.chainPath))
			}
			sslConfig = append(sslConfig,
				fmt.Sprintf("%sSSLProtocol all -SSLv3 -TLSv1 -TLSv1.1", indent),
			)
			result = append(result, sslConfig...)
			sslInserted = true
		}
	}

	// 添加注释
	header := fmt.Sprintf("\n# SSL VirtualHost for %s - Generated by sslctl\n", i.serverName)

	return header + strings.Join(result, "\n")
}

// getIndent 获取行的缩进
func (i *ApacheInstaller) getIndent(line string) string {
	for idx, ch := range line {
		if ch != ' ' && ch != '\t' {
			return line[:idx]
		}
	}
	return ""
}

// testConfig 测试 Apache 配置
func (i *ApacheInstaller) testConfig() error {
	if i.testCommand == "" {
		return nil
	}
	return executor.Run(i.testCommand)
}

// Rollback 回滚到备份
func (i *ApacheInstaller) Rollback(backupPath string) error {
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("读取备份文件失败: %w", err)
	}

	if err := os.WriteFile(i.configPath, content, 0600); err != nil {
		return fmt.Errorf("写入配置失败: %w", err)
	}

	return nil
}

// FindHTTPVirtualHost 查找 HTTP VirtualHost 的配置文件
func FindHTTPVirtualHost(configPath, serverName string) (string, error) {
	return findConfigWithServerName(configPath, matcher.StripPort(serverName))
}

// findConfigWithServerName 递归查找配置文件
func findConfigWithServerName(configPath, serverName string) (string, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	configDir := filepath.Dir(configPath)
	serverNameRe := regexp.MustCompile(`(?i)^\s*ServerName\s+(.+)$`)
	includeRe := regexp.MustCompile(`(?i)^\s*Include(?:Optional)?\s+(.+)$`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// 检查 ServerName（剥离端口后比较）
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
			name := strings.TrimSpace(matches[1])
			name = matcher.StripPort(strings.Trim(name, `"'`))
			if name == serverName {
				return configPath, nil
			}
		}

		// 检查 Include
		if matches := includeRe.FindStringSubmatch(line); len(matches) > 1 {
			pattern := strings.TrimSpace(matches[1])
			pattern = strings.Trim(pattern, `"'`)

			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(configDir, pattern)
			}

			files, err := filepath.Glob(pattern)
			if err == nil {
				for _, f := range files {
					if result, err := findConfigWithServerName(f, serverName); err == nil && result != "" {
						return result, nil
					}
				}
			}
		}
	}

	return "", nil
}
