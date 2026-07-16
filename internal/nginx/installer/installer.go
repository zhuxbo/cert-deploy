// Package installer 为 Nginx 站点安装 HTTPS 配置
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

// NginxInstaller Nginx HTTPS 安装器
type NginxInstaller struct {
	configPath  string // 站点配置文件路径
	certPath    string // 证书路径
	keyPath     string // 私钥路径
	serverName  string // 服务器名称
	testCommand string // 测试命令
}

// NewNginxInstaller 创建 Nginx 安装器
func NewNginxInstaller(configPath, certPath, keyPath, serverName, testCommand string) *NginxInstaller {
	return &NginxInstaller{
		configPath:  configPath,
		certPath:    certPath,
		keyPath:     keyPath,
		serverName:  serverName,
		testCommand: testCommand,
	}
}

// InstallResult 安装结果
type InstallResult struct {
	BackupPath string // 备份路径
	Modified   bool   // 是否修改了配置
}

// Install 安装 HTTPS 配置
// 在现有 HTTP server 块中添加 SSL 配置
func (i *NginxInstaller) Install() (*InstallResult, error) {
	// 1. 读取配置文件
	content, err := os.ReadFile(i.configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	originalContent := string(content)

	// 2. 先执行注入（addSSLConfig 已具备"按名注入 + 跳过已配 SSL 块"能力），再据结果判定。
	// 不能先用 hasSSLConfig 做全局短路：通配符块已配 SSL（如 *.example.com）会命中谓词，
	// 而目标块（www.example.com，listen 80 无 SSL）仍可注入——短路会静默跳过，
	// 证书写到无人引用的默认路径并误报成功。
	newContent, err := i.addSSLConfig(originalContent)
	if err != nil {
		return nil, fmt.Errorf("生成 SSL 配置失败: %w", err)
	}

	// 3. 无可注入块时区分两种结果：
	// - 匹配目标的块已配置 SSL → 无需安装（Modified=false）
	// - 找不到可处理的 server 块（如非 80 端口、无 HTTP server 块）→ 返回明确错误，
	//   避免调用方误以为"无需安装"而继续部署证书并误报成功（HTTPS 实际未生效），
	//   与 Apache 安装器行为一致
	if newContent == originalContent {
		if i.hasSSLConfig(originalContent) {
			return &InstallResult{Modified: false}, nil
		}
		return nil, fmt.Errorf("未找到可安装 HTTPS 的 server 块（需要 listen 80 且 server_name 匹配 %s 的 HTTP server 块）", i.serverName)
	}

	// 4. 备份原配置（确认要写入后才备份，避免产生无用备份文件）
	backupPath, err := i.backup(originalContent)
	if err != nil {
		return nil, fmt.Errorf("备份配置失败: %w", err)
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

// isServerBlockStart 检测 server 块开始
// 支持 "server {" 和 "server\n{" 两种格式
func isServerBlockStart(line string) (bool, bool) {
	oneLineRe := regexp.MustCompile(`^\s*server\s*\{`)
	serverOnlyRe := regexp.MustCompile(`^\s*server\s*$`)

	if oneLineRe.MatchString(line) {
		return true, false // server 块开始，不需要等下一行的 {
	}
	if serverOnlyRe.MatchString(line) {
		return false, true // 可能是 server 块，需要等下一行的 {
	}
	return false, false
}

// isOpenBrace 检测独立的 { 行
func isOpenBrace(line string) bool {
	return regexp.MustCompile(`^\s*\{\s*$`).MatchString(line)
}

// hasSSLConfig 检查目标 server 块是否已配置 SSL
// 只检查匹配 serverName 的 server 块，而不是整个文件
func (i *NginxInstaller) hasSSLConfig(content string) bool {
	lines := strings.Split(content, "\n")

	serverNameRe := regexp.MustCompile(`^\s*server_name\s+([^;]+);`)
	sslCertRe := regexp.MustCompile(`^\s*ssl_certificate\s+`)

	inServerBlock := false
	pendingServer := false
	braceCount := 0
	currentServerNames := []string{}
	hasSSLInBlock := false

	for _, line := range lines {
		// 跳过注释
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// 等待 { 行（server\n...\n{ 格式，跳过空行）
		if pendingServer {
			if trimmed == "" {
				continue
			}
			pendingServer = false
			if isOpenBrace(line) {
				inServerBlock = true
				braceCount = 1
				currentServerNames = nil
				hasSSLInBlock = false
				continue
			}
		}

		// 检测 server 块开始
		started, pending := isServerBlockStart(line)
		if started {
			inServerBlock = true
			braceCount = 1
			currentServerNames = nil
			hasSSLInBlock = false
			continue
		}
		if pending {
			pendingServer = true
			continue
		}

		if !inServerBlock {
			continue
		}

		// 统计大括号
		braceCount += strings.Count(line, "{") - strings.Count(line, "}")

		// 解析 server_name
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
			names := strings.Fields(matches[1])
			currentServerNames = append(currentServerNames, names...)
		}

		// 检测 SSL 配置
		if sslCertRe.MatchString(line) {
			hasSSLInBlock = true
		}

		// server 块结束
		if braceCount <= 0 {
			// 检查这个 server 块是否匹配目标站点且已有 SSL
			// （与 addSSLConfig 共用 blockMatchesServerName 谓词：lower + 通配符，
			// 避免"精确匹配漏检通配符块已有 SSL → addSSLConfig 二次注入 duplicate listen"）
			if hasSSLInBlock && i.blockMatchesServerName(currentServerNames) {
				return true
			}
			inServerBlock = false
		}
	}

	return false
}

// backup 备份配置文件
func (i *NginxInstaller) backup(content string) (string, error) {
	backupDir := filepath.Dir(i.configPath)
	timestamp := time.Now().Format("20060102-150405")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("%s.%s.bak", filepath.Base(i.configPath), timestamp))

	if err := os.WriteFile(backupPath, []byte(content), 0600); err != nil {
		return "", err
	}

	return backupPath, nil
}

// addSSLConfig 添加 SSL 配置到 server 块
func (i *NginxInstaller) addSSLConfig(content string) (string, error) {
	lines := strings.Split(content, "\n")
	var result []string

	// 状态跟踪
	inServerBlock := false
	pendingServer := false
	braceCount := 0
	hasListen80 := false
	hasIPv6Listen := false
	hasSSLInBlock := false
	listenLineIndex := -1
	ipv6ListenLineIndex := -1
	rootLineIndex := -1
	currentServerNames := []string{}

	// 正则表达式
	listenRe := regexp.MustCompile(`^\s*listen\s+([^;]+);`)
	// 精确匹配端口 80：开头或冒号后是 80，后面是空格、分号或行尾
	listen80Re := regexp.MustCompile(`(?:^|[:\s])80(?:\s|;|$)`)
	ipv6ListenRe := regexp.MustCompile(`\[::\]`)
	rootRe := regexp.MustCompile(`^\s*root\s+`)
	serverNameRe := regexp.MustCompile(`^\s*server_name\s+([^;]+);`)
	sslCertRe := regexp.MustCompile(`^\s*ssl_certificate\s+`)

	for _, line := range lines {
		// 跳过注释行：保留输出，但不参与块解析（不计花括号、不匹配指令）
		// 与 hasSSLConfig 一致，避免注释中的花括号干扰 braceCount 导致 server 块边界错乱
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			result = append(result, line)
			continue
		}

		// 等待 { 行（server\n...\n{ 格式，跳过空行）
		if pendingServer {
			if strings.TrimSpace(line) == "" {
				result = append(result, line)
				continue
			}
			pendingServer = false
			if isOpenBrace(line) {
				inServerBlock = true
				braceCount = 1
				hasListen80 = false
				hasIPv6Listen = false
				hasSSLInBlock = false
				listenLineIndex = -1
				ipv6ListenLineIndex = -1
				rootLineIndex = -1
				currentServerNames = nil
				result = append(result, line)
				continue
			}
		}

		// 检测 server 块开始
		started, pending := isServerBlockStart(line)
		if started {
			inServerBlock = true
			braceCount = 1
			hasListen80 = false
			hasIPv6Listen = false
			hasSSLInBlock = false
			listenLineIndex = -1
			ipv6ListenLineIndex = -1
			rootLineIndex = -1
			currentServerNames = nil
			result = append(result, line)
			continue
		}
		if pending {
			pendingServer = true
			result = append(result, line)
			continue
		}

		if inServerBlock {
			// 统计大括号
			braceCount += strings.Count(line, "{") - strings.Count(line, "}")

			// 检查 listen 指令
			if matches := listenRe.FindStringSubmatch(line); len(matches) > 1 {
				listenValue := strings.TrimSpace(matches[1])
				if listen80Re.MatchString(listenValue) && !strings.Contains(listenValue, "ssl") {
					hasListen80 = true
					listenLineIndex = len(result)
				}
				if ipv6ListenRe.MatchString(listenValue) && !strings.Contains(listenValue, "ssl") {
					hasIPv6Listen = true
					ipv6ListenLineIndex = len(result)
				}
			}

			// 解析 server_name（可能一行多名、跨多行累积）
			if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
				currentServerNames = append(currentServerNames, strings.Fields(matches[1])...)
			}

			// 检测块内已有 SSL 配置（已配 SSL 的块不再注入，防 duplicate listen）
			if sslCertRe.MatchString(line) {
				hasSSLInBlock = true
			}

			// 记录 root 指令位置（仅 server 块顶层 braceCount==1）
			// root 写在 location 内时不能作为 SSL 插入锚点，否则 ssl_certificate 会落入
			// location 块，触发 nginx "ssl_certificate directive is not allowed here"
			if braceCount == 1 && rootRe.MatchString(line) {
				rootLineIndex = len(result)
			}

			// server 块结束
			if braceCount <= 0 {
				// 仅向 server_name 匹配目标站点、且尚未配置 SSL 的块注入：
				// 已有 ssl_certificate 的块（如通配符块已配 SSL 且含 listen 80）再注入
				// 会产生 duplicate listen 443，导致配置测试失败回滚
				if hasListen80 && listenLineIndex >= 0 && !hasSSLInBlock && i.blockMatchesServerName(currentServerNames) {
					// 先插入 SSL 配置（在 root 后或 listen 后），再插入 listen 443（在 listen 80 后）
					// 注意：先插入靠后的，再插入靠前的，避免索引偏移
					sslConfigInsertIndex := rootLineIndex
					if sslConfigInsertIndex < 0 {
						sslConfigInsertIndex = listenLineIndex
					}
					result = i.insertSSLCertDirectives(result, sslConfigInsertIndex)
					// 插入顺序：从后往前，避免索引偏移问题
					// IPv6 listen 443 插入在 IPv6 listen 行后
					if hasIPv6Listen && ipv6ListenLineIndex >= 0 {
						result = i.insertIPv6ListenDirective(result, ipv6ListenLineIndex)
					}
					// listen 443 插入在 listen 80 后
					result = i.insertListenDirectives(result, listenLineIndex)
				}
				inServerBlock = false
			}
		}

		result = append(result, line)
	}

	return strings.Join(result, "\n"), nil
}

// blockMatchesServerName 判断 server 块的 server_name 列表是否命中目标站点。
// 兼容通配符（*.example.com）两侧匹配；无 server_name 的块（default_server 等）不命中，
// 因为扫描器已过滤空/`_` server_name，安装器的 serverName 必为真实域名。
func (i *NginxInstaller) blockMatchesServerName(names []string) bool {
	if i.serverName == "" {
		return false
	}
	target := strings.ToLower(i.serverName)
	for _, name := range names {
		if name == "_" {
			continue
		}
		n := strings.ToLower(name)
		if matcher.MatchDomain(n, target) || matcher.MatchDomain(target, n) {
			return true
		}
	}
	return false
}

// insertListenDirectives 在 listen 80 后插入 listen 443 ssl
func (i *NginxInstaller) insertListenDirectives(lines []string, afterIndex int) []string {
	indent := i.getIndent(lines[afterIndex])
	listenLines := []string{
		fmt.Sprintf("%slisten 443 ssl;", indent),
	}
	return insertLines(lines, afterIndex, listenLines)
}

// insertIPv6ListenDirective 在 IPv6 listen 行后插入 listen [::]:443 ssl
func (i *NginxInstaller) insertIPv6ListenDirective(lines []string, afterIndex int) []string {
	indent := i.getIndent(lines[afterIndex])
	return insertLines(lines, afterIndex, []string{
		fmt.Sprintf("%slisten [::]:443 ssl;", indent),
	})
}

// insertSSLCertDirectives 在 root 后插入 SSL 证书配置（前后加空行）
func (i *NginxInstaller) insertSSLCertDirectives(lines []string, afterIndex int) []string {
	indent := i.getIndent(lines[afterIndex])
	certLines := []string{
		"",
		fmt.Sprintf("%sssl_certificate %s;", indent, i.certPath),
		fmt.Sprintf("%sssl_certificate_key %s;", indent, i.keyPath),
		fmt.Sprintf("%sssl_protocols TLSv1.2 TLSv1.3;", indent),
		fmt.Sprintf("%sssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;", indent),
		fmt.Sprintf("%sssl_prefer_server_ciphers off;", indent),
		"",
	}
	return insertLines(lines, afterIndex, certLines)
}

// insertLines 在指定位置后插入多行
func insertLines(lines []string, afterIndex int, newLines []string) []string {
	result := make([]string, 0, len(lines)+len(newLines))
	result = append(result, lines[:afterIndex+1]...)
	result = append(result, newLines...)
	result = append(result, lines[afterIndex+1:]...)
	return result
}

// getIndent 获取行的缩进
func (i *NginxInstaller) getIndent(line string) string {
	for idx, ch := range line {
		if ch != ' ' && ch != '\t' {
			return line[:idx]
		}
	}
	return ""
}

// testConfig 测试 Nginx 配置
func (i *NginxInstaller) testConfig() error {
	if i.testCommand == "" {
		return nil
	}
	return executor.Run(i.testCommand)
}

// Rollback 回滚到备份
func (i *NginxInstaller) Rollback(backupPath string) error {
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("读取备份文件失败: %w", err)
	}

	if err := os.WriteFile(i.configPath, content, 0600); err != nil {
		return fmt.Errorf("写入配置失败: %w", err)
	}

	return nil
}

// FindHTTPServerBlock 查找 HTTP server 块的配置文件
func FindHTTPServerBlock(configPath, serverName string) (string, error) {
	// 递归查找包含指定 server_name 的配置文件
	return findConfigWithServerName(configPath, serverName)
}

// findConfigWithServerName 递归查找配置文件
func findConfigWithServerName(configPath, serverName string) (string, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	configDir := filepath.Dir(configPath)
	serverNameRe := regexp.MustCompile(`(?i)^\s*server_name\s+([^;]+);`)
	includeRe := regexp.MustCompile(`^\s*include\s+([^;]+);`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// 检查 server_name
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
			names := strings.Fields(matches[1])
			for _, name := range names {
				if name == serverName {
					return configPath, nil
				}
			}
		}

		// 检查 include
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
