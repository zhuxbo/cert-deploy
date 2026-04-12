package errors

import (
	"fmt"
	"strings"
)

// ServerKind Web 服务器类型（仅用于 PrefixUnknownError 的渲染分支）
type ServerKind string

const (
	ServerKindNginx  ServerKind = "nginx"
	ServerKindApache ServerKind = "apache"
)

// AffectedSite 使用相对路径但无法可靠解析 prefix 的站点
type AffectedSite struct {
	ServerName      string
	ConfigFile      string
	CertificatePath string
	PrivateKeyPath  string
	ChainPath       string // Apache SSLCertificateChainFile
}

// PrefixUnknownError 无法确定 Web 服务器相对路径解析基准（prefix/ServerRoot）时的错误
// 用于在扫描阶段阻断部署，由 CLI 层渲染为用户可读的修复指引
type PrefixUnknownError struct {
	ServerKind ServerKind     // nginx / apache
	BinaryPath string         // nginx.exe / httpd 路径（用于提示）
	Candidates []string       // 常见的 prefix 候选路径（供用户参考）
	Sites      []AffectedSite // 受影响的站点列表
}

func (e *PrefixUnknownError) Error() string {
	kind := string(e.ServerKind)
	if kind == "" {
		kind = "nginx"
	}
	return fmt.Sprintf("%s prefix unknown: %d site(s) use relative paths", kind, len(e.Sites))
}

// RenderHint 渲染用户可读的修复指引文本
// 输出格式与其它 CLI 错误提示保持一致，中止时直接写到 stderr
func (e *PrefixUnknownError) RenderHint() string {
	var b strings.Builder
	b.WriteString("[!] 无法确定 Web 服务器相对路径的解析基准（prefix）\n")
	b.WriteString("\n")

	certLabel, keyLabel, chainLabel := e.directiveLabels()

	b.WriteString("    受影响的站点:\n")
	for _, site := range e.Sites {
		serverName := site.ServerName
		if serverName == "" {
			serverName = "<未命名>"
		}
		if site.ConfigFile != "" {
			fmt.Fprintf(&b, "      %s  (配置文件: %s)\n", serverName, site.ConfigFile)
		} else {
			fmt.Fprintf(&b, "      %s\n", serverName)
		}
		if site.CertificatePath != "" {
			fmt.Fprintf(&b, "        %s %s\n", certLabel, site.CertificatePath)
		}
		if site.PrivateKeyPath != "" {
			fmt.Fprintf(&b, "        %s %s\n", keyLabel, site.PrivateKeyPath)
		}
		if site.ChainPath != "" && chainLabel != "" {
			fmt.Fprintf(&b, "        %s %s\n", chainLabel, site.ChainPath)
		}
	}
	b.WriteString("\n")

	if len(e.Candidates) > 0 {
		b.WriteString("    常用路径:\n")
		for _, c := range e.Candidates {
			fmt.Fprintf(&b, "      %s\n", c)
		}
		b.WriteString("\n")
	}

	b.WriteString("    部署已中止，避免写入错误位置导致静默失败。\n")
	b.WriteString("\n")

	testCmd, flagName := e.testCommandAndFlag()

	b.WriteString("    修复方法 1:\n")
	b.WriteString("      1. 编辑配置文件将证书路径修改为绝对路径\n")
	fmt.Fprintf(&b, "      2. 执行 %s 验证\n", testCmd)
	b.WriteString("      3. 重新运行 sslctl\n")
	b.WriteString("\n")

	b.WriteString("    修复方法 2:\n")
	fmt.Fprintf(&b, "      sslctl scan|setup %s \"<实际 prefix 路径>\" [其它原有参数]\n", flagName)

	return b.String()
}

// directiveLabels 返回对应服务器的配置指令名标签（已对齐）
func (e *PrefixUnknownError) directiveLabels() (cert, key, chain string) {
	if e.ServerKind == ServerKindApache {
		return "SSLCertificateFile      ",
			"SSLCertificateKeyFile   ",
			"SSLCertificateChainFile "
	}
	// nginx 默认
	return "ssl_certificate    ",
		"ssl_certificate_key",
		""
}

// testCommandAndFlag 返回对应服务器的配置测试命令和 CLI 覆盖参数名
func (e *PrefixUnknownError) testCommandAndFlag() (testCmd, flag string) {
	if e.ServerKind == ServerKindApache {
		return "apachectl configtest", "--apache-prefix"
	}
	return "nginx -t", "--nginx-prefix"
}
