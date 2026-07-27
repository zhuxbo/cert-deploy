package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestParseConfigFile(t *testing.T) {
	// 获取 testdata 目录的绝对路径
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取工作目录失败: %v", err)
	}
	testdataPath := filepath.Join(wd, "..", "..", "..", "testdata", "apache", "ssl-site.conf")

	s := NewWithConfig(testdataPath)
	sites, err := s.ScanFile(testdataPath)
	if err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	if len(sites) != 2 {
		t.Errorf("期望解析出 2 个站点，实际 %d", len(sites))
	}

	// 验证第一个站点
	if len(sites) > 0 {
		site := sites[0]
		if site.ServerName != "example.com" {
			t.Errorf("站点1 ServerName 期望 example.com，实际 %s", site.ServerName)
		}
		if site.CertificatePath != "/etc/ssl/certs/example.com.crt" {
			t.Errorf("站点1 证书路径不正确: %s", site.CertificatePath)
		}
		if site.PrivateKeyPath != "/etc/ssl/private/example.com.key" {
			t.Errorf("站点1 私钥路径不正确: %s", site.PrivateKeyPath)
		}
		if site.ChainPath != "/etc/ssl/certs/example.com.chain.crt" {
			t.Errorf("站点1 证书链路径不正确: %s", site.ChainPath)
		}
	}

	// 验证第二个站点
	if len(sites) > 1 {
		site := sites[1]
		if site.ServerName != "test.example.com" {
			t.Errorf("站点2 ServerName 期望 test.example.com，实际 %s", site.ServerName)
		}
		// 第二个站点没有证书链
		if site.ChainPath != "" {
			t.Errorf("站点2 不应该有证书链，实际: %s", site.ChainPath)
		}
	}
}

func TestParseConfigFile_NoSSL(t *testing.T) {
	// 创建临时配置文件（无 SSL）
	content := `
<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	if len(sites) != 0 {
		t.Errorf("期望 0 个 SSL 站点，实际 %d", len(sites))
	}
}

func TestParseConfigFile_SSLEngineOff(t *testing.T) {
	// 测试 SSL 配置但缺少证书文件
	content := `
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/html
    SSLEngine on
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	// 没有证书文件配置，不应该识别为 SSL 站点
	if len(sites) != 0 {
		t.Errorf("期望 0 个 SSL 站点（缺少证书配置），实际 %d", len(sites))
	}
}

func TestParseConfigFile_QuotedPaths(t *testing.T) {
	// 测试带引号的路径
	content := `
<VirtualHost *:443>
    ServerName "example.com"
    DocumentRoot /var/www/html
    SSLEngine on
    SSLCertificateFile "/etc/ssl/certs/example.crt"
    SSLCertificateKeyFile '/etc/ssl/private/example.key'
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个 SSL 站点，实际 %d", len(sites))
	}

	// 路径应该去除引号
	if sites[0].ServerName != "example.com" {
		t.Errorf("ServerName 未正确去除引号: %s", sites[0].ServerName)
	}
	if sites[0].CertificatePath != "/etc/ssl/certs/example.crt" {
		t.Errorf("证书路径未正确去除引号: %s", sites[0].CertificatePath)
	}
	if sites[0].PrivateKeyPath != "/etc/ssl/private/example.key" {
		t.Errorf("私钥路径未正确去除引号: %s", sites[0].PrivateKeyPath)
	}
}

func TestParseConfigFile_Comments(t *testing.T) {
	// 测试注释处理
	content := `
<VirtualHost *:443>
    ServerName example.com
    # SSLCertificateFile /etc/ssl/old.crt
    SSLCertificateFile /etc/ssl/new.crt
    SSLCertificateKeyFile /etc/ssl/new.key
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个 SSL 站点，实际 %d", len(sites))
	}

	// 应该使用非注释的证书路径
	if sites[0].CertificatePath != "/etc/ssl/new.crt" {
		t.Errorf("证书路径应为新路径，实际: %s", sites[0].CertificatePath)
	}
}

func TestParseConfigFile_CaseInsensitive(t *testing.T) {
	// 测试大小写不敏感
	content := `
<virtualhost *:443>
    servername example.com
    sslcertificatefile /etc/ssl/example.crt
    SSLCERTIFICATEKEYFILE /etc/ssl/example.key
</virtualhost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	if len(sites) != 1 {
		t.Errorf("期望 1 个 SSL 站点，实际 %d", len(sites))
	}
}

func TestFindIncludes(t *testing.T) {
	// 创建主配置文件和 include 的文件
	tmpDir, err := os.MkdirTemp("", "apache-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// 创建 include 的配置文件
	includedContent := `
<VirtualHost *:443>
    ServerName included.example.com
    SSLCertificateFile /etc/ssl/included.crt
    SSLCertificateKeyFile /etc/ssl/included.key
</VirtualHost>
`
	includedFile := filepath.Join(tmpDir, "included.conf")
	if err := os.WriteFile(includedFile, []byte(includedContent), 0644); err != nil {
		t.Fatalf("创建 include 文件失败: %v", err)
	}

	// 创建主配置文件
	mainContent := `
<VirtualHost *:443>
    ServerName main.example.com
    SSLCertificateFile /etc/ssl/main.crt
    SSLCertificateKeyFile /etc/ssl/main.key
</VirtualHost>

Include ` + includedFile + `
`
	mainFile := filepath.Join(tmpDir, "httpd.conf")
	if err := os.WriteFile(mainFile, []byte(mainContent), 0644); err != nil {
		t.Fatalf("创建主配置文件失败: %v", err)
	}

	s := NewWithConfig(mainFile)
	sites, err := s.Scan()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	// 应该找到两个站点
	if len(sites) != 2 {
		t.Errorf("期望 2 个站点，实际 %d", len(sites))
	}
}

func TestFindIncludes_IncludeOptional(t *testing.T) {
	// 测试 IncludeOptional 指令
	tmpDir, err := os.MkdirTemp("", "apache-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// 创建主配置文件（引用不存在的文件）
	mainContent := `
<VirtualHost *:443>
    ServerName main.example.com
    SSLCertificateFile /etc/ssl/main.crt
    SSLCertificateKeyFile /etc/ssl/main.key
</VirtualHost>

IncludeOptional ` + filepath.Join(tmpDir, "nonexistent.conf") + `
`
	mainFile := filepath.Join(tmpDir, "httpd.conf")
	if err := os.WriteFile(mainFile, []byte(mainContent), 0644); err != nil {
		t.Fatalf("创建主配置文件失败: %v", err)
	}

	s := NewWithConfig(mainFile)
	sites, err := s.Scan()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	// 应该找到一个站点（IncludeOptional 不存在不报错）
	if len(sites) != 1 {
		t.Errorf("期望 1 个站点，实际 %d", len(sites))
	}
}

func TestGetCommonApachePaths(t *testing.T) {
	paths := getCommonApachePaths()
	if len(paths) == 0 {
		t.Error("应该返回至少一个常见路径")
	}
}

func TestListenPort(t *testing.T) {
	// 测试监听端口解析
	content := `
<VirtualHost 192.168.1.1:8443>
    ServerName example.com
    SSLCertificateFile /etc/ssl/example.crt
    SSLCertificateKeyFile /etc/ssl/example.key
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个 SSL 站点，实际 %d", len(sites))
	}

	if sites[0].ListenPort != "192.168.1.1:8443" {
		t.Errorf("ListenPort 期望 192.168.1.1:8443，实际 %s", sites[0].ListenPort)
	}
}

// TestParseConfigFile_ServerAlias 测试 ServerAlias 多域名
func TestParseConfigFile_ServerAlias(t *testing.T) {
	content := `
<VirtualHost *:443>
    ServerName example.com
    ServerAlias www.example.com api.example.com
    ServerAlias admin.example.com
    SSLCertificateFile /etc/ssl/example.crt
    SSLCertificateKeyFile /etc/ssl/example.key
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.WriteString(content)
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个站点，实际 %d", len(sites))
	}

	if sites[0].ServerName != "example.com" {
		t.Errorf("ServerName 期望 example.com，实际 %s", sites[0].ServerName)
	}

	// 应该有 3 个别名
	if len(sites[0].ServerAlias) != 3 {
		t.Errorf("期望 3 个 ServerAlias，实际 %d: %v", len(sites[0].ServerAlias), sites[0].ServerAlias)
	}
}

// TestParseConfigFile_SSLEngine 测试 SSLEngine on 检测
func TestParseConfigFile_SSLEngine(t *testing.T) {
	content := `
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/example.crt
    SSLCertificateKeyFile /etc/ssl/example.key
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.WriteString(content)
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if len(sites) != 1 {
		t.Errorf("期望 1 个 SSL 站点，实际 %d", len(sites))
	}
}

// TestScanAll_MixedVHosts 测试混合 SSL/非 SSL VirtualHost
func TestScanAll_MixedVHosts(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "apache-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
# HTTP 站点
<VirtualHost *:80>
    ServerName http.example.com
    DocumentRoot /var/www/http
</VirtualHost>

# HTTPS 站点
<VirtualHost *:443>
    ServerName ssl.example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/ssl.crt
    SSLCertificateKeyFile /etc/ssl/ssl.key
</VirtualHost>

# 另一个 HTTP 站点
<VirtualHost *:80>
    ServerName http2.example.com
    DocumentRoot /var/www/http2
</VirtualHost>
`
	mainFile := filepath.Join(tmpDir, "httpd.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	sites, err := s.ScanAll()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	// 应该找到所有 3 个站点
	if len(sites) != 3 {
		t.Errorf("期望 3 个站点，实际 %d", len(sites))
	}

	// 验证 SSL 标记
	sslCount := 0
	for _, site := range sites {
		if site.HasSSL {
			sslCount++
		}
	}
	if sslCount != 1 {
		t.Errorf("期望 1 个 SSL 站点，实际 %d", sslCount)
	}
}

// TestFindByDomain_WildcardMatch 测试通配符域名匹配
func TestFindByDomain_WildcardMatch(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "apache-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
<VirtualHost *:443>
    ServerName example.com
    ServerAlias *.example.com
    SSLCertificateFile /etc/ssl/wildcard.crt
    SSLCertificateKeyFile /etc/ssl/wildcard.key
</VirtualHost>
<VirtualHost *:443>
    ServerName specific.test.com
    SSLCertificateFile /etc/ssl/specific.crt
    SSLCertificateKeyFile /etc/ssl/specific.key
</VirtualHost>
`
	mainFile := filepath.Join(tmpDir, "httpd.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)

	tests := []struct {
		domain string
		expect string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"api.example.com", "example.com"},
		{"specific.test.com", "specific.test.com"},
	}

	for _, tt := range tests {
		// 重置扫描状态
		s.scannedFiles = make(map[string]bool)
		site, err := s.FindByDomain(tt.domain)
		if err != nil {
			t.Errorf("FindByDomain(%s) 错误: %v", tt.domain, err)
			continue
		}
		if site == nil {
			t.Errorf("FindByDomain(%s) 未找到站点", tt.domain)
			continue
		}
		if site.ServerName != tt.expect {
			t.Errorf("FindByDomain(%s) = %s，期望 %s", tt.domain, site.ServerName, tt.expect)
		}
	}
}

// TestParseConfigFile_ChainFile 测试证书链文件解析
func TestParseConfigFile_ChainFile(t *testing.T) {
	content := `
<VirtualHost *:443>
    ServerName example.com
    SSLCertificateFile /etc/ssl/example.crt
    SSLCertificateKeyFile /etc/ssl/example.key
    SSLCertificateChainFile /etc/ssl/chain.crt
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.WriteString(content)
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个站点，实际 %d", len(sites))
	}

	if sites[0].ChainPath != "/etc/ssl/chain.crt" {
		t.Errorf("ChainPath 期望 /etc/ssl/chain.crt，实际 %s", sites[0].ChainPath)
	}
}

// TestParseConfigFile_DocumentRoot 测试 DocumentRoot 解析
func TestParseConfigFile_DocumentRoot(t *testing.T) {
	content := `
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/example
    SSLCertificateFile /etc/ssl/example.crt
    SSLCertificateKeyFile /etc/ssl/example.key
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.WriteString(content)
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个站点，实际 %d", len(sites))
	}

	if sites[0].Webroot != "/var/www/example" {
		t.Errorf("Webroot 期望 /var/www/example，实际 %s", sites[0].Webroot)
	}
}

// TestHasSSLConfig 测试 SSL 配置检测
func TestHasSSLConfig(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "有 SSLEngine on",
			content: `
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
</VirtualHost>`,
			want: true,
		},
		{
			name: "有 SSLCertificateFile",
			content: `
<VirtualHost *:443>
    ServerName example.com
    SSLCertificateFile /etc/ssl/cert.crt
</VirtualHost>`,
			want: true,
		},
		{
			name: "无 SSL 配置",
			content: `
<VirtualHost *:80>
    ServerName example.com
</VirtualHost>`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
			if err != nil {
				t.Fatalf("创建临时文件失败: %v", err)
			}
			defer func() { _ = os.Remove(tmpFile.Name()) }()
			_, _ = tmpFile.WriteString(tt.content)
			_ = tmpFile.Close()

			s := NewWithConfig(tmpFile.Name())
			got := s.HasSSLConfig(tmpFile.Name())
			if got != tt.want {
				t.Errorf("HasSSLConfig() = %v，期望 %v", got, tt.want)
			}
		})
	}
}

// TestScanHTTPSites 测试 HTTP 站点扫描
func TestScanHTTPSites(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "apache-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
<VirtualHost *:80>
    ServerName http1.example.com
    DocumentRoot /var/www/http1
</VirtualHost>
<VirtualHost *:443>
    ServerName ssl.example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/cert.crt
    SSLCertificateKeyFile /etc/ssl/cert.key
</VirtualHost>
<VirtualHost *:80>
    ServerName http2.example.com
    DocumentRoot /var/www/http2
</VirtualHost>
`
	mainFile := filepath.Join(tmpDir, "httpd.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	sites, err := s.ScanHTTPSites()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	// 应该找到 2 个 HTTP 站点（排除 SSL）
	if len(sites) != 2 {
		t.Errorf("期望 2 个 HTTP 站点，实际 %d", len(sites))
	}
}

// TestSetDebug 测试调试模式设置
func TestSetDebug(t *testing.T) {
	s := New()

	var logOutput string
	logFn := func(format string, args ...interface{}) {
		logOutput = format
	}

	s.SetDebug(true, logFn)
	s.logDebug("test message")

	if logOutput != "test message" {
		t.Errorf("调试日志未正确输出")
	}

	// 关闭调试模式
	s.SetDebug(false, nil)
	logOutput = ""
	s.logDebug("should not appear")

	if logOutput != "" {
		t.Errorf("调试模式关闭后不应有输出")
	}
}

// TestFindIncludes_GlobPattern 测试 glob 模式的 Include
func TestFindIncludes_GlobPattern(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "apache-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// 创建 sites-enabled 目录和多个配置文件
	sitesDir := filepath.Join(tmpDir, "sites-enabled")
	_ = os.MkdirAll(sitesDir, 0755)

	site1 := `
<VirtualHost *:443>
    ServerName site1.example.com
    SSLCertificateFile /etc/ssl/site1.crt
    SSLCertificateKeyFile /etc/ssl/site1.key
</VirtualHost>
`
	site2 := `
<VirtualHost *:443>
    ServerName site2.example.com
    SSLCertificateFile /etc/ssl/site2.crt
    SSLCertificateKeyFile /etc/ssl/site2.key
</VirtualHost>
`
	_ = os.WriteFile(filepath.Join(sitesDir, "site1.conf"), []byte(site1), 0644)
	_ = os.WriteFile(filepath.Join(sitesDir, "site2.conf"), []byte(site2), 0644)

	// 主配置使用 glob 模式
	mainContent := "Include " + sitesDir + "/*.conf"
	mainFile := filepath.Join(tmpDir, "httpd.conf")
	_ = os.WriteFile(mainFile, []byte(mainContent), 0644)

	s := NewWithConfig(mainFile)
	sites, err := s.Scan()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	if len(sites) != 2 {
		t.Errorf("期望 2 个站点（通过 glob 模式包含），实际 %d", len(sites))
	}
}

// TestScan_CircularInclude 测试循环 Include 处理
func TestScan_CircularInclude(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "apache-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// 创建循环 Include
	file1 := filepath.Join(tmpDir, "a.conf")
	file2 := filepath.Join(tmpDir, "b.conf")

	content1 := `
<VirtualHost *:443>
    ServerName a.example.com
    SSLCertificateFile /etc/ssl/a.crt
    SSLCertificateKeyFile /etc/ssl/a.key
</VirtualHost>
Include ` + file2 + `
`
	content2 := `
<VirtualHost *:443>
    ServerName b.example.com
    SSLCertificateFile /etc/ssl/b.crt
    SSLCertificateKeyFile /etc/ssl/b.key
</VirtualHost>
Include ` + file1 + `
`
	_ = os.WriteFile(file1, []byte(content1), 0644)
	_ = os.WriteFile(file2, []byte(content2), 0644)

	s := NewWithConfig(file1)
	sites, err := s.Scan()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	// 应该正确处理循环引用，找到 2 个站点
	if len(sites) != 2 {
		t.Errorf("期望 2 个站点（循环引用被正确处理），实际 %d", len(sites))
	}
}

// TestParseConfigFile_NestedDirectoryBlocks 测试嵌套的 Directory 块
func TestParseConfigFile_NestedDirectoryBlocks(t *testing.T) {
	content := `
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/example
    SSLCertificateFile /etc/ssl/example.crt
    SSLCertificateKeyFile /etc/ssl/example.key

    <Directory /var/www/example>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    <Location /admin>
        Require user admin
    </Location>
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.WriteString(content)
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个站点，实际 %d", len(sites))
	}

	if sites[0].ServerName != "example.com" {
		t.Errorf("ServerName 期望 example.com，实际 %s", sites[0].ServerName)
	}
}

// TestParseConfigFile_QuotedAngleBracket 测试引号内 < 不会被误判为嵌套标签
func TestParseConfigFile_QuotedAngleBracket(t *testing.T) {
	content := `
<VirtualHost *:443>
    ServerName example.com
    SSLCertificateFile /etc/ssl/example.crt
    SSLCertificateKeyFile /etc/ssl/example.key
    ErrorDocument 404 "<html><body>Not Found</body></html>"
    <Directory /var/www/example>
        Options Indexes
    </Directory>
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.WriteString(content)
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个站点，实际 %d", len(sites))
	}

	if sites[0].ServerName != "example.com" {
		t.Errorf("ServerName 期望 example.com，实际 %s", sites[0].ServerName)
	}
}

// TestGetConfigPath 测试获取配置路径
func TestGetConfigPath(t *testing.T) {
	s := NewWithConfig("/etc/apache2/httpd.conf")
	if s.GetConfigPath() != "/etc/apache2/httpd.conf" {
		t.Errorf("GetConfigPath() = %s，期望 /etc/apache2/httpd.conf", s.GetConfigPath())
	}
}

// TestParseConfigFile_MissingCertOrKey 测试缺少证书或私钥
func TestParseConfigFile_MissingCertOrKey(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{
			name: "只有证书，没有私钥",
			content: `
<VirtualHost *:443>
    ServerName example.com
    SSLCertificateFile /etc/ssl/cert.crt
</VirtualHost>`,
			want: 0,
		},
		{
			name: "只有私钥，没有证书",
			content: `
<VirtualHost *:443>
    ServerName example.com
    SSLCertificateKeyFile /etc/ssl/cert.key
</VirtualHost>`,
			want: 0,
		},
		{
			name: "完整的 SSL 配置",
			content: `
<VirtualHost *:443>
    ServerName example.com
    SSLCertificateFile /etc/ssl/cert.crt
    SSLCertificateKeyFile /etc/ssl/cert.key
</VirtualHost>`,
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
			if err != nil {
				t.Fatalf("创建临时文件失败: %v", err)
			}
			defer func() { _ = os.Remove(tmpFile.Name()) }()
			_, _ = tmpFile.WriteString(tt.content)
			_ = tmpFile.Close()

			s := NewWithConfig(tmpFile.Name())
			sites, err := s.ScanFile(tmpFile.Name())
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if len(sites) != tt.want {
				t.Errorf("期望 %d 个站点，实际 %d", tt.want, len(sites))
			}
		})
	}
}

// TestScanConfigFile_DeepInclude 测试多层嵌套 Include 正确递归处理
func TestScanConfigFile_DeepInclude(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建 3 层嵌套: main.conf → level1.conf → level2.conf
	level2 := filepath.Join(tmpDir, "level2.conf")
	_ = os.WriteFile(level2, []byte(`
<VirtualHost *:443>
    ServerName deep.example.com
    SSLCertificateFile /etc/ssl/deep.crt
    SSLCertificateKeyFile /etc/ssl/deep.key
</VirtualHost>
`), 0644)

	level1 := filepath.Join(tmpDir, "level1.conf")
	_ = os.WriteFile(level1, []byte(`
<VirtualHost *:443>
    ServerName mid.example.com
    SSLCertificateFile /etc/ssl/mid.crt
    SSLCertificateKeyFile /etc/ssl/mid.key
</VirtualHost>
Include `+level2+`
`), 0644)

	main := filepath.Join(tmpDir, "main.conf")
	_ = os.WriteFile(main, []byte(`
<VirtualHost *:443>
    ServerName top.example.com
    SSLCertificateFile /etc/ssl/top.crt
    SSLCertificateKeyFile /etc/ssl/top.key
</VirtualHost>
Include `+level1+`
`), 0644)

	s := NewWithConfig(main)
	sites, err := s.Scan()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	if len(sites) != 3 {
		t.Errorf("期望 3 个站点（3 层嵌套），实际 %d", len(sites))
		for _, site := range sites {
			t.Logf("  站点: %s", site.ServerName)
		}
	}
}

// TestScanConfigFile_MaxFilesLimit 测试 maxScanFiles 限制正确截断扫描
func TestScanConfigFile_MaxFilesLimit(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建 main.conf 包含大量 Include
	var includes string
	fileCount := maxScanFiles + 10 // 超出限制
	for i := 0; i < fileCount; i++ {
		confPath := filepath.Join(tmpDir, "site"+filepath.Base(t.Name())+string(rune('A'+i%26))+string(rune('0'+i/26))+".conf")
		content := `
<VirtualHost *:443>
    ServerName site` + filepath.Base(confPath) + `.example.com
    SSLCertificateFile /etc/ssl/` + filepath.Base(confPath) + `.crt
    SSLCertificateKeyFile /etc/ssl/` + filepath.Base(confPath) + `.key
</VirtualHost>
`
		_ = os.WriteFile(confPath, []byte(content), 0644)
		includes += "Include " + confPath + "\n"
	}

	mainConf := filepath.Join(tmpDir, "main.conf")
	_ = os.WriteFile(mainConf, []byte(includes), 0644)

	s := NewWithConfig(mainConf)
	sites, err := s.Scan()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	// 应该被 maxScanFiles 截断，站点数不超过 maxScanFiles
	if len(s.scannedFiles) > maxScanFiles {
		t.Errorf("扫描文件数 %d 超过限制 %d", len(s.scannedFiles), maxScanFiles)
	}

	// 应该找到一些站点但不是全部
	if len(sites) >= fileCount {
		t.Errorf("站点数 %d 应小于总文件数 %d（被截断）", len(sites), fileCount)
	}
	if len(sites) == 0 {
		t.Error("应至少找到一些站点")
	}
}

// TestGetApacheConfigRegex 测试 getApacheConfigFromCommand 中使用的正则解析逻辑
// 由于该函数依赖 exec.Command，这里直接测试正则匹配和路径拼接逻辑
func TestGetApacheConfigRegex(t *testing.T) {
	rootRe := regexp.MustCompile(`HTTPD_ROOT="([^"]+)"`)
	configRe := regexp.MustCompile(`SERVER_CONFIG_FILE="([^"]+)"`)

	tests := []struct {
		name       string
		output     string
		wantRoot   string
		wantConfig string
		wantAbs    bool   // configFile 是否为绝对路径
		wantPath   string // 最终拼接后的路径（相对路径时 root + config）
	}{
		{
			name: "Debian/Ubuntu 标准输出（相对路径）",
			output: `Server version: Apache/2.4.52 (Ubuntu)
Server built:   2023-01-01T00:00:00
 -D HTTPD_ROOT="/etc/apache2"
 -D SERVER_CONFIG_FILE="apache2.conf"
 -D DEFAULT_PIDLOG="logs/httpd.pid"`,
			wantRoot:   "/etc/apache2",
			wantConfig: "apache2.conf",
			wantAbs:    false,
			wantPath:   "/etc/apache2/apache2.conf",
		},
		{
			name: "CentOS/RHEL 标准输出（相对路径含子目录）",
			output: `Server version: Apache/2.4.6 (CentOS)
 -D HTTPD_ROOT="/etc/httpd"
 -D SERVER_CONFIG_FILE="conf/httpd.conf"
 -D AP_TYPES_CONFIG_FILE="conf/mime.types"`,
			wantRoot:   "/etc/httpd",
			wantConfig: "conf/httpd.conf",
			wantAbs:    false,
			wantPath:   "/etc/httpd/conf/httpd.conf",
		},
		{
			name: "绝对路径 SERVER_CONFIG_FILE",
			output: `Server version: Apache/2.4.52
 -D HTTPD_ROOT="/etc/apache2"
 -D SERVER_CONFIG_FILE="/opt/apache/httpd.conf"`,
			wantRoot:   "/etc/apache2",
			wantConfig: "/opt/apache/httpd.conf",
			wantAbs:    true,
			wantPath:   "/opt/apache/httpd.conf",
		},
		{
			name:       "无匹配项",
			output:     "Server version: Apache/2.4.52\nSome other output",
			wantRoot:   "",
			wantConfig: "",
		},
		{
			name: "只有 HTTPD_ROOT 没有 SERVER_CONFIG_FILE",
			output: `Server version: Apache/2.4.52
 -D HTTPD_ROOT="/etc/apache2"`,
			wantRoot:   "/etc/apache2",
			wantConfig: "",
		},
		{
			name: "只有 SERVER_CONFIG_FILE 没有 HTTPD_ROOT（相对路径）",
			output: `Server version: Apache/2.4.52
 -D SERVER_CONFIG_FILE="conf/httpd.conf"`,
			wantRoot:   "",
			wantConfig: "conf/httpd.conf",
			wantAbs:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := []byte(tt.output)

			var serverRoot, configFile string

			if matches := rootRe.FindSubmatch(output); len(matches) > 1 {
				serverRoot = string(matches[1])
			}
			if matches := configRe.FindSubmatch(output); len(matches) > 1 {
				configFile = string(matches[1])
			}

			if serverRoot != tt.wantRoot {
				t.Errorf("HTTPD_ROOT = %q，期望 %q", serverRoot, tt.wantRoot)
			}
			if configFile != tt.wantConfig {
				t.Errorf("SERVER_CONFIG_FILE = %q，期望 %q", configFile, tt.wantConfig)
			}

			// 测试路径拼接逻辑
			if configFile != "" && tt.wantPath != "" {
				var configPath string
				if filepath.IsAbs(configFile) {
					configPath = configFile
					if !tt.wantAbs {
						t.Error("configFile 应为相对路径但被判为绝对路径")
					}
				} else if serverRoot != "" {
					configPath = filepath.Join(serverRoot, configFile)
					if tt.wantAbs {
						t.Error("configFile 应为绝对路径但被判为相对路径")
					}
				}
				if configPath != tt.wantPath {
					t.Errorf("拼接路径 = %q，期望 %q", configPath, tt.wantPath)
				}
			}

			// 测试边界情况：相对路径但无 HTTPD_ROOT
			if configFile != "" && !filepath.IsAbs(configFile) && serverRoot == "" {
				// 应该返回错误 "无法确定配置文件绝对路径"
				t.Logf("边界情况：相对路径 %q 无 HTTPD_ROOT，生产代码会返回错误", configFile)
			}
		})
	}
}

// TestGetApacheConfigFromCommand_WithRealFile 测试完整的路径解析+文件存在检查逻辑
func TestGetApacheConfigFromCommand_WithRealFile(t *testing.T) {
	// 模拟 getApacheConfigFromCommand 的路径解析逻辑（跳过 exec.Command 部分）
	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "conf", "httpd.conf")
	_ = os.MkdirAll(filepath.Dir(confPath), 0755)
	_ = os.WriteFile(confPath, []byte("# test"), 0644)

	// 模拟相对路径拼接场景
	serverRoot := tmpDir
	configFile := "conf/httpd.conf"

	var resultPath string
	if filepath.IsAbs(configFile) {
		resultPath = configFile
	} else if serverRoot != "" {
		resultPath = filepath.Join(serverRoot, configFile)
	}

	if resultPath != confPath {
		t.Errorf("路径拼接结果 = %q，期望 %q", resultPath, confPath)
	}

	// 验证文件存在
	if _, err := os.Stat(resultPath); err != nil {
		t.Errorf("文件应该存在: %v", err)
	}

	// 模拟绝对路径场景
	absConfigFile := confPath
	if !filepath.IsAbs(absConfigFile) {
		t.Error("绝对路径判断失败")
	}
}

// TestScanWithApacheCtlRegex 测试 scanWithApacheCtl 中使用的正则解析
func TestScanWithApacheCtlRegex(t *testing.T) {
	vhostRe := regexp.MustCompile(`port\s+(\d+)\s+namevhost\s+(\S+)\s+\(([^:]+):(\d+)\)`)

	tests := []struct {
		name       string
		output     string
		wantSites  int
		wantChecks []struct {
			serverName string
			port       string
			configFile string
			hasSSL     bool
		}
	}{
		{
			name: "标准 apachectl -S 输出",
			output: `VirtualHost configuration:
*:80                   is a NameVirtualHost
         default server example.com (/etc/apache2/sites-enabled/example.conf:1)
         port 80 namevhost example.com (/etc/apache2/sites-enabled/example.conf:1)
         port 80 namevhost blog.example.com (/etc/apache2/sites-enabled/blog.conf:1)
*:443                  is a NameVirtualHost
         default server example.com (/etc/apache2/sites-enabled/example-ssl.conf:2)
         port 443 namevhost example.com (/etc/apache2/sites-enabled/example-ssl.conf:2)
         port 443 namevhost blog.example.com (/etc/apache2/sites-enabled/blog-ssl.conf:2)
ServerRoot: "/etc/apache2"`,
			wantSites: 4,
			wantChecks: []struct {
				serverName string
				port       string
				configFile string
				hasSSL     bool
			}{
				{"example.com", "80", "/etc/apache2/sites-enabled/example.conf", false},
				{"blog.example.com", "80", "/etc/apache2/sites-enabled/blog.conf", false},
				{"example.com", "443", "/etc/apache2/sites-enabled/example-ssl.conf", true},
				{"blog.example.com", "443", "/etc/apache2/sites-enabled/blog-ssl.conf", true},
			},
		},
		{
			name: "只有 HTTP 站点",
			output: `*:80                   is a NameVirtualHost
         port 80 namevhost only-http.com (/etc/apache2/sites-enabled/http.conf:1)`,
			wantSites: 1,
			wantChecks: []struct {
				serverName string
				port       string
				configFile string
				hasSSL     bool
			}{
				{"only-http.com", "80", "/etc/apache2/sites-enabled/http.conf", false},
			},
		},
		{
			name:      "空输出",
			output:    "",
			wantSites: 0,
		},
		{
			name: "无匹配行（只有 default server）",
			output: `*:80                   is a NameVirtualHost
         default server example.com (/etc/apache2/sites-enabled/example.conf:1)`,
			wantSites: 0,
		},
		{
			name: "同一站点多端口（HTTP + HTTPS）合并为同一 key",
			output: `         port 80 namevhost multi.example.com (/etc/apache2/sites-enabled/multi.conf:1)
         port 443 namevhost multi.example.com (/etc/apache2/sites-enabled/multi.conf:1)`,
			wantSites: 1, // 合并为一个站点（同 serverName + configFile）
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 模拟 scanWithApacheCtl 的解析逻辑
			siteMap := make(map[string]*Site)

			lines := strings.Split(tt.output, "\n")
			for _, line := range lines {
				if matches := vhostRe.FindStringSubmatch(line); len(matches) > 4 {
					port := matches[1]
					serverName := matches[2]
					configFile := matches[3]

					key := serverName + ":" + configFile
					site, exists := siteMap[key]
					if !exists {
						site = &Site{
							ServerName: serverName,
							ConfigFile: configFile,
						}
						siteMap[key] = site
					}

					portStr := port
					if port == "443" {
						portStr = "443 ssl"
						site.HasSSL = true
					}
					site.ListenPorts = append(site.ListenPorts, portStr)
				}
			}

			if len(siteMap) != tt.wantSites {
				t.Errorf("站点数 = %d，期望 %d", len(siteMap), tt.wantSites)
			}

			// 验证具体站点
			for _, check := range tt.wantChecks {
				key := check.serverName + ":" + check.configFile
				site, exists := siteMap[key]
				if !exists {
					t.Errorf("未找到站点 %s", key)
					continue
				}
				if site.HasSSL != check.hasSSL {
					t.Errorf("站点 %s HasSSL = %v，期望 %v", key, site.HasSSL, check.hasSSL)
				}
			}
		})
	}
}

// TestFindAllByDomain 测试根据域名查找所有站点（包括非 SSL）
func TestFindAllByDomain(t *testing.T) {
	tmpDir := t.TempDir()

	content := `
# HTTP 站点
<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/example
</VirtualHost>

# HTTPS 站点
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/example.crt
    SSLCertificateKeyFile /etc/ssl/example.key
</VirtualHost>

# 通配符别名
<VirtualHost *:80>
    ServerName wildcard.example.com
    ServerAlias *.wildcard.example.com
    DocumentRoot /var/www/wildcard
</VirtualHost>

# 另一个完全不同的域名
<VirtualHost *:80>
    ServerName other.net
    DocumentRoot /var/www/other
</VirtualHost>
`
	mainFile := filepath.Join(tmpDir, "httpd.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	tests := []struct {
		name       string
		domain     string
		wantFound  bool
		wantServer string
	}{
		{"精确匹配 HTTP 站点", "example.com", true, "example.com"},
		{"精确匹配其他站点", "other.net", true, "other.net"},
		{"通配符匹配别名", "sub.wildcard.example.com", true, "wildcard.example.com"},
		{"精确匹配通配符站点", "wildcard.example.com", true, "wildcard.example.com"},
		{"不存在的域名", "nonexistent.com", false, ""},
		{"大小写不敏感", "Example.COM", true, "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewWithConfig(mainFile)
			site, err := s.FindAllByDomain(tt.domain)
			if err != nil {
				t.Fatalf("FindAllByDomain(%q) 错误: %v", tt.domain, err)
			}
			if tt.wantFound {
				if site == nil {
					t.Errorf("FindAllByDomain(%q) 未找到站点", tt.domain)
					return
				}
				if site.ServerName != tt.wantServer {
					t.Errorf("FindAllByDomain(%q) ServerName = %q，期望 %q", tt.domain, site.ServerName, tt.wantServer)
				}
			} else {
				if site != nil {
					t.Errorf("FindAllByDomain(%q) 不应找到站点，但找到了 %q", tt.domain, site.ServerName)
				}
			}
		})
	}
}

// TestFindAllByDomain_SSLDetails 测试 FindAllByDomain 返回的站点包含 SSL 详情
func TestFindAllByDomain_SSLDetails(t *testing.T) {
	tmpDir := t.TempDir()

	content := `
<VirtualHost *:443>
    ServerName ssl-detail.example.com
    ServerAlias www.ssl-detail.example.com
    DocumentRoot /var/www/ssl-detail
    SSLEngine on
    SSLCertificateFile /etc/ssl/detail.crt
    SSLCertificateKeyFile /etc/ssl/detail.key
    SSLCertificateChainFile /etc/ssl/detail-chain.crt
</VirtualHost>
`
	mainFile := filepath.Join(tmpDir, "httpd.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	site, err := s.FindAllByDomain("ssl-detail.example.com")
	if err != nil {
		t.Fatalf("FindAllByDomain 错误: %v", err)
	}
	if site == nil {
		t.Fatal("FindAllByDomain 未找到站点")
	}

	if !site.HasSSL {
		t.Error("站点应标记为 HasSSL = true")
	}
	if site.CertificatePath != "/etc/ssl/detail.crt" {
		t.Errorf("CertificatePath = %q，期望 /etc/ssl/detail.crt", site.CertificatePath)
	}
	if site.PrivateKeyPath != "/etc/ssl/detail.key" {
		t.Errorf("PrivateKeyPath = %q，期望 /etc/ssl/detail.key", site.PrivateKeyPath)
	}
	if site.ChainPath != "/etc/ssl/detail-chain.crt" {
		t.Errorf("ChainPath = %q，期望 /etc/ssl/detail-chain.crt", site.ChainPath)
	}
	if site.Webroot != "/var/www/ssl-detail" {
		t.Errorf("Webroot = %q，期望 /var/www/ssl-detail", site.Webroot)
	}
}

// TestFindAllByDomain_ViaAlias 测试通过 ServerAlias 查找
func TestFindAllByDomain_ViaAlias(t *testing.T) {
	tmpDir := t.TempDir()

	content := `
<VirtualHost *:80>
    ServerName primary.example.com
    ServerAlias alias1.example.com alias2.example.com
    DocumentRoot /var/www/primary
</VirtualHost>
`
	mainFile := filepath.Join(tmpDir, "httpd.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	site, err := s.FindAllByDomain("alias2.example.com")
	if err != nil {
		t.Fatalf("错误: %v", err)
	}
	if site == nil {
		t.Fatal("通过别名应能找到站点")
	}
	if site.ServerName != "primary.example.com" {
		t.Errorf("ServerName = %q，期望 primary.example.com", site.ServerName)
	}
}

// TestEnrichSiteFromConfig 测试从配置文件补充站点信息
func TestEnrichSiteFromConfig(t *testing.T) {
	tmpDir := t.TempDir()

	content := `
<VirtualHost *:443>
    ServerName enrich.example.com
    ServerAlias www.enrich.example.com cdn.enrich.example.com
    DocumentRoot /var/www/enrich
    SSLCertificateFile /etc/ssl/enrich.crt
    SSLCertificateKeyFile /etc/ssl/enrich.key
    SSLCertificateChainFile /etc/ssl/enrich-chain.crt
</VirtualHost>

<VirtualHost *:80>
    ServerName other.example.com
    DocumentRoot /var/www/other
</VirtualHost>
`
	configFile := filepath.Join(tmpDir, "test.conf")
	_ = os.WriteFile(configFile, []byte(content), 0644)

	s := NewWithConfig(configFile)

	// 测试 enrich 目标站点
	site := &Site{
		ServerName: "enrich.example.com",
		ConfigFile: configFile,
		HasSSL:     true,
	}
	s.enrichSiteFromConfig(site)

	if len(site.ServerAlias) != 2 {
		t.Errorf("ServerAlias 数量 = %d，期望 2", len(site.ServerAlias))
	}
	if site.CertificatePath != "/etc/ssl/enrich.crt" {
		t.Errorf("CertificatePath = %q，期望 /etc/ssl/enrich.crt", site.CertificatePath)
	}
	if site.PrivateKeyPath != "/etc/ssl/enrich.key" {
		t.Errorf("PrivateKeyPath = %q，期望 /etc/ssl/enrich.key", site.PrivateKeyPath)
	}
	if site.ChainPath != "/etc/ssl/enrich-chain.crt" {
		t.Errorf("ChainPath = %q，期望 /etc/ssl/enrich-chain.crt", site.ChainPath)
	}
	if site.Webroot != "/var/www/enrich" {
		t.Errorf("Webroot = %q，期望 /var/www/enrich", site.Webroot)
	}
}

// TestEnrichSiteFromConfig_NotFound 测试 enrichSiteFromConfig 找不到目标站点
func TestEnrichSiteFromConfig_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	content := `
<VirtualHost *:443>
    ServerName other.example.com
    SSLCertificateFile /etc/ssl/other.crt
</VirtualHost>
`
	configFile := filepath.Join(tmpDir, "test.conf")
	_ = os.WriteFile(configFile, []byte(content), 0644)

	s := NewWithConfig(configFile)
	site := &Site{
		ServerName: "nonexistent.example.com",
		ConfigFile: configFile,
	}
	s.enrichSiteFromConfig(site)

	// 不应该有任何字段被填充
	if site.CertificatePath != "" {
		t.Errorf("不匹配站点不应填充 CertificatePath，实际 %q", site.CertificatePath)
	}
}

// TestEnrichSiteFromConfig_EmptyFields 测试空 ConfigFile 和 ServerName
func TestEnrichSiteFromConfig_EmptyFields(t *testing.T) {
	s := New()

	// 空 ConfigFile
	site := &Site{ServerName: "example.com", ConfigFile: ""}
	s.enrichSiteFromConfig(site) // 应直接返回不崩溃

	// 空 ServerName
	site2 := &Site{ServerName: "", ConfigFile: "/some/file"}
	s.enrichSiteFromConfig(site2) // 应直接返回不崩溃
}

// TestParseAllConfigFile_FileSizeLimit 测试 parseAllConfigFile 文件大小限制
func TestParseAllConfigFile_FileSizeLimit(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建超大文件（超过 maxConfigFileSize）
	largePath := filepath.Join(tmpDir, "large.conf")
	f, err := os.Create(largePath)
	if err != nil {
		t.Fatalf("创建文件失败: %v", err)
	}
	// 写入足够数据超过 10MB 限制
	// 用重复行快速填充
	line := strings.Repeat("# padding comment line to fill up file size\n", 100)
	for written := 0; written < maxConfigFileSize+1; {
		n, err := f.WriteString(line)
		if err != nil {
			t.Fatalf("写入失败: %v", err)
		}
		written += n
	}
	_ = f.Close()

	s := NewWithConfig(largePath)
	var debugMsg string
	s.SetDebug(true, func(format string, args ...interface{}) {
		debugMsg = fmt.Sprintf(format, args...)
	})

	sites, err := s.parseAllConfigFile(largePath)
	if err != nil {
		t.Fatalf("不应返回错误: %v", err)
	}
	// 超大文件应返回 nil（跳过）
	if sites != nil {
		t.Errorf("超大文件应返回 nil，实际 %d 个站点", len(sites))
	}
	// 应输出调试日志
	if !strings.Contains(debugMsg, "配置文件过大") {
		t.Errorf("调试日志应包含 '配置文件过大'，实际: %q", debugMsg)
	}
}

// TestParseHTTPConfigFile_FileSizeLimit 测试 parseHTTPConfigFile 文件大小限制
func TestParseHTTPConfigFile_FileSizeLimit(t *testing.T) {
	tmpDir := t.TempDir()

	largePath := filepath.Join(tmpDir, "large-http.conf")
	f, err := os.Create(largePath)
	if err != nil {
		t.Fatalf("创建文件失败: %v", err)
	}
	line := strings.Repeat("# padding\n", 100)
	for written := 0; written < maxConfigFileSize+1; {
		n, err := f.WriteString(line)
		if err != nil {
			t.Fatalf("写入失败: %v", err)
		}
		written += n
	}
	_ = f.Close()

	s := NewWithConfig(largePath)
	var debugMsg string
	s.SetDebug(true, func(format string, args ...interface{}) {
		debugMsg = fmt.Sprintf(format, args...)
	})

	sites, err := s.parseHTTPConfigFile(largePath)
	if err != nil {
		t.Fatalf("不应返回错误: %v", err)
	}
	if sites != nil {
		t.Errorf("超大文件应返回 nil，实际 %d 个站点", len(sites))
	}
	if !strings.Contains(debugMsg, "配置文件过大") {
		t.Errorf("调试日志应包含 '配置文件过大'，实际: %q", debugMsg)
	}
}

// TestParseConfigFile_FileSizeLimit 测试 parseConfigFile（SSL）文件大小限制
func TestParseConfigFile_FileSizeLimit(t *testing.T) {
	tmpDir := t.TempDir()

	largePath := filepath.Join(tmpDir, "large-ssl.conf")
	f, err := os.Create(largePath)
	if err != nil {
		t.Fatalf("创建文件失败: %v", err)
	}
	line := strings.Repeat("# padding\n", 100)
	for written := 0; written < maxConfigFileSize+1; {
		n, err := f.WriteString(line)
		if err != nil {
			t.Fatalf("写入失败: %v", err)
		}
		written += n
	}
	_ = f.Close()

	s := NewWithConfig(largePath)
	var debugMsg string
	s.SetDebug(true, func(format string, args ...interface{}) {
		debugMsg = fmt.Sprintf(format, args...)
	})

	sites, err := s.parseConfigFile(largePath)
	if err != nil {
		t.Fatalf("不应返回错误: %v", err)
	}
	if sites != nil {
		t.Errorf("超大文件应返回 nil，实际 %d 个站点", len(sites))
	}
	if !strings.Contains(debugMsg, "配置文件过大") {
		t.Errorf("调试日志应包含 '配置文件过大'，实际: %q", debugMsg)
	}
}

// TestScanAllConfigFile_MaxFilesLimit 测试 ScanAll 路径的文件数量限制
func TestScanAllConfigFile_MaxFilesLimit(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建超过 maxScanFiles 数量的配置文件
	var includes string
	fileCount := maxScanFiles + 10
	for i := 0; i < fileCount; i++ {
		confPath := filepath.Join(tmpDir, fmt.Sprintf("all-site-%04d.conf", i))
		content := fmt.Sprintf(`
<VirtualHost *:80>
    ServerName site%d.example.com
    DocumentRoot /var/www/site%d
</VirtualHost>
`, i, i)
		_ = os.WriteFile(confPath, []byte(content), 0644)
		includes += "Include " + confPath + "\n"
	}

	mainConf := filepath.Join(tmpDir, "main-all.conf")
	_ = os.WriteFile(mainConf, []byte(includes), 0644)

	s := NewWithConfig(mainConf)
	sites, err := s.ScanAll()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	// 不应超过 maxScanFiles
	if len(s.scannedFiles) > maxScanFiles {
		t.Errorf("ScanAll 扫描文件数 %d 超过限制 %d", len(s.scannedFiles), maxScanFiles)
	}

	// 应该找到部分站点
	if len(sites) >= fileCount {
		t.Errorf("ScanAll 站点数 %d 应小于总文件数 %d", len(sites), fileCount)
	}
	if len(sites) == 0 {
		t.Error("ScanAll 应至少找到一些站点")
	}
}

// TestScanHTTPConfigFile_MaxFilesLimit 测试 ScanHTTPSites 路径的文件数量限制
func TestScanHTTPConfigFile_MaxFilesLimit(t *testing.T) {
	tmpDir := t.TempDir()

	var includes string
	fileCount := maxScanFiles + 10
	for i := 0; i < fileCount; i++ {
		confPath := filepath.Join(tmpDir, fmt.Sprintf("http-site-%04d.conf", i))
		content := fmt.Sprintf(`
<VirtualHost *:80>
    ServerName http-site%d.example.com
    DocumentRoot /var/www/http-site%d
</VirtualHost>
`, i, i)
		_ = os.WriteFile(confPath, []byte(content), 0644)
		includes += "Include " + confPath + "\n"
	}

	mainConf := filepath.Join(tmpDir, "main-http.conf")
	_ = os.WriteFile(mainConf, []byte(includes), 0644)

	s := NewWithConfig(mainConf)
	sites, err := s.ScanHTTPSites()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	if len(s.scannedFiles) > maxScanFiles {
		t.Errorf("ScanHTTPSites 扫描文件数 %d 超过限制 %d", len(s.scannedFiles), maxScanFiles)
	}
	if len(sites) >= fileCount {
		t.Errorf("ScanHTTPSites 站点数 %d 应小于总文件数 %d", len(sites), fileCount)
	}
	if len(sites) == 0 {
		t.Error("ScanHTTPSites 应至少找到一些站点")
	}
}

// TestParseAllConfigFile_MixedSites 测试 parseAllConfigFile 解析混合站点
func TestParseAllConfigFile_MixedSites(t *testing.T) {
	tmpDir := t.TempDir()

	content := `
# HTTP 站点
<VirtualHost *:80>
    ServerName http-only.example.com
    DocumentRoot /var/www/http-only
</VirtualHost>

# HTTPS 站点（通过 SSLEngine on）
<VirtualHost *:443>
    ServerName ssl-engine.example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/engine.crt
    SSLCertificateKeyFile /etc/ssl/engine.key
    DocumentRoot /var/www/ssl-engine
</VirtualHost>

# 443 端口自动标记 SSL
<VirtualHost *:443>
    ServerName auto-ssl.example.com
    SSLCertificateFile /etc/ssl/auto.crt
    SSLCertificateKeyFile /etc/ssl/auto.key
</VirtualHost>

# 没有 ServerName 的 VirtualHost（应被跳过）
<VirtualHost *:80>
    DocumentRoot /var/www/noname
</VirtualHost>

# 嵌套 Directory 块
<VirtualHost *:80>
    ServerName nested.example.com
    DocumentRoot /var/www/nested
    <Directory /var/www/nested>
        Options Indexes
        AllowOverride All
    </Directory>
</VirtualHost>
`
	confPath := filepath.Join(tmpDir, "mixed.conf")
	_ = os.WriteFile(confPath, []byte(content), 0644)

	s := NewWithConfig(confPath)
	sites, err := s.parseAllConfigFile(confPath)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 应该找到 4 个有 ServerName 的站点（跳过无 ServerName 的）
	if len(sites) != 4 {
		t.Errorf("期望 4 个站点，实际 %d", len(sites))
		for _, s := range sites {
			t.Logf("  站点: %s, HasSSL=%v", s.ServerName, s.HasSSL)
		}
	}

	// 验证各站点属性
	sitesByName := make(map[string]*Site)
	for _, site := range sites {
		sitesByName[site.ServerName] = site
	}

	// HTTP 站点
	if site, ok := sitesByName["http-only.example.com"]; ok {
		if site.HasSSL {
			t.Error("http-only 不应标记为 SSL")
		}
		if site.Webroot != "/var/www/http-only" {
			t.Errorf("http-only Webroot = %q", site.Webroot)
		}
	} else {
		t.Error("未找到 http-only.example.com")
	}

	// SSLEngine on 站点
	if site, ok := sitesByName["ssl-engine.example.com"]; ok {
		if !site.HasSSL {
			t.Error("ssl-engine 应标记为 SSL")
		}
		if site.CertificatePath != "/etc/ssl/engine.crt" {
			t.Errorf("ssl-engine CertificatePath = %q", site.CertificatePath)
		}
	} else {
		t.Error("未找到 ssl-engine.example.com")
	}

	// 443 端口自动 SSL
	if site, ok := sitesByName["auto-ssl.example.com"]; ok {
		if !site.HasSSL {
			t.Error("auto-ssl 应标记为 SSL（443 端口）")
		}
	} else {
		t.Error("未找到 auto-ssl.example.com")
	}

	// 嵌套 Directory 块
	if _, ok := sitesByName["nested.example.com"]; !ok {
		t.Error("未找到 nested.example.com（嵌套 Directory 不应干扰解析）")
	}
}

// TestParseAllConfigFile_ServerAlias 测试 parseAllConfigFile 解析 ServerAlias
func TestParseAllConfigFile_ServerAlias(t *testing.T) {
	tmpDir := t.TempDir()

	content := `
<VirtualHost *:443>
    ServerName main.example.com
    ServerAlias www.main.example.com api.main.example.com
    SSLCertificateFile /etc/ssl/main.crt
    SSLCertificateKeyFile /etc/ssl/main.key
</VirtualHost>
`
	confPath := filepath.Join(tmpDir, "alias.conf")
	_ = os.WriteFile(confPath, []byte(content), 0644)

	s := NewWithConfig(confPath)
	sites, err := s.parseAllConfigFile(confPath)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个站点，实际 %d", len(sites))
	}

	if len(sites[0].ServerAlias) != 2 {
		t.Errorf("期望 2 个 ServerAlias，实际 %d: %v", len(sites[0].ServerAlias), sites[0].ServerAlias)
	}
}

// TestScanAll_FallbackToFileScanning 测试 ScanAll 在 apachectl -S 不可用时回退到文件扫描
func TestScanAll_FallbackToFileScanning(t *testing.T) {
	tmpDir := t.TempDir()

	content := `
<VirtualHost *:80>
    ServerName fallback.example.com
    DocumentRoot /var/www/fallback
</VirtualHost>
<VirtualHost *:443>
    ServerName fallback.example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/fallback.crt
    SSLCertificateKeyFile /etc/ssl/fallback.key
</VirtualHost>
`
	mainFile := filepath.Join(tmpDir, "httpd.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	// 在测试环境中 apachectl 不可用，ScanAll 会回退到文件扫描
	sites, err := s.ScanAll()
	if err != nil {
		t.Fatalf("ScanAll 失败: %v", err)
	}

	if len(sites) != 2 {
		t.Errorf("期望 2 个站点（HTTP + HTTPS），实际 %d", len(sites))
	}

	hasHTTP := false
	hasSSL := false
	for _, site := range sites {
		if site.ServerName == "fallback.example.com" {
			if site.HasSSL {
				hasSSL = true
			} else {
				hasHTTP = true
			}
		}
	}
	if !hasHTTP {
		t.Error("应找到 HTTP 站点")
	}
	if !hasSSL {
		t.Error("应找到 SSL 站点")
	}
}

// TestScanConfigFile_NonexistentFile 测试扫描不存在的文件
func TestScanConfigFile_NonexistentFile(t *testing.T) {
	s := NewWithConfig("/nonexistent/path/httpd.conf")

	// scanConfigFile 对不存在的文件应返回 nil 不报错
	sites, err := s.scanConfigFile("/nonexistent/path/httpd.conf")
	if err != nil {
		t.Fatalf("不存在的文件不应返回错误: %v", err)
	}
	if len(sites) != 0 {
		t.Errorf("不存在的文件应返回空站点列表，实际 %d", len(sites))
	}
}

// TestScanConfigFile_DuplicateFile 测试重复扫描同一文件（去重机制）
func TestScanConfigFile_DuplicateFile(t *testing.T) {
	tmpDir := t.TempDir()

	content := `
<VirtualHost *:443>
    ServerName dup.example.com
    SSLCertificateFile /etc/ssl/dup.crt
    SSLCertificateKeyFile /etc/ssl/dup.key
</VirtualHost>
`
	confFile := filepath.Join(tmpDir, "dup.conf")
	_ = os.WriteFile(confFile, []byte(content), 0644)

	s := NewWithConfig(confFile)

	// 第一次扫描
	sites1, err := s.scanConfigFile(confFile)
	if err != nil {
		t.Fatalf("第一次扫描失败: %v", err)
	}
	if len(sites1) != 1 {
		t.Fatalf("第一次扫描期望 1 个站点，实际 %d", len(sites1))
	}

	// 第二次扫描同一文件（应被去重跳过）
	sites2, err := s.scanConfigFile(confFile)
	if err != nil {
		t.Fatalf("第二次扫描失败: %v", err)
	}
	if len(sites2) != 0 {
		t.Errorf("重复扫描应返回空（已去重），实际 %d", len(sites2))
	}
}

// TestParseHTTPConfigFile_Port443AsSSL 测试 HTTP 扫描器将 443 端口识别为 SSL
func TestParseHTTPConfigFile_Port443AsSSL(t *testing.T) {
	tmpDir := t.TempDir()

	content := `
<VirtualHost *:80>
    ServerName http-site.example.com
    DocumentRoot /var/www/http
</VirtualHost>
<VirtualHost *:443>
    ServerName ssl-site.example.com
    DocumentRoot /var/www/ssl
</VirtualHost>
`
	confPath := filepath.Join(tmpDir, "ports.conf")
	_ = os.WriteFile(confPath, []byte(content), 0644)

	s := NewWithConfig(confPath)
	sites, err := s.parseHTTPConfigFile(confPath)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 只有 80 端口的站点应被识别为 HTTP
	if len(sites) != 1 {
		t.Errorf("期望 1 个 HTTP 站点（443 被排除），实际 %d", len(sites))
	}
	if len(sites) > 0 && sites[0].ServerName != "http-site.example.com" {
		t.Errorf("HTTP 站点名 = %q，期望 http-site.example.com", sites[0].ServerName)
	}
}

// TestParseHTTPConfigFile_NoServerName 测试无 ServerName 的 VirtualHost 被跳过
func TestParseHTTPConfigFile_NoServerName(t *testing.T) {
	tmpDir := t.TempDir()

	content := `
<VirtualHost *:80>
    DocumentRoot /var/www/noname
</VirtualHost>
<VirtualHost *:80>
    ServerName named.example.com
    DocumentRoot /var/www/named
</VirtualHost>
`
	confPath := filepath.Join(tmpDir, "noname.conf")
	_ = os.WriteFile(confPath, []byte(content), 0644)

	s := NewWithConfig(confPath)
	sites, err := s.parseHTTPConfigFile(confPath)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 无 ServerName 的应被跳过
	if len(sites) != 1 {
		t.Errorf("期望 1 个站点（无名被跳过），实际 %d", len(sites))
	}
}

// TestGetServerRoot 测试 GetServerRoot 方法
func TestGetServerRoot(t *testing.T) {
	s := &Scanner{
		mainConfigPath: "/etc/apache2/apache2.conf",
		serverRoot:     "/etc/apache2",
		scannedFiles:   make(map[string]bool),
	}
	if s.GetServerRoot() != "/etc/apache2" {
		t.Errorf("GetServerRoot() = %q，期望 /etc/apache2", s.GetServerRoot())
	}

	s2 := New()
	if s2.GetServerRoot() != "" {
		t.Errorf("新建扫描器 GetServerRoot() 应为空，实际 %q", s2.GetServerRoot())
	}
}

// TestScanAll_WithInclude 测试 ScanAll 递归 Include 处理
func TestScanAll_WithInclude(t *testing.T) {
	tmpDir := t.TempDir()

	sslConf := `
<VirtualHost *:443>
    ServerName ssl-inc.example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/inc.crt
    SSLCertificateKeyFile /etc/ssl/inc.key
</VirtualHost>
`
	httpConf := `
<VirtualHost *:80>
    ServerName http-inc.example.com
    DocumentRoot /var/www/http-inc
</VirtualHost>
`
	sslFile := filepath.Join(tmpDir, "ssl.conf")
	httpFile := filepath.Join(tmpDir, "http.conf")
	_ = os.WriteFile(sslFile, []byte(sslConf), 0644)
	_ = os.WriteFile(httpFile, []byte(httpConf), 0644)

	mainContent := "Include " + sslFile + "\nInclude " + httpFile + "\n"
	mainFile := filepath.Join(tmpDir, "httpd.conf")
	_ = os.WriteFile(mainFile, []byte(mainContent), 0644)

	s := NewWithConfig(mainFile)
	sites, err := s.ScanAll()
	if err != nil {
		t.Fatalf("ScanAll 失败: %v", err)
	}

	if len(sites) != 2 {
		t.Errorf("期望 2 个站点（通过 Include），实际 %d", len(sites))
		for _, site := range sites {
			t.Logf("  站点: %s, HasSSL=%v", site.ServerName, site.HasSSL)
		}
	}
}

func TestParseApacheDArg(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"unquoted forward slash", `C:\xampp\apache\bin\httpd.exe -d C:/xampp/apache`, "C:/xampp/apache"},
		{"unquoted backslash", `httpd.exe -d C:\xampp\apache`, `C:\xampp\apache`},
		{"quoted with space", `httpd.exe -d "C:/Program Files/Apache"`, "C:/Program Files/Apache"},
		{"no -d", `httpd.exe -k start`, ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseApacheDArg(c.in)
			if got != c.want {
				t.Errorf("parseApacheDArg(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestParseWinProcList(t *testing.T) {
	wmicOut := `CommandLine=C:\xampp\apache\bin\httpd.exe -d C:/xampp/apache
ExecutablePath=C:\xampp\apache\bin\httpd.exe

CommandLine=c:\xampp\apache\bin\httpd.exe
ExecutablePath=c:\xampp\apache\bin\httpd.exe
`
	procs := parseWinProcList(wmicOut)
	if len(procs) != 2 {
		t.Fatalf("wmic 期望 2 个进程，实际 %d", len(procs))
	}
	if procs[0].commandLine != `C:\xampp\apache\bin\httpd.exe -d C:/xampp/apache` {
		t.Errorf("wmic procs[0].commandLine 不正确: %q", procs[0].commandLine)
	}
	if procs[1].executablePath != `c:\xampp\apache\bin\httpd.exe` {
		t.Errorf("wmic procs[1].executablePath 不正确: %q", procs[1].executablePath)
	}

	psOut := `ExecutablePath : C:\xampp\apache\bin\httpd.exe
CommandLine    : C:\xampp\apache\bin\httpd.exe -d C:/xampp/apache

ExecutablePath : c:\xampp\apache\bin\httpd.exe
CommandLine    : c:\xampp\apache\bin\httpd.exe
`
	procs = parseWinProcList(psOut)
	if len(procs) != 2 {
		t.Fatalf("powershell 期望 2 个进程，实际 %d", len(procs))
	}
	if procs[0].commandLine != `C:\xampp\apache\bin\httpd.exe -d C:/xampp/apache` {
		t.Errorf("ps procs[0].commandLine 不正确: %q", procs[0].commandLine)
	}
}
