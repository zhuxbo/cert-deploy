package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/matcher"
)

// TestParseConfigFile_ServerNameWithPort 验证带端口的 ServerName/ServerAlias 被正确剥离。
// httpd-ssl.conf 默认模板会写成 "ServerName www.example.com:443"，
// 端口若不剥离会导致域名匹配失败（"未找到可绑定的站点"）。
func TestParseConfigFile_ServerNameWithPort(t *testing.T) {
	content := `
<VirtualHost _default_:443>
    ServerName www.example.com:443
    ServerAlias example.com:443 alt.example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/cert.crt
    SSLCertificateKeyFile /etc/ssl/cert.key
</VirtualHost>
`
	tmpDir, err := os.MkdirTemp("", "apache-port-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	mainFile := filepath.Join(tmpDir, "httpd-ssl.conf")
	if err := os.WriteFile(mainFile, []byte(content), 0644); err != nil {
		t.Fatalf("写入配置失败: %v", err)
	}

	s := NewWithConfig(mainFile)
	sites, err := s.ScanFile(mainFile)
	if err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个站点，实际 %d", len(sites))
	}

	site := sites[0]
	if site.ServerName != "www.example.com" {
		t.Errorf("ServerName 应剥离端口：期望 www.example.com，实际 %q", site.ServerName)
	}
	if len(site.ServerAlias) != 2 || site.ServerAlias[0] != "example.com" || site.ServerAlias[1] != "alt.example.com" {
		t.Errorf("ServerAlias 应剥离端口：期望 [example.com alt.example.com]，实际 %v", site.ServerAlias)
	}
}

// TestScanHTTPSites_ServerNameWithPort 验证 HTTP 站点 ServerName 端口剥离。
func TestScanHTTPSites_ServerNameWithPort(t *testing.T) {
	content := `
<VirtualHost *:80>
    ServerName www.example.com:80
    DocumentRoot /var/www/html
</VirtualHost>
`
	tmpDir, err := os.MkdirTemp("", "apache-port-http-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	mainFile := filepath.Join(tmpDir, "httpd.conf")
	if err := os.WriteFile(mainFile, []byte(content), 0644); err != nil {
		t.Fatalf("写入配置失败: %v", err)
	}

	s := NewWithConfig(mainFile)
	sites, err := s.ScanHTTPSites()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个 HTTP 站点，实际 %d", len(sites))
	}
	if sites[0].ServerName != "www.example.com" {
		t.Errorf("HTTP ServerName 应剥离端口：期望 www.example.com，实际 %q", sites[0].ServerName)
	}
}

// TestParseAllConfigFile_ServerNameWithPort 覆盖 scan/setup 命令实际路径
// （webserver.Scan → ScanAll → parseAllConfigFile）。
func TestParseAllConfigFile_ServerNameWithPort(t *testing.T) {
	content := `
<VirtualHost _default_:443>
    ServerName www.example.com:443
    ServerAlias example.com:443
    SSLEngine on
    SSLCertificateFile /etc/ssl/cert.crt
    SSLCertificateKeyFile /etc/ssl/cert.key
    DocumentRoot /var/www/html
</VirtualHost>
`
	tmpDir, err := os.MkdirTemp("", "apache-all-port-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	mainFile := filepath.Join(tmpDir, "httpd-ssl.conf")
	if err := os.WriteFile(mainFile, []byte(content), 0644); err != nil {
		t.Fatalf("写入配置失败: %v", err)
	}

	s := NewWithConfig(mainFile)
	sites, err := s.parseAllConfigFile(mainFile)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个站点，实际 %d: %+v", len(sites), sites)
	}
	if sites[0].ServerName != "www.example.com" {
		t.Errorf("ServerName 应剥离端口：期望 www.example.com，实际 %q", sites[0].ServerName)
	}
	if len(sites[0].ServerAlias) != 1 || sites[0].ServerAlias[0] != "example.com" {
		t.Errorf("ServerAlias 应剥离端口：期望 [example.com]，实际 %v", sites[0].ServerAlias)
	}
}

// TestEndToEnd_ScanAllPortStrippedMatches 复现并验证用户报告的场景：
// httpd-ssl.conf 中 ServerName 带 :443，修复前扫描结果带端口导致与证书域名不匹配
// （"未找到可绑定的站点"）。修复后应能完全匹配。
func TestEndToEnd_ScanAllPortStrippedMatches(t *testing.T) {
	content := `
<VirtualHost _default_:443>
    ServerName www.ahmeijing.team:443
    SSLEngine on
    SSLCertificateFile /etc/ssl/cert.crt
    SSLCertificateKeyFile /etc/ssl/cert.key
</VirtualHost>
`
	tmpDir, err := os.MkdirTemp("", "apache-e2e-port-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	mainFile := filepath.Join(tmpDir, "httpd-ssl.conf")
	if err := os.WriteFile(mainFile, []byte(content), 0644); err != nil {
		t.Fatalf("写入配置失败: %v", err)
	}

	s := NewWithConfig(mainFile)
	sites, err := s.parseAllConfigFile(mainFile)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(sites) != 1 {
		t.Fatalf("期望 1 个站点，实际 %d", len(sites))
	}

	site := sites[0]
	if site.ServerName != "www.ahmeijing.team" {
		t.Fatalf("ServerName 应剥离端口：期望 www.ahmeijing.team，实际 %q", site.ServerName)
	}

	// 证书域名应能完全匹配该站点（修复前为 MatchTypeNone）
	m := matcher.New([]string{"ahmeijing.team", "www.ahmeijing.team"})
	domains := append([]string{site.ServerName}, site.ServerAlias...)
	result := m.Match(domains)
	if result.Type != config.MatchTypeFull {
		t.Errorf("期望完全匹配，实际 %v（站点域名: %v）", result.Type, domains)
	}
}
