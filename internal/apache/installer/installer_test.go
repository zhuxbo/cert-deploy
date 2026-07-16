package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHasSSLConfig_NoSSL(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "example.com", "")
	content := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`
	if inst.hasSSLConfig(content) {
		t.Error("expected hasSSLConfig = false for HTTP-only config")
	}
}

func TestHasSSLConfig_HasSSL(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "example.com", "")
	content := `<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
</VirtualHost>`
	if !inst.hasSSLConfig(content) {
		t.Error("expected hasSSLConfig = true for matching :443 VirtualHost")
	}
}

func TestHasSSLConfig_DifferentDomain(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "example.com", "")
	content := `<VirtualHost *:443>
    ServerName other.com
    SSLEngine on
</VirtualHost>`
	if inst.hasSSLConfig(content) {
		t.Error("expected hasSSLConfig = false for different domain")
	}
}

func TestHasSSLConfig_CaseInsensitive(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "example.com", "")
	content := `<virtualhost *:443>
    serverName example.com
    SSLEngine on
</virtualhost>`
	if !inst.hasSSLConfig(content) {
		t.Error("expected hasSSLConfig = true (case insensitive)")
	}
}

func TestHasSSLConfig_WithAlias(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "www.example.com", "")
	content := `<VirtualHost *:443>
    ServerName example.com
    ServerAlias www.example.com
    SSLEngine on
</VirtualHost>`
	if !inst.hasSSLConfig(content) {
		t.Error("expected hasSSLConfig = true for matching ServerAlias")
	}
}

func TestExtractVirtualHost80_Simple(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "example.com", "")
	content := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

	vhost, err := inst.extractHTTPVirtualHost(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vhost == "" {
		t.Fatal("expected non-empty VirtualHost")
	}
	if !strings.Contains(vhost, "ServerName example.com") {
		t.Error("expected ServerName in extracted VirtualHost")
	}
}

func TestExtractHTTPVirtualHost_CustomPortSkipped(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "example.com", "")
	// 非 80 端口的 VirtualHost 不应被提取：generateSSLVirtualHost 只把端口 80 改写为 443，
	// 基于 *:8080 等端口生成会得到端口未改写的伪 SSL 块，故一律跳过（找不到 → 空结果 → 调用方报错）。
	for _, port := range []string{"8080", "180", "1800", "8443"} {
		content := `<VirtualHost *:` + port + `>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

		vhost, err := inst.extractHTTPVirtualHost(content)
		if err != nil {
			t.Fatalf("port %s: unexpected error: %v", port, err)
		}
		if vhost != "" {
			t.Errorf("port %s: 非 80 端口 VirtualHost 不应被提取，实际提取到内容", port)
		}
	}
}

// TestAddSSLVirtualHost_CustomPortErrors 端口非 80 时 addSSLVirtualHost 应明确报错，
// 而非基于自定义端口注入伪 SSL 配置（与 Nginx 安装器无 80 块即报错的行为一致）。
func TestAddSSLVirtualHost_CustomPortErrors(t *testing.T) {
	inst := NewApacheInstaller("", "/ssl/cert.pem", "/ssl/key.pem", "", "example.com", "")
	content := `<VirtualHost *:8080>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

	out, err := inst.addSSLVirtualHost(content)
	if err == nil {
		t.Fatal("端口 8080 的站点应报错（无 :80 VirtualHost），而非注入 SSL")
	}
	if out != "" {
		t.Errorf("报错时不应产生配置输出，实际: %q", out)
	}
}

// TestExtractHTTPVirtualHost_Port80AmongCustom 混合端口时仅提取端口 80 的 VirtualHost。
func TestExtractHTTPVirtualHost_Port80AmongCustom(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "example.com", "")
	content := `<VirtualHost *:8080>
    ServerName example.com
    DocumentRoot /var/www/alt
</VirtualHost>

<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

	vhost, err := inst.extractHTTPVirtualHost(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(vhost, "/var/www/html") {
		t.Error("应提取端口 80 的 VirtualHost（DocumentRoot /var/www/html）")
	}
	if strings.Contains(vhost, "/var/www/alt") {
		t.Error("不应提取端口 8080 的 VirtualHost")
	}
}

func TestExtractHTTPVirtualHost_Skip443(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "example.com", "")
	content := `<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
</VirtualHost>`

	vhost, err := inst.extractHTTPVirtualHost(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vhost != "" {
		t.Error("expected empty result for :443 VirtualHost")
	}
}

func TestExtractVirtualHost80_WildcardHost(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "example.com", "")
	content := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

	vhost, err := inst.extractHTTPVirtualHost(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vhost == "" {
		t.Error("expected non-empty result for wildcard host")
	}
}

func TestExtractVirtualHost80_MultipleVHosts(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "target.com", "")
	content := `<VirtualHost *:80>
    ServerName other.com
    DocumentRoot /var/www/other
</VirtualHost>

<VirtualHost *:80>
    ServerName target.com
    DocumentRoot /var/www/target
</VirtualHost>

<VirtualHost *:80>
    ServerName third.com
    DocumentRoot /var/www/third
</VirtualHost>`

	vhost, err := inst.extractHTTPVirtualHost(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(vhost, "target.com") {
		t.Error("expected target.com in extracted VirtualHost")
	}
	if strings.Contains(vhost, "other.com") {
		t.Error("should not contain other.com")
	}
}

func TestExtractVirtualHost80_NotFound(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "notfound.com", "")
	content := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

	vhost, err := inst.extractHTTPVirtualHost(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vhost != "" {
		t.Error("expected empty result for not found domain")
	}
}

func TestGenerateSSLVirtualHost_Basic(t *testing.T) {
	inst := NewApacheInstaller("", "/ssl/cert.pem", "/ssl/key.pem", "", "example.com", "")
	vhost80 := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

	result := inst.generateSSLVirtualHost(vhost80)

	// 验证端口替换
	if !strings.Contains(result, ":443") {
		t.Error("expected :443 in generated config")
	}
	if strings.Contains(result, ":80") {
		t.Error("should not contain :80")
	}

	// 验证 SSL 指令
	if !strings.Contains(result, "SSLEngine on") {
		t.Error("expected SSLEngine on")
	}
	if !strings.Contains(result, "SSLCertificateFile /ssl/cert.pem") {
		t.Error("expected SSLCertificateFile")
	}
	if !strings.Contains(result, "SSLCertificateKeyFile /ssl/key.pem") {
		t.Error("expected SSLCertificateKeyFile")
	}
	if !strings.Contains(result, "SSLProtocol") {
		t.Error("expected SSLProtocol")
	}

	// 无链时不应包含 ChainFile
	if strings.Contains(result, "SSLCertificateChainFile") {
		t.Error("should not contain SSLCertificateChainFile without chain")
	}
}

func TestGenerateSSLVirtualHost_WithChain(t *testing.T) {
	inst := NewApacheInstaller("", "/ssl/cert.pem", "/ssl/key.pem", "/ssl/chain.pem", "example.com", "")
	vhost80 := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

	result := inst.generateSSLVirtualHost(vhost80)

	if !strings.Contains(result, "SSLCertificateChainFile /ssl/chain.pem") {
		t.Error("expected SSLCertificateChainFile")
	}
}

func TestGenerateSSLVirtualHost_NoChain(t *testing.T) {
	inst := NewApacheInstaller("", "/ssl/cert.pem", "/ssl/key.pem", "", "example.com", "")
	vhost80 := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

	result := inst.generateSSLVirtualHost(vhost80)

	if strings.Contains(result, "SSLCertificateChainFile") {
		t.Error("should not contain SSLCertificateChainFile when chain is empty")
	}
}

func TestInstall_NewHTTPS(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "site.conf")

	// 写入初始 HTTP 配置
	content := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	inst := NewApacheInstaller(configPath, "/ssl/cert.pem", "/ssl/key.pem", "", "example.com", "")
	result, err := inst.Install()
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	if !result.Modified {
		t.Error("expected Modified = true")
	}
	if result.BackupPath == "" {
		t.Error("expected non-empty BackupPath")
	}

	// 验证生成的配置包含 SSL
	newContent, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(newContent), ":443") {
		t.Error("expected :443 in new config")
	}
	if !strings.Contains(string(newContent), "SSLEngine on") {
		t.Error("expected SSLEngine on in new config")
	}

	// 验证备份文件存在
	if _, err := os.Stat(result.BackupPath); err != nil {
		t.Errorf("backup file not found: %v", err)
	}
}

func TestInstall_AlreadyHasSSL(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "site.conf")

	content := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>

<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
</VirtualHost>`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	inst := NewApacheInstaller(configPath, "/ssl/cert.pem", "/ssl/key.pem", "", "example.com", "")
	result, err := inst.Install()
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	if result.Modified {
		t.Error("expected Modified = false when SSL already exists")
	}
}

// TestInstall_NoMatchingVirtualHost_ReturnsError 锁定契约：找不到目标站点的 HTTP
// VirtualHost 时返回错误（而非静默无操作）。nginx 安装器已对齐此行为，避免调用方
// 误以为"无需安装"继续部署证书并误报成功。
func TestInstall_NoMatchingVirtualHost_ReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "site.conf")

	// 配置里只有 other.com，目标 example.com 找不到可用的 HTTP VirtualHost
	content := `<VirtualHost *:80>
    ServerName other.com
    DocumentRoot /var/www/other
</VirtualHost>`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	inst := NewApacheInstaller(configPath, "/ssl/cert.pem", "/ssl/key.pem", "", "example.com", "")
	result, err := inst.Install()
	if err == nil {
		t.Fatalf("找不到目标站点的 HTTP VirtualHost 时应返回错误，实际 result=%+v, err=nil", result)
	}
}

func TestRollback_Success(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "site.conf")
	backupPath := filepath.Join(tmpDir, "site.conf.bak")

	originalContent := "original config"
	modifiedContent := "modified config"

	if err := os.WriteFile(configPath, []byte(modifiedContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(backupPath, []byte(originalContent), 0644); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	inst := NewApacheInstaller(configPath, "", "", "", "", "")
	if err := inst.Rollback(backupPath); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	// 验证配置已回滚
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(data) != originalContent {
		t.Errorf("config not rolled back: got %q", string(data))
	}
}

func TestRollback_BackupNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "site.conf")

	inst := NewApacheInstaller(configPath, "", "", "", "", "")
	err := inst.Rollback(filepath.Join(tmpDir, "nonexistent.bak"))
	if err == nil {
		t.Error("expected error for nonexistent backup")
	}
}

func TestFindHTTPVirtualHost_Direct(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "site.conf")

	content := `<VirtualHost *:80>
    ServerName target.com
    DocumentRoot /var/www/html
</VirtualHost>`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := FindHTTPVirtualHost(configPath, "target.com")
	if err != nil {
		t.Fatalf("FindHTTPVirtualHost: %v", err)
	}
	if result != configPath {
		t.Errorf("result = %q, want %q", result, configPath)
	}
}

func TestFindHTTPVirtualHost_Recursive(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建子目录
	confDir := filepath.Join(tmpDir, "conf.d")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// 创建主配置（包含 Include）
	mainConfig := filepath.Join(tmpDir, "apache.conf")
	mainContent := `Include ` + filepath.Join(confDir, "*.conf")
	if err := os.WriteFile(mainConfig, []byte(mainContent), 0644); err != nil {
		t.Fatalf("write main: %v", err)
	}

	// 创建子配置
	subConfig := filepath.Join(confDir, "site.conf")
	subContent := `<VirtualHost *:80>
    ServerName sub.example.com
    DocumentRoot /var/www/sub
</VirtualHost>`
	if err := os.WriteFile(subConfig, []byte(subContent), 0644); err != nil {
		t.Fatalf("write sub: %v", err)
	}

	result, err := FindHTTPVirtualHost(mainConfig, "sub.example.com")
	if err != nil {
		t.Fatalf("FindHTTPVirtualHost: %v", err)
	}
	if result != subConfig {
		t.Errorf("result = %q, want %q", result, subConfig)
	}
}

func TestFindHTTPVirtualHost_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "site.conf")

	content := `<VirtualHost *:80>
    ServerName other.com
    DocumentRoot /var/www/html
</VirtualHost>`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := FindHTTPVirtualHost(configPath, "notfound.com")
	if err != nil {
		t.Fatalf("FindHTTPVirtualHost: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result, got %q", result)
	}
}

func TestNewApacheInstaller_DefaultCommand(t *testing.T) {
	inst := NewApacheInstaller("/etc/apache2/sites-available/site.conf", "/ssl/cert.pem", "/ssl/key.pem", "", "example.com", "")
	if inst.testCommand != "" {
		t.Errorf("testCommand = %q, want empty", inst.testCommand)
	}
}

func TestNewApacheInstaller_CustomCommand(t *testing.T) {
	inst := NewApacheInstaller("/etc/apache2/sites-available/site.conf", "/ssl/cert.pem", "/ssl/key.pem", "", "example.com", "httpd -t")
	if inst.testCommand != "httpd -t" {
		t.Errorf("testCommand = %q, want 'httpd -t'", inst.testCommand)
	}
}

func TestGetIndent(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "", "")

	tests := []struct {
		line string
		want string
	}{
		{"    ServerName example.com", "    "},
		{"\tServerName example.com", "\t"},
		{"ServerName example.com", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := inst.getIndent(tt.line)
		if got != tt.want {
			t.Errorf("getIndent(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

// TestSwapAddrPort80 验证仅端口恰为 80 的地址被换成 443，其余端口（如 8080）不受影响。
func TestSwapAddrPort80(t *testing.T) {
	tests := []struct {
		token string
		want  string
	}{
		{"*:80", "*:443"},
		{"1.2.3.4:80", "1.2.3.4:443"},
		{"example.com:80", "example.com:443"},
		{"[2001:db8::1]:80", "[2001:db8::1]:443"},
		{"_default_:80", "_default_:443"},
		{"*:8080", "*:8080"}, // 端口 8080 不是 80，不动
		{"1.2.3.4:8080", "1.2.3.4:8080"},
		{"[2001:db8::1]:8080", "[2001:db8::1]:8080"},
		{"*", "*"},                           // 无端口不动
		{"[2001:db8::80]", "[2001:db8::80]"}, // 带方括号裸 IPv6，无端口不动
		{"*:443", "*:443"},                   // 已是 443 不动
	}
	for _, tt := range tests {
		if got := swapAddrPort80(tt.token); got != tt.want {
			t.Errorf("swapAddrPort80(%q) = %q, want %q", tt.token, got, tt.want)
		}
	}
}

// TestReplaceVirtualHostPort80 验证 <VirtualHost> 开始标签的多地址端口替换。
func TestReplaceVirtualHostPort80(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"<VirtualHost *:80>", "<VirtualHost *:443>"},
		{"    <VirtualHost *:80>", "    <VirtualHost *:443>"},
		{"<VirtualHost *:8080>", "<VirtualHost *:8080>"},
		{"<VirtualHost *:80 1.2.3.4:80>", "<VirtualHost *:443 1.2.3.4:443>"},
		{"<VirtualHost *:80 5.6.7.8:8080>", "<VirtualHost *:443 5.6.7.8:8080>"},
		{"<VirtualHost [2001:db8::1]:80>", "<VirtualHost [2001:db8::1]:443>"},
		{"<virtualhost *:80>", "<virtualhost *:443>"},
		{"    ServerName example.com", "    ServerName example.com"}, // 非开始行不动
	}
	for _, tt := range tests {
		if got := replaceVirtualHostPort80(tt.line); got != tt.want {
			t.Errorf("replaceVirtualHostPort80(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

// TestGenerateSSLVirtualHost_CustomPortNotCorrupted 回归：字面替换会把 <VirtualHost *:8080>
// 误改成 *:44380。改为按地址 token 精确端口替换后，8080 端口保持不变。
func TestGenerateSSLVirtualHost_CustomPortNotCorrupted(t *testing.T) {
	inst := NewApacheInstaller("", "/ssl/cert.pem", "/ssl/key.pem", "", "example.com", "")
	vhost := `<VirtualHost *:8080>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

	result := inst.generateSSLVirtualHost(vhost)

	if strings.Contains(result, "44380") {
		t.Errorf("端口 8080 不应被污染成 44380\n%s", result)
	}
	if !strings.Contains(result, "<VirtualHost *:8080>") {
		t.Errorf("非 80 端口地址应保持不变\n%s", result)
	}
}
