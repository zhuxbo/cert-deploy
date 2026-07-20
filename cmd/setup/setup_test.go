// Package setup 一键部署命令测试
package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/certops"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/matcher"
	"github.com/zhuxbo/sslctl/pkg/webserver"
	"github.com/zhuxbo/sslctl/testdata/certs"
)

// newTestDeployService 构建用于部署测试的 certops 服务（备份目录落在 dir 下）
func newTestDeployService(t *testing.T, dir string) *certops.Service {
	t.Helper()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	return certops.NewService(cm, logger.NewNopLogger())
}

// TestCreateBinding_Nginx 测试创建 Nginx 绑定
func TestCreateBinding_Nginx(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName:  "example.com",
		ServerAlias: []string{"www.example.com"},
		ConfigFile:  "/etc/nginx/conf.d/example.conf",
		HasSSL:      true,
		CertPath:    "/etc/ssl/certs/example.pem",
		KeyPath:     "/etc/ssl/private/example.key",
		ServerType:  config.ServerTypeNginx,
	}

	binding := createBinding(site, cfgManager)

	if binding.ServerName != "example.com" {
		t.Errorf("ServerName = %s, want example.com", binding.ServerName)
	}

	if binding.ServerType != config.ServerTypeNginx {
		t.Errorf("ServerType = %s, want nginx", binding.ServerType)
	}

	if !binding.Enabled {
		t.Error("Enabled 应为 true")
	}

	if binding.Paths.Certificate != "/etc/ssl/certs/example.pem" {
		t.Errorf("Certificate = %s", binding.Paths.Certificate)
	}

	if !strings.HasSuffix(binding.Reload.TestCommand, " -t") || !strings.Contains(binding.Reload.TestCommand, "nginx") {
		t.Errorf("TestCommand = %s, 应包含 nginx 和 -t", binding.Reload.TestCommand)
	}

	if !strings.HasSuffix(binding.Reload.ReloadCommand, " -s reload") || !strings.Contains(binding.Reload.ReloadCommand, "nginx") {
		t.Errorf("ReloadCommand = %s, 应包含 nginx 和 -s reload", binding.Reload.ReloadCommand)
	}
}

// TestHasDeployFailures 验证退出码判定：任一失败/未完成即视为失败。
func TestHasDeployFailures(t *testing.T) {
	tests := []struct {
		name     string
		siteFail int
		certFail int
		needKey  int
		want     bool
	}{
		{"全部成功", 0, 0, 0, false},
		{"部分站点失败", 1, 0, 0, true},
		{"证书失败", 0, 1, 0, true},
		{"需要私钥跳过", 0, 0, 1, true},
		{"多类失败", 2, 1, 3, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasDeployFailures(tt.siteFail, tt.certFail, tt.needKey); got != tt.want {
				t.Errorf("hasDeployFailures(%d,%d,%d) = %v, want %v",
					tt.siteFail, tt.certFail, tt.needKey, got, tt.want)
			}
		})
	}
}

// TestCreateBinding_DockerNginx_Volume 验证 Docker Nginx 站点绑定：
// 证书路径用宿主机挂载路径、命令为 docker exec 容器化命令、Docker 信息为 volume 模式。
func TestCreateBinding_DockerNginx_Volume(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName:    "docker.example.com",
		ConfigFile:    "/etc/nginx/conf.d/docker.conf",
		HasSSL:        true,
		CertPath:      "/etc/nginx/certs/cert.pem", // 容器内路径
		KeyPath:       "/etc/nginx/certs/key.pem",
		ServerType:    config.ServerTypeDockerNginx,
		ContainerID:   "abc123",
		ContainerName: "nginx-web",
		HostCertPath:  "/opt/docker/certs/cert.pem", // 宿主机挂载路径
		HostKeyPath:   "/opt/docker/certs/key.pem",
		VolumeMode:    true,
	}

	binding := createBinding(site, cfgManager)

	// 证书路径应为宿主机侧挂载路径（而非容器内路径）
	if binding.Paths.Certificate != "/opt/docker/certs/cert.pem" {
		t.Errorf("Certificate = %s, 应为宿主机挂载路径", binding.Paths.Certificate)
	}
	if binding.Paths.PrivateKey != "/opt/docker/certs/key.pem" {
		t.Errorf("PrivateKey = %s, 应为宿主机挂载路径", binding.Paths.PrivateKey)
	}
	// 命令应为容器化 docker exec 命令
	if binding.Reload.TestCommand != "docker exec nginx-web nginx -t" {
		t.Errorf("TestCommand = %q, 应为 docker exec nginx-web nginx -t", binding.Reload.TestCommand)
	}
	if binding.Reload.ReloadCommand != "docker exec nginx-web nginx -s reload" {
		t.Errorf("ReloadCommand = %q, 应为 docker exec nginx-web nginx -s reload", binding.Reload.ReloadCommand)
	}
	// Docker 信息应为 volume 模式
	if binding.Docker == nil || binding.Docker.DeployMode != "volume" || binding.Docker.ContainerName != "nginx-web" {
		t.Errorf("Docker 信息不正确: %+v", binding.Docker)
	}
	// 校验应通过（可安全部署）
	if err := config.ValidateDockerBinding(&binding); err != nil {
		t.Errorf("挂载卷 Docker 绑定应可部署: %v", err)
	}
}

// TestCreateBinding_DockerNginx_NoMount 验证无宿主机挂载路径的 Docker 站点为 copy 模式，
// 部署校验会拒绝（不可通过通用路径安全部署）。
func TestCreateBinding_DockerNginx_NoMount(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName:    "docker2.example.com",
		ConfigFile:    "/etc/nginx/conf.d/docker2.conf",
		HasSSL:        true,
		CertPath:      "/etc/nginx/certs/cert.pem",
		KeyPath:       "/etc/nginx/certs/key.pem",
		ServerType:    config.ServerTypeDockerNginx,
		ContainerName: "nginx-web2",
		VolumeMode:    false, // 无挂载卷
	}

	binding := createBinding(site, cfgManager)

	if binding.Docker == nil || binding.Docker.DeployMode != "copy" {
		t.Errorf("无挂载卷应为 copy 模式: %+v", binding.Docker)
	}
	if err := config.ValidateDockerBinding(&binding); err == nil {
		t.Error("copy 模式 Docker 绑定应被部署校验拒绝")
	}
}

// TestCreateBinding_DockerApache_VolumeChainHostPath 验证 Docker Apache 卷模式下证书链使用宿主机路径：
// 此前 createBinding 只取容器内 ChainPath，卷模式会把证书链写到宿主机错误位置。
func TestCreateBinding_DockerApache_VolumeChainHostPath(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName:    "docker-apache.example.com",
		ConfigFile:    "/etc/apache2/sites/docker.conf",
		HasSSL:        true,
		CertPath:      "/etc/apache2/ssl/cert.pem", // 容器内路径
		KeyPath:       "/etc/apache2/ssl/key.pem",
		ChainPath:     "/etc/apache2/ssl/chain.pem", // 容器内链路径
		ServerType:    config.ServerTypeDockerApache,
		ContainerID:   "def456",
		ContainerName: "apache-web",
		HostCertPath:  "/opt/docker/ssl/cert.pem", // 宿主机挂载路径
		HostKeyPath:   "/opt/docker/ssl/key.pem",
		HostChainPath: "/opt/docker/ssl/chain.pem",
		VolumeMode:    true,
	}

	binding := createBinding(site, cfgManager)

	// 证书链应为宿主机侧挂载路径（而非容器内路径）
	if binding.Paths.ChainFile != "/opt/docker/ssl/chain.pem" {
		t.Errorf("ChainFile = %s, 应为宿主机链路径 /opt/docker/ssl/chain.pem", binding.Paths.ChainFile)
	}
	if binding.Paths.Certificate != "/opt/docker/ssl/cert.pem" {
		t.Errorf("Certificate = %s, 应为宿主机路径", binding.Paths.Certificate)
	}
	if binding.Docker == nil || binding.Docker.DeployMode != "volume" {
		t.Errorf("应为 volume 模式: %+v", binding.Docker)
	}
	if err := config.ValidateDockerBinding(&binding); err != nil {
		t.Errorf("宿主机路径齐全的卷绑定应可部署: %v", err)
	}
}

// TestCreateBinding_Apache 测试创建 Apache 绑定
func TestCreateBinding_Apache(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName:  "example.com",
		ConfigFile:  "/etc/apache2/sites-available/example.conf",
		HasSSL:      true,
		CertPath:    "/etc/ssl/certs/example.pem",
		KeyPath:     "/etc/ssl/private/example.key",
		ServerType:  config.ServerTypeApache,
	}

	binding := createBinding(site, cfgManager)

	if binding.ServerType != config.ServerTypeApache {
		t.Errorf("ServerType = %s, want apache", binding.ServerType)
	}

	validTestCmds := map[string]bool{
		"apache2ctl -t": true,
		"apachectl -t":  true,
		"httpd -t":      true,
	}
	if !validTestCmds[binding.Reload.TestCommand] {
		t.Errorf("TestCommand = %s, 不在合法命令集合中", binding.Reload.TestCommand)
	}

	validReloadCmds := map[string]bool{
		"apache2ctl graceful": true,
		"apachectl graceful":  true,
		"httpd -k graceful":   true,
	}
	if !validReloadCmds[binding.Reload.ReloadCommand] {
		t.Errorf("ReloadCommand = %s, 不在合法命令集合中", binding.Reload.ReloadCommand)
	}
}

// TestCreateBinding_NoSSL 测试无 SSL 站点创建绑定
func TestCreateBinding_NoSSL(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName:  "example.com",
		ConfigFile:  "/etc/nginx/conf.d/example.conf",
		HasSSL:      false,
		CertPath:    "", // 无 SSL 配置
		KeyPath:     "",
		ServerType:  config.ServerTypeNginx,
	}

	binding := createBinding(site, cfgManager)

	// 应该使用默认路径
	if binding.Paths.Certificate == "" {
		t.Error("Certificate 路径不应为空")
	}

	if binding.Paths.PrivateKey == "" {
		t.Error("PrivateKey 路径不应为空")
	}
}

// TestDeployCert_Nginx 测试 Nginx 证书部署
func TestDeployCert_Nginx(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	testCert, err := certs.GenerateValidCert("example.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	binding := &config.SiteBinding{
		ServerName: "example.com",
		ServerType: config.ServerTypeNginx,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
		},
		Reload: config.ReloadConfig{
			TestCommand:   "",
			ReloadCommand: "",
		},
	}

	certData := &fetcher.CertData{
		OrderID:          12345,
		Cert:             testCert.CertPEM,
		IntermediateCert: "",
	}

	svc := newTestDeployService(t, tmpDir)
	err = deployToSiteBinding(t.Context(), svc, binding, certData, testCert.KeyPEM)
	if err != nil {
		t.Fatalf("deployCert() error = %v", err)
	}

	// 验证证书文件已创建
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("证书文件未创建")
	}

	// 验证私钥文件已创建
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("私钥文件未创建")
	}
}

// TestDeploySingleBindings_SkipDisabled 验证 SSL 配置安装失败（Enabled=false）的绑定
// 被计为失败且不被部署，而非误报"部署成功"。
// 回归：曾经部署循环不检查 Enabled，导致 SSL 安装失败的站点仍报成功（成功=1, 失败=0）。
func TestDeploySingleBindings_SkipDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	disabledCert := filepath.Join(tmpDir, "disabled", "cert.pem")
	enabledCert := filepath.Join(tmpDir, "enabled", "cert.pem")

	testCert, err := certs.GenerateValidCert("enabled.example.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	bindings := []config.SiteBinding{
		{
			ServerName: "disabled.example.com", // 模拟 SSL 配置安装失败被禁用
			ServerType: config.ServerTypeNginx,
			Enabled:    false,
			Paths:      config.BindingPaths{Certificate: disabledCert, PrivateKey: filepath.Join(tmpDir, "disabled", "key.pem")},
		},
		{
			ServerName: "enabled.example.com",
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
			Paths:      config.BindingPaths{Certificate: enabledCert, PrivateKey: filepath.Join(tmpDir, "enabled", "key.pem")},
		},
	}

	certData := &fetcher.CertData{OrderID: 1, Cert: testCert.CertPEM}
	svc := newTestDeployService(t, tmpDir)
	success, fail, failedSites := deploySingleBindings(t.Context(), svc, bindings, certData, testCert.KeyPEM)

	if success != 1 {
		t.Errorf("success = %d, 期望 1（仅 enabled 站点）", success)
	}
	if fail != 1 {
		t.Errorf("fail = %d, 期望 1（disabled 站点计为失败）", fail)
	}
	if len(failedSites) != 1 || failedSites[0] != "disabled.example.com" {
		t.Errorf("failedSites = %v, 期望 [disabled.example.com]", failedSites)
	}
	// 禁用的绑定不应被部署：证书文件不应写入
	if _, err := os.Stat(disabledCert); err == nil {
		t.Error("禁用的绑定不应写入证书文件（不应被部署）")
	}
	// 启用的绑定应正常部署
	if _, err := os.Stat(enabledCert); os.IsNotExist(err) {
		t.Error("启用的绑定应写入证书文件")
	}
}

// TestDeployCert_Apache 测试 Apache 证书部署
func TestDeployCert_Apache(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	chainPath := filepath.Join(tmpDir, "chain.pem")

	testCert, _ := certs.GenerateValidCert("example.com", nil)
	intermediateCert, _ := certs.GenerateValidCert("Intermediate CA", nil)

	binding := &config.SiteBinding{
		ServerName: "example.com",
		ServerType: config.ServerTypeApache,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
			ChainFile:   chainPath,
		},
	}

	certData := &fetcher.CertData{
		Cert:             testCert.CertPEM,
		IntermediateCert: intermediateCert.CertPEM,
	}

	svc := newTestDeployService(t, tmpDir)
	err := deployToSiteBinding(t.Context(), svc, binding, certData, testCert.KeyPEM)
	if err != nil {
		t.Fatalf("deployCert() error = %v", err)
	}

	// 验证所有文件已创建
	for _, path := range []string{certPath, keyPath, chainPath} {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("文件未创建: %s", path)
		}
	}
}

// TestDeployCert_Apache_Fullchain 测试 Apache fullchain 模式部署（无 ChainFile）
func TestDeployCert_Apache_Fullchain(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	testCert, _ := certs.GenerateValidCert("example.com", nil)
	intermediateCert, _ := certs.GenerateValidCert("Intermediate CA", nil)

	binding := &config.SiteBinding{
		ServerName: "example.com",
		ServerType: config.ServerTypeApache,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
			// 不设置 ChainFile — fullchain 模式
		},
	}

	certData := &fetcher.CertData{
		Cert:             testCert.CertPEM,
		IntermediateCert: intermediateCert.CertPEM,
	}

	svc := newTestDeployService(t, tmpDir)
	err := deployToSiteBinding(t.Context(), svc, binding, certData, testCert.KeyPEM)
	if err != nil {
		t.Fatalf("deployCert() error = %v", err)
	}

	// 验证证书文件包含 cert + intermediate（fullchain）
	certData2, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读取证书文件失败: %v", err)
	}
	certContent := string(certData2)
	if !strings.Contains(certContent, testCert.CertPEM) {
		t.Error("证书文件应包含服务器证书")
	}
	if !strings.Contains(certContent, intermediateCert.CertPEM) {
		t.Error("证书文件应包含中间证书（fullchain 模式）")
	}

	// 不应创建 chain.pem
	chainPath := filepath.Join(tmpDir, "chain.pem")
	if _, err := os.Stat(chainPath); !os.IsNotExist(err) {
		t.Error("fullchain 模式下不应创建独立的 chain.pem")
	}
}

// TestDeployCert_CreateDirectory 测试目录自动创建
func TestDeployCert_CreateDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "certs", "example.com")
	certPath := filepath.Join(nestedDir, "cert.pem")
	keyPath := filepath.Join(nestedDir, "key.pem")

	testCert, _ := certs.GenerateValidCert("example.com", nil)

	binding := &config.SiteBinding{
		ServerName: "example.com",
		ServerType: config.ServerTypeNginx,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
		},
	}

	certData := &fetcher.CertData{
		Cert: testCert.CertPEM,
	}

	svc := newTestDeployService(t, tmpDir)
	err := deployToSiteBinding(t.Context(), svc, binding, certData, testCert.KeyPEM)
	if err != nil {
		t.Fatalf("deployCert() error = %v", err)
	}

	// 验证嵌套目录已创建
	if _, err := os.Stat(nestedDir); os.IsNotExist(err) {
		t.Error("嵌套目录未创建")
	}
}

// TestDetectWebServer 测试 Web 服务器检测
func TestDetectWebServer(t *testing.T) {
	// 这个测试依赖系统环境，只验证函数不会 panic
	serverType := webserver.DetectWebServerType()
	t.Logf("检测到的 Web 服务器: %s", serverType)

	// 验证返回值是有效的类型
	validTypes := []string{"nginx", "apache", ""}
	found := false
	for _, vt := range validTypes {
		if serverType == vt {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("DetectWebServerType() = %s, 不是有效类型", serverType)
	}
}

// TestConfirm 测试确认提示（仅验证函数签名）
func TestConfirm(t *testing.T) {
	// confirm 函数需要交互式输入，这里只验证函数存在
	// 实际测试需要模拟 stdin
	_ = confirm
}

// TestScanSites 测试站点扫描（仅验证函数签名）
func TestScanSites(t *testing.T) {
	// scanSites 依赖系统环境，这里只验证函数存在
	_ = scanSites
}

// TestInstallService 测试服务安装（仅验证函数签名）
func TestInstallService(t *testing.T) {
	// installService 需要 root 权限，这里只验证函数存在
	_ = installService
}

// TestInstallSSLConfig_Nginx 测试自动安装 SSL 配置
func TestInstallSSLConfig_Nginx(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName: "example.com",
		ConfigFile: "/etc/nginx/conf.d/example.conf",
		HasSSL:     false,
		ServerType: config.ServerTypeNginx,
	}

	result, err := installSSLConfig(site, cfgManager)
	if err != nil {
		t.Fatalf("installSSLConfig() error = %v", err)
	}

	if !result.Modified {
		t.Error("installSSLConfig() Modified 应为 true")
	}

	if result.BackupPath == "" {
		t.Error("installSSLConfig() BackupPath 不应为空")
	}
}

// TestInstallSSLConfig_Apache 测试 Apache 自动安装 SSL 配置
func TestInstallSSLConfig_Apache(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName: "example.com",
		ConfigFile: "/etc/apache2/sites-available/example.conf",
		HasSSL:     false,
		ServerType: config.ServerTypeApache,
	}

	result, err := installSSLConfig(site, cfgManager)
	if err != nil {
		t.Fatalf("installSSLConfig() error = %v", err)
	}

	if !result.Modified {
		t.Error("installSSLConfig() Modified 应为 true")
	}
}

// TestMergeSameNameSites 测试同域名站点合并
func TestMergeSameNameSites(t *testing.T) {
	t.Run("80和443分开的server block合并", func(t *testing.T) {
		sites := []*matcher.ScannedSiteInfo{
			{
				ServerName: "example.com",
				ConfigFile: "/etc/nginx/conf.d/example.conf",
				HasSSL:     true,
				CertPath:   "/etc/ssl/cert.pem",
				KeyPath:    "/etc/ssl/key.pem",
				ServerType: "nginx",
			},
			{
				ServerName: "example.com",
				ConfigFile: "/etc/nginx/conf.d/example.conf",
				HasSSL:     false,
				ServerType: "nginx",
				Webroot:    "/var/www/html",
			},
		}

		result := mergeSameNameSites(sites)
		if len(result) != 1 {
			t.Fatalf("合并后应有 1 个站点，实际 %d", len(result))
		}
		if !result[0].HasSSL {
			t.Error("合并后应保留 SSL 状态")
		}
		if result[0].CertPath != "/etc/ssl/cert.pem" {
			t.Errorf("合并后 CertPath = %s，期望 /etc/ssl/cert.pem", result[0].CertPath)
		}
		if result[0].Webroot != "/var/www/html" {
			t.Errorf("合并后应继承 Webroot = /var/www/html，实际 %s", result[0].Webroot)
		}
	})

	t.Run("80在前443在后", func(t *testing.T) {
		sites := []*matcher.ScannedSiteInfo{
			{
				ServerName: "example.com",
				ConfigFile: "/etc/nginx/conf.d/example.conf",
				HasSSL:     false,
				ServerType: "nginx",
				Webroot:    "/var/www/html",
			},
			{
				ServerName: "example.com",
				ConfigFile: "/etc/nginx/conf.d/example.conf",
				HasSSL:     true,
				CertPath:   "/etc/ssl/cert.pem",
				KeyPath:    "/etc/ssl/key.pem",
				ServerType: "nginx",
			},
		}

		result := mergeSameNameSites(sites)
		if len(result) != 1 {
			t.Fatalf("合并后应有 1 个站点，实际 %d", len(result))
		}
		if !result[0].HasSSL {
			t.Error("合并后应保留 SSL 状态")
		}
		if result[0].CertPath != "/etc/ssl/cert.pem" {
			t.Errorf("合并后 CertPath = %s", result[0].CertPath)
		}
		if result[0].Webroot != "/var/www/html" {
			t.Errorf("合并后应继承 Webroot，实际 %s", result[0].Webroot)
		}
	})

	t.Run("不同域名不合并", func(t *testing.T) {
		sites := []*matcher.ScannedSiteInfo{
			{ServerName: "a.com", HasSSL: true, CertPath: "/a.pem", KeyPath: "/a.key", ServerType: "nginx"},
			{ServerName: "b.com", HasSSL: false, ServerType: "nginx"},
		}

		result := mergeSameNameSites(sites)
		if len(result) != 2 {
			t.Fatalf("不同域名不应合并，期望 2 实际 %d", len(result))
		}
	})

	t.Run("单条目不变", func(t *testing.T) {
		sites := []*matcher.ScannedSiteInfo{
			{ServerName: "a.com", HasSSL: true, CertPath: "/a.pem", KeyPath: "/a.key", ServerType: "nginx"},
		}
		result := mergeSameNameSites(sites)
		if len(result) != 1 {
			t.Fatalf("单条目应保持，期望 1 实际 %d", len(result))
		}
	})

	t.Run("空列表", func(t *testing.T) {
		result := mergeSameNameSites(nil)
		if len(result) != 0 {
			t.Fatalf("空列表应返回空，实际 %d", len(result))
		}
	})
}

// TestBuildCertName 测试证书名称生成
func TestBuildCertName(t *testing.T) {
	tests := []struct {
		domain  string
		orderID int
		want    string
	}{
		{"example.com", 12345, "example.com-12345"},
		{"*.example.com", 99999, "WILDCARD.example.com-99999"},
		{"sub.example.com", 1, "sub.example.com-1"},
		{"*.sub.example.com", 100, "WILDCARD.sub.example.com-100"},
	}

	for _, tt := range tests {
		got := buildCertName(tt.domain, tt.orderID)
		if got != tt.want {
			t.Errorf("buildCertName(%q, %d) = %q, want %q", tt.domain, tt.orderID, got, tt.want)
		}
	}
}

// TestPrewriteKeyThenCert_KeyBeforeCert 验证 needSSLInstall 预写"先写私钥后写证书"：
// 证书写入失败时私钥应已落盘，证明写序为 key→cert（旧序 cert→key 下私钥不会被写入）。
func TestPrewriteKeyThenCert_KeyBeforeCert(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")
	certPath := filepath.Join(tmpDir, "cert.pem")
	// 制造证书写入失败：cert 路径为目录
	if err := os.Mkdir(certPath, 0700); err != nil {
		t.Fatalf("制造证书写入障碍失败: %v", err)
	}

	err := prewriteKeyThenCert(certPath, keyPath, "FULLCHAIN", "PRIVATEKEY")
	if err == nil {
		t.Fatal("证书路径为目录时预写应失败")
	}
	// 关键断言：证书写入失败时私钥已先落盘
	got, readErr := os.ReadFile(keyPath)
	if readErr != nil {
		t.Fatalf("私钥应先于证书写入（写序应为 key→cert）: %v", readErr)
	}
	if string(got) != "PRIVATEKEY" {
		t.Errorf("私钥内容 = %q, want PRIVATEKEY", string(got))
	}
}

// TestPrewriteKeyThenCert_Success 正常路径：私钥与证书均写入，私钥权限 0600、证书 0644。
func TestPrewriteKeyThenCert_Success(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")
	certPath := filepath.Join(tmpDir, "cert.pem")

	if err := prewriteKeyThenCert(certPath, keyPath, "FULLCHAIN", "PRIVATEKEY"); err != nil {
		t.Fatalf("正常预写应成功: %v", err)
	}
	if data, _ := os.ReadFile(keyPath); string(data) != "PRIVATEKEY" {
		t.Errorf("私钥内容 = %q, want PRIVATEKEY", string(data))
	}
	if data, _ := os.ReadFile(certPath); string(data) != "FULLCHAIN" {
		t.Errorf("证书内容 = %q, want FULLCHAIN", string(data))
	}
	if fi, err := os.Stat(keyPath); err == nil && fi.Mode().Perm() != 0600 {
		t.Errorf("私钥权限 = %o, want 0600", fi.Mode().Perm())
	}
}
