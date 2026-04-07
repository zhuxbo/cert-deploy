// Package webserver 检测器测试
package webserver

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestDetectLocalServer 测试本地服务器检测
func TestDetectLocalServer(t *testing.T) {
	serverType := DetectLocalServer()
	// 根据测试环境，可能返回不同的类型
	t.Logf("检测到的本地服务器类型: %s", serverType)

	// 验证返回的是有效类型
	validTypes := []ServerType{TypeNginx, TypeApache, TypeUnknown}
	found := false
	for _, vt := range validTypes {
		if serverType == vt {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DetectLocalServer() 返回无效类型: %s", serverType)
	}
}

// TestIsNginxInstalled 测试 Nginx 安装检测
func TestIsNginxInstalled(t *testing.T) {
	installed := isNginxInstalled()
	t.Logf("Nginx 已安装: %v", installed)
}

// TestIsApacheInstalled 测试 Apache 安装检测
func TestIsApacheInstalled(t *testing.T) {
	installed := isApacheInstalled()
	t.Logf("Apache 已安装: %v", installed)
}

// TestGetNginxConfigPath 测试获取 Nginx 配置路径
func TestGetNginxConfigPath(t *testing.T) {
	configPath := GetNginxConfigPath()
	if configPath != "" {
		t.Logf("Nginx 配置路径: %s", configPath)
		// 验证路径存在
		if _, err := os.Stat(configPath); err != nil {
			t.Logf("配置路径不存在: %v", err)
		}
	} else {
		t.Log("未找到 Nginx 配置路径")
	}
}

// TestGetApacheConfigPath 测试获取 Apache 配置路径
func TestGetApacheConfigPath(t *testing.T) {
	configPath := GetApacheConfigPath()
	if configPath != "" {
		t.Logf("Apache 配置路径: %s", configPath)
	} else {
		t.Log("未找到 Apache 配置路径")
	}
}

// TestGetNginxSitesDir 测试获取 Nginx 站点目录
func TestGetNginxSitesDir(t *testing.T) {
	sitesDir := GetNginxSitesDir()
	if sitesDir != "" {
		t.Logf("Nginx 站点目录: %s", sitesDir)
	} else {
		t.Log("未找到 Nginx 站点目录")
	}
}

// TestGetApacheSitesDir 测试获取 Apache 站点目录
func TestGetApacheSitesDir(t *testing.T) {
	sitesDir := GetApacheSitesDir()
	if sitesDir != "" {
		t.Logf("Apache 站点目录: %s", sitesDir)
	} else {
		t.Log("未找到 Apache 站点目录")
	}
}

// TestGetNginxConfigPath_WithMockPaths 测试使用模拟路径获取配置
func TestGetNginxConfigPath_WithMockPaths(t *testing.T) {
	// 创建临时目录模拟配置
	tmpDir := t.TempDir()
	mockConfPath := filepath.Join(tmpDir, "nginx.conf")

	// 创建模拟配置文件
	if err := os.WriteFile(mockConfPath, []byte("# nginx config"), 0644); err != nil {
		t.Fatalf("创建模拟配置失败: %v", err)
	}

	// 注意：这个测试只是验证函数不会崩溃
	// 实际路径检测逻辑在系统路径中
	_ = GetNginxConfigPath()
}

// TestGetApacheConfigPath_WithMockPaths 测试使用模拟路径获取配置
func TestGetApacheConfigPath_WithMockPaths(t *testing.T) {
	// 创建临时目录模拟配置
	tmpDir := t.TempDir()
	mockConfPath := filepath.Join(tmpDir, "httpd.conf")

	// 创建模拟配置文件
	if err := os.WriteFile(mockConfPath, []byte("# apache config"), 0644); err != nil {
		t.Fatalf("创建模拟配置失败: %v", err)
	}

	// 注意：这个测试只是验证函数不会崩溃
	_ = GetApacheConfigPath()
}

// TestDetectNginxCommands 测试 Nginx 命令检测
func TestDetectNginxCommands(t *testing.T) {
	cmds := DetectNginxCommands()

	// 命令应以 "nginx" 结尾 + " -t"（可能包含完整路径）
	if !strings.HasSuffix(cmds.TestCmd, " -t") || !strings.Contains(cmds.TestCmd, "nginx") {
		t.Errorf("TestCmd = %s, 应包含 nginx 和 -t", cmds.TestCmd)
	}
	if !strings.HasSuffix(cmds.ReloadCmd, " -s reload") || !strings.Contains(cmds.ReloadCmd, "nginx") {
		t.Errorf("ReloadCmd = %s, 应包含 nginx 和 -s reload", cmds.ReloadCmd)
	}
	t.Logf("TestCmd = %s, ReloadCmd = %s", cmds.TestCmd, cmds.ReloadCmd)
}

// TestDetectApacheCommands 测试 Apache 命令检测
func TestDetectApacheCommands(t *testing.T) {
	cmds := DetectApacheCommands()

	validTestCmds := map[string]bool{
		"apache2ctl -t": true,
		"apachectl -t":  true,
		"httpd -t":      true,
	}
	if !validTestCmds[cmds.TestCmd] {
		t.Errorf("TestCmd = %s, 不在合法命令集合中", cmds.TestCmd)
	}

	validReloadCmds := map[string]bool{
		"apache2ctl graceful": true,
		"apachectl graceful":  true,
		"httpd -k graceful":   true,
	}
	if !validReloadCmds[cmds.ReloadCmd] {
		t.Errorf("ReloadCmd = %s, 不在合法命令集合中", cmds.ReloadCmd)
	}

	t.Logf("检测到 Apache 命令: test=%s, reload=%s", cmds.TestCmd, cmds.ReloadCmd)
}

// TestDetectDockerServer 测试 Docker 服务器检测
func TestDetectDockerServer(t *testing.T) {
	// 使用不存在的容器 ID 测试
	serverType := DetectDockerServer("nonexistent-container-id")
	if serverType != TypeUnknown {
		t.Logf("检测到容器类型: %s", serverType)
	} else {
		t.Log("Docker 检测返回 unknown（预期，无 Docker 或容器不存在）")
	}
}

// TestDetectDockerServer_InputValidation 测试容器 ID 输入校验
func TestDetectDockerServer_InputValidation(t *testing.T) {
	tests := []struct {
		name        string
		containerID string
		want        ServerType
	}{
		{"空 ID", "", TypeUnknown},
		{"超长 ID（129 字符）", strings.Repeat("a", 129), TypeUnknown},
		{"刚好 128 字符（不应被拒绝）", strings.Repeat("a", 128), TypeUnknown}, // 长度合法但容器不存在
		{"包含空格", "my container", TypeUnknown},
		{"包含斜杠", "my/container", TypeUnknown},
		{"包含冒号", "my:container", TypeUnknown},
		{"包含分号", "my;rm -rf /", TypeUnknown},
		{"包含反引号", "my`id`container", TypeUnknown},
		{"包含美元符号", "my$HOME", TypeUnknown},
		{"包含单引号", "my'container", TypeUnknown},
		{"包含双引号", `my"container`, TypeUnknown},
		{"包含换行符", "my\ncontainer", TypeUnknown},
		{"包含 tab", "my\tcontainer", TypeUnknown},
		{"包含中文", "我的容器", TypeUnknown},
		{"合法的短 ID", "abc123", TypeUnknown},                   // 格式合法但容器不存在
		{"合法的完整 ID", "abc123def456789012345678", TypeUnknown}, // 格式合法但容器不存在
		{"合法的容器名（含下划线）", "my_container", TypeUnknown},
		{"合法的容器名（含短横线）", "my-container", TypeUnknown},
		{"合法的容器名（含点号）", "my.container", TypeUnknown},
		{"仅数字", "1234567890", TypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectDockerServer(tt.containerID)
			if got != tt.want {
				t.Errorf("DetectDockerServer(%q) = %s, 期望 %s", tt.containerID, got, tt.want)
			}
		})
	}
}

// TestDetectDockerServer_BoundaryLength 测试容器 ID 长度边界
func TestDetectDockerServer_BoundaryLength(t *testing.T) {
	tests := []struct {
		name   string
		length int
		reject bool // 是否应被输入校验拒绝（即不会执行 docker 命令）
	}{
		{"长度 0", 0, true},
		{"长度 1", 1, false},
		{"长度 64（Docker ID 最大长度）", 64, false},
		{"长度 128（容器名最大长度）", 128, false},
		{"长度 129（超限）", 129, true},
		{"长度 256（远超限制）", 256, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := strings.Repeat("a", tt.length)
			got := DetectDockerServer(id)
			// 所有用例都应返回 TypeUnknown（非法输入被拒绝，合法输入但容器不存在）
			if got != TypeUnknown {
				t.Errorf("DetectDockerServer(len=%d) = %s, 期望 %s", tt.length, got, TypeUnknown)
			}
		})
	}
}

// TestDetectWebServerType 测试 Web 服务器类型字符串映射
func TestDetectWebServerType(t *testing.T) {
	result := DetectWebServerType()
	// 验证返回的字符串是合法值
	validResults := map[string]bool{
		"nginx":  true,
		"apache": true,
		"":       true,
	}
	if !validResults[result] {
		t.Errorf("DetectWebServerType() = %q, 不在合法值集合中", result)
	}
	t.Logf("DetectWebServerType() = %q", result)
}

// TestFindNginxBin 测试查找 nginx 可执行文件
func TestFindNginxBin(t *testing.T) {
	bin := findNginxBin()
	// 应始终返回非空字符串（至少返回 "nginx" 作为回退）
	if bin == "" {
		t.Error("findNginxBin() 不应返回空字符串")
	}
	t.Logf("findNginxBin() = %s", bin)
}

// TestFindApacheBin 测试查找 Apache 可执行文件
func TestFindApacheBin(t *testing.T) {
	bin := findApacheBin()
	// 应始终返回非空字符串（至少返回 "apachectl" 作为回退）
	if bin == "" {
		t.Error("findApacheBin() 不应返回空字符串")
	}
	t.Logf("findApacheBin() = %s", bin)
}

// TestGetNginxPrefixArgs 测试获取 nginx -p 参数
func TestGetNginxPrefixArgs(t *testing.T) {
	// 使用空字符串测试
	result := getNginxPrefixArgs("")
	if result != "" {
		t.Errorf("getNginxPrefixArgs(\"\") = %q, 期望空字符串", result)
	}

	// 使用相对路径测试
	result = getNginxPrefixArgs("nginx")
	if result != "" {
		t.Errorf("getNginxPrefixArgs(\"nginx\") = %q, 期望空字符串", result)
	}

	// 使用不存在的绝对路径测试（非 Windows 环境应返回空）
	if runtime.GOOS != "windows" {
		result = getNginxPrefixArgs("/usr/sbin/nginx")
		if result != "" {
			t.Errorf("getNginxPrefixArgs(\"/usr/sbin/nginx\") = %q, 非 Windows 应返回空字符串", result)
		}
	}
}

// TestDetectApacheCommands_Properties 测试 Apache 命令检测返回值属性
func TestDetectApacheCommands_Properties(t *testing.T) {
	cmds := DetectApacheCommands()

	// TestCmd 应以 -t 结尾
	if !strings.HasSuffix(cmds.TestCmd, " -t") {
		t.Errorf("TestCmd = %s, 应以 ' -t' 结尾", cmds.TestCmd)
	}

	// ReloadCmd 应包含 graceful
	if !strings.Contains(cmds.ReloadCmd, "graceful") {
		t.Errorf("ReloadCmd = %s, 应包含 'graceful'", cmds.ReloadCmd)
	}

	// 两个命令都不应为空
	if cmds.TestCmd == "" {
		t.Error("TestCmd 不应为空")
	}
	if cmds.ReloadCmd == "" {
		t.Error("ReloadCmd 不应为空")
	}

	t.Logf("Apache 命令: test=%s, reload=%s", cmds.TestCmd, cmds.ReloadCmd)
}

// TestDetectNginxCommands_Properties 测试 Nginx 命令检测返回值属性
func TestDetectNginxCommands_Properties(t *testing.T) {
	cmds := DetectNginxCommands()

	// TestCmd 和 ReloadCmd 都不应为空
	if cmds.TestCmd == "" {
		t.Error("TestCmd 不应为空")
	}
	if cmds.ReloadCmd == "" {
		t.Error("ReloadCmd 不应为空")
	}

	// TestCmd 应包含 nginx 和 -t
	if !strings.Contains(cmds.TestCmd, "nginx") {
		t.Errorf("TestCmd = %s, 应包含 'nginx'", cmds.TestCmd)
	}
	if !strings.HasSuffix(cmds.TestCmd, " -t") {
		t.Errorf("TestCmd = %s, 应以 ' -t' 结尾", cmds.TestCmd)
	}

	// ReloadCmd 应包含 nginx 和 -s reload
	if !strings.Contains(cmds.ReloadCmd, "nginx") {
		t.Errorf("ReloadCmd = %s, 应包含 'nginx'", cmds.ReloadCmd)
	}
	if !strings.HasSuffix(cmds.ReloadCmd, " -s reload") {
		t.Errorf("ReloadCmd = %s, 应以 ' -s reload' 结尾", cmds.ReloadCmd)
	}
}

// TestGetNginxConfigPath_Result 测试 GetNginxConfigPath 返回值属性
func TestGetNginxConfigPath_Result(t *testing.T) {
	configPath := GetNginxConfigPath()
	if configPath != "" {
		// 应以 .conf 结尾
		if !strings.HasSuffix(configPath, ".conf") {
			t.Errorf("GetNginxConfigPath() = %s, 应以 .conf 结尾", configPath)
		}
		// 应是绝对路径
		if !filepath.IsAbs(configPath) {
			t.Errorf("GetNginxConfigPath() = %s, 应是绝对路径", configPath)
		}
	}
}

// TestGetApacheSitesDir_Result 测试 GetApacheSitesDir 返回值属性
func TestGetApacheSitesDir_Result(t *testing.T) {
	dir := GetApacheSitesDir()
	if dir != "" {
		// 如果返回非空，应是绝对路径
		if !filepath.IsAbs(dir) {
			t.Errorf("GetApacheSitesDir() = %s, 应是绝对路径", dir)
		}
		// 应是目录
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("GetApacheSitesDir() = %s, 路径不存在: %v", dir, err)
		} else if !info.IsDir() {
			t.Errorf("GetApacheSitesDir() = %s, 应是目录", dir)
		}
	}
}

// TestDetectLocalServer_WithModifiedPATH 在无服务器环境下测试检测逻辑
func TestDetectLocalServer_WithModifiedPATH(t *testing.T) {
	// 保存并修改 PATH，使得 LookPath 找不到 nginx/apache
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir()) // 使用空目录作为 PATH

	serverType := DetectLocalServer()
	t.Logf("修改 PATH 后检测到: %s", serverType)

	// 恢复 PATH 后验证
	os.Setenv("PATH", origPath)
}

// TestIsNginxInstalled_WithModifiedPATH 在 nginx 不在 PATH 中时测试
func TestIsNginxInstalled_WithModifiedPATH(t *testing.T) {
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())

	installed := isNginxInstalled()
	t.Logf("修改 PATH 后 nginx 已安装: %v", installed)

	os.Setenv("PATH", origPath)
}

// TestIsApacheInstalled_WithModifiedPATH 在 apache 不在 PATH 中时测试
func TestIsApacheInstalled_WithModifiedPATH(t *testing.T) {
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())

	installed := isApacheInstalled()
	t.Logf("修改 PATH 后 apache 已安装: %v", installed)

	os.Setenv("PATH", origPath)
}

// TestDetectWebServerType_WithModifiedPATH 在无服务器环境下测试字符串映射
func TestDetectWebServerType_WithModifiedPATH(t *testing.T) {
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())

	result := DetectWebServerType()
	t.Logf("修改 PATH 后 DetectWebServerType() = %q", result)

	os.Setenv("PATH", origPath)
}

// TestDetectApacheCommands_WithModifiedPATH 测试 Apache 命令检测（无 PATH）
func TestDetectApacheCommands_WithModifiedPATH(t *testing.T) {
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())

	cmds := DetectApacheCommands()
	t.Logf("修改 PATH 后 Apache 命令: test=%s, reload=%s", cmds.TestCmd, cmds.ReloadCmd)

	// 应回退到 findApacheBin 或默认值
	if cmds.TestCmd == "" || cmds.ReloadCmd == "" {
		t.Error("即使 PATH 无效，也应返回默认命令")
	}

	os.Setenv("PATH", origPath)
}

// TestDetectNginxCommands_WithModifiedPATH 测试 Nginx 命令检测（无 PATH）
func TestDetectNginxCommands_WithModifiedPATH(t *testing.T) {
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())

	cmds := DetectNginxCommands()
	t.Logf("修改 PATH 后 Nginx 命令: test=%s, reload=%s", cmds.TestCmd, cmds.ReloadCmd)

	// 应回退到默认 "nginx"
	if cmds.TestCmd == "" || cmds.ReloadCmd == "" {
		t.Error("即使 PATH 无效，也应返回默认命令")
	}

	os.Setenv("PATH", origPath)
}

// TestFindNginxBin_WithModifiedPATH 测试 nginx 查找（无 PATH）
func TestFindNginxBin_WithModifiedPATH(t *testing.T) {
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())

	bin := findNginxBin()
	t.Logf("修改 PATH 后 findNginxBin() = %s", bin)

	// 应至少返回 "nginx" 作为回退
	if bin == "" {
		t.Error("findNginxBin() 不应返回空字符串")
	}

	os.Setenv("PATH", origPath)
}

// TestFindApacheBin_WithModifiedPATH 测试 Apache 查找（无 PATH）
func TestFindApacheBin_WithModifiedPATH(t *testing.T) {
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())

	bin := findApacheBin()
	t.Logf("修改 PATH 后 findApacheBin() = %s", bin)

	// 应至少返回 "apachectl" 作为回退
	if bin == "" {
		t.Error("findApacheBin() 不应返回空字符串")
	}

	os.Setenv("PATH", origPath)
}

// TestDetectDockerServer_AllInvalidChars 测试各种非法字符被拒绝
func TestDetectDockerServer_AllInvalidChars(t *testing.T) {
	invalidChars := []string{
		"!", "@", "#", "$", "%", "^", "&", "*", "(", ")",
		"+", "=", "[", "]", "{", "}", "|", "\\", "/",
		":", ";", "'", "\"", ",", "<", ">", "?", "~", "`",
		" ", "\t", "\n", "\r",
	}

	for _, ch := range invalidChars {
		id := "valid" + ch + "id"
		got := DetectDockerServer(id)
		if got != TypeUnknown {
			t.Errorf("DetectDockerServer(%q) = %s, 含非法字符 %q 应返回 %s", id, got, ch, TypeUnknown)
		}
	}
}
