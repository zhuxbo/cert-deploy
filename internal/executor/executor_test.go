// Package executor 命令执行器测试
package executor

import (
	"testing"
)

// TestParseCommand 测试命令解析
func TestParseCommand(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantExec     string
		wantArgsLen  int
	}{
		{"空命令", "", "", 0},
		{"单个命令", "nginx", "nginx", 0},
		{"带参数", "nginx -t", "nginx", 1},
		{"多个参数", "systemctl reload nginx", "systemctl", 2},
		{"带路径", "/usr/sbin/nginx -s reload", "/usr/sbin/nginx", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec, args := ParseCommand(tt.input)
			if exec != tt.wantExec {
				t.Errorf("ParseCommand() exec = %q, want %q", exec, tt.wantExec)
			}
			if len(args) != tt.wantArgsLen {
				t.Errorf("ParseCommand() args len = %d, want %d", len(args), tt.wantArgsLen)
			}
		})
	}
}

// TestIsAllowed 测试命令白名单检查
func TestIsAllowed(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		allowed bool
	}{
		// 允许的命令
		{"nginx测试", "nginx -t", true},
		{"nginx重载", "nginx -s reload", true},
		{"systemctl重载nginx", "systemctl reload nginx", true},
		{"service重载nginx", "service nginx reload", true},
		{"apachectl测试", "apachectl -t", true},
		{"sslctl服务启动", "systemctl start sslctl", true},
		{"sslctl服务停止", "systemctl stop sslctl", true},

		// 不允许的命令
		{"rm命令", "rm -rf /", false},
		{"cat命令", "cat /etc/passwd", false},
		{"curl命令", "curl http://evil.com", false},
		{"shell注入", "nginx -t; rm -rf /", false},
		{"管道注入", "nginx -t | cat /etc/passwd", false},
		{"空命令", "", false},
		{"未知命令", "unknown-command", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAllowed(tt.cmd)
			if got != tt.allowed {
				t.Errorf("IsAllowed(%q) = %v, want %v", tt.cmd, got, tt.allowed)
			}
		})
	}
}

// TestRun_NotAllowed 测试执行不在白名单中的命令
func TestRun_NotAllowed(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
	}{
		{"rm命令", "rm -rf /tmp/test"},
		{"cat命令", "cat /etc/passwd"},
		{"shell注入", "nginx -t; echo hacked"},
		{"空命令", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Run(tt.cmd)
			if err == nil {
				t.Errorf("Run(%q) 应该返回错误，但返回了 nil", tt.cmd)
			}
			if err != nil && !contains(err.Error(), "whitelist") {
				t.Errorf("Run(%q) 错误信息应包含 'whitelist'，实际: %v", tt.cmd, err)
			}
		})
	}
}

// TestRunOutput_NotAllowed 测试执行不在白名单中的命令
func TestRunOutput_NotAllowed(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
	}{
		{"rm命令", "rm -rf /tmp/test"},
		{"echo命令", "echo hello"},
		{"shell注入", "nginx -t && echo hacked"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RunOutput(tt.cmd)
			if err == nil {
				t.Errorf("RunOutput(%q) 应该返回错误，但返回了 nil", tt.cmd)
			}
			if err != nil && !contains(err.Error(), "whitelist") {
				t.Errorf("RunOutput(%q) 错误信息应包含 'whitelist'，实际: %v", tt.cmd, err)
			}
		})
	}
}

// TestRunScan_ValidExecutable 测试允许的扫描可执行文件
func TestRunScan_ValidExecutable(t *testing.T) {
	// 测试允许的可执行文件名
	validExecutables := []string{
		"nginx",
		"nginx.exe",
		"/usr/sbin/nginx",
	}

	validArgs := []string{"-t", "-T", "-V"}

	for _, exec := range validExecutables {
		for _, arg := range validArgs {
			t.Run(exec+"_"+arg, func(t *testing.T) {
				// 注意：这里只测试白名单验证通过，实际命令可能因为可执行文件不存在而失败
				_, err := RunScan(exec, arg)
				// 如果错误包含 "not in scan whitelist"，说明白名单验证失败
				if err != nil && contains(err.Error(), "not in scan whitelist") {
					t.Errorf("RunScan(%q, %q) 不应该因为白名单拒绝", exec, arg)
				}
			})
		}
	}
}

// TestRunScan_InvalidExecutable 测试不允许的扫描可执行文件
func TestRunScan_InvalidExecutable(t *testing.T) {
	tests := []struct {
		name string
		exec string
		args []string
	}{
		{"bash", "bash", []string{"-c", "echo hacked"}},
		{"sh", "sh", []string{"-c", "cat /etc/passwd"}},
		{"rm", "rm", []string{"-rf", "/"}},
		{"curl", "curl", []string{"http://evil.com"}},
		{"python", "python", []string{"-c", "import os; os.system('id')"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RunScan(tt.exec, tt.args...)
			if err == nil {
				t.Errorf("RunScan(%q, %v) 应该返回错误，但返回了 nil", tt.exec, tt.args)
			}
			if err != nil && !contains(err.Error(), "not in scan whitelist") {
				t.Errorf("RunScan(%q, %v) 错误信息应包含 'not in scan whitelist'，实际: %v", tt.exec, tt.args, err)
			}
		})
	}
}

// TestRunScan_InvalidArgs 测试不允许的扫描参数
func TestRunScan_InvalidArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"危险参数-c", []string{"-c", "echo hacked"}},
		{"未知参数", []string{"-unknown"}},
		{"路径参数", []string{"/etc/passwd"}},
		{"命令注入", []string{"-t;", "rm", "-rf", "/"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RunScan("nginx", tt.args...)
			if err == nil {
				t.Errorf("RunScan(nginx, %v) 应该返回错误，但返回了 nil", tt.args)
			}
			if err != nil && !contains(err.Error(), "not in scan whitelist") {
				t.Errorf("RunScan(nginx, %v) 错误信息应包含 'not in scan whitelist'，实际: %v", tt.args, err)
			}
		})
	}
}

// TestAllowedCommands_Coverage 测试白名单覆盖率
func TestAllowedCommands_Coverage(t *testing.T) {
	// 确保关键命令在白名单中
	requiredCommands := []string{
		// Nginx
		"nginx -t",
		"nginx -s reload",
		"nginx -V",
		"nginx -T",
		"systemctl reload nginx",
		"service nginx reload",
		// Apache
		"apachectl -t",
		"apachectl graceful",
		"apache2ctl -t",
		"httpd -t",
		// sslctl 服务
		"systemctl start sslctl",
		"systemctl stop sslctl",
		"systemctl restart sslctl",
	}

	for _, cmd := range requiredCommands {
		if !AllowedCommands[cmd] {
			t.Errorf("关键命令 %q 不在白名单中", cmd)
		}
	}
}

// TestAllowedScanExecutables_Coverage 测试扫描可执行文件白名单
func TestAllowedScanExecutables_Coverage(t *testing.T) {
	requiredExecutables := []string{
		"nginx",
		"nginx.exe",
		"/usr/sbin/nginx",
	}

	for _, exec := range requiredExecutables {
		if !AllowedScanExecutables[exec] {
			t.Errorf("扫描可执行文件 %q 不在白名单中", exec)
		}
	}
}

// TestAllowedScanArgs_Coverage 测试扫描参数白名单
func TestAllowedScanArgs_Coverage(t *testing.T) {
	requiredArgs := []string{"-t", "-T", "-V"}

	for _, arg := range requiredArgs {
		if !AllowedScanArgs[arg] {
			t.Errorf("扫描参数 %q 不在白名单中", arg)
		}
	}
}

// TestRunContext_NotAllowed 测试 RunContext 白名单机制
func TestRunContext_NotAllowed(t *testing.T) {
	ctx := t.Context()
	err := RunContext(ctx, "rm -rf /")
	if err == nil {
		t.Error("RunContext() 不在白名单的命令应返回错误")
	}
	if err != nil && !contains(err.Error(), "whitelist") {
		t.Errorf("RunContext() 错误应包含 'whitelist': %v", err)
	}
}

// TestRunOutputContext_NotAllowed 测试 RunOutputContext 白名单机制
func TestRunOutputContext_NotAllowed(t *testing.T) {
	ctx := t.Context()
	_, err := RunOutputContext(ctx, "echo hello")
	if err == nil {
		t.Error("RunOutputContext() 不在白名单的命令应返回错误")
	}
}

// TestRunScanContext_NotAllowed 测试 RunScanContext 白名单机制
func TestRunScanContext_NotAllowed(t *testing.T) {
	ctx := t.Context()
	_, err := RunScanContext(ctx, "bash", "-c", "echo")
	if err == nil {
		t.Error("RunScanContext() 不在白名单的可执行文件应返回错误")
	}
	if err != nil && !contains(err.Error(), "not in scan whitelist") {
		t.Errorf("RunScanContext() 错误应包含 'not in scan whitelist': %v", err)
	}
}

// TestRunScanContext_ArgsWithValueParam 测试带值参数跳过白名单检查逻辑
func TestRunScanContext_ArgsWithValueParam(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name        string
		executable  string
		args        []string
		shouldBlock bool // true 表示应被白名单拒绝
	}{
		{
			name:        "-p带路径值应跳过",
			executable:  "nginx",
			args:        []string{"-p", "/custom/path"},
			shouldBlock: false,
		},
		{
			name:        "-k带信号值应跳过",
			executable:  "nginx",
			args:        []string{"-k", "reload"},
			shouldBlock: false,
		},
		{
			name:        "-p带Windows路径",
			executable:  "nginx",
			args:        []string{"-t", "-p", "C:\\nginx\\conf"},
			shouldBlock: false,
		},
		{
			name:        "-k带graceful",
			executable:  "httpd",
			args:        []string{"-k", "graceful"},
			shouldBlock: false,
		},
		{
			name:        "不带值的非法参数应拒绝",
			executable:  "nginx",
			args:        []string{"--evil-flag"},
			shouldBlock: true,
		},
		{
			name:        "非法参数在合法参数之后",
			executable:  "nginx",
			args:        []string{"-t", "--inject"},
			shouldBlock: true,
		},
		{
			name:        "-p后无值且后面跟非法参数",
			executable:  "nginx",
			args:        []string{"-p"},
			shouldBlock: false, // -p 是合法参数，只是没有下一个值可跳过
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RunScanContext(ctx, tt.executable, tt.args...)
			if tt.shouldBlock {
				if err == nil {
					t.Errorf("RunScanContext(%q, %v) 应该返回错误", tt.executable, tt.args)
				} else if !contains(err.Error(), "not in scan whitelist") {
					t.Errorf("RunScanContext(%q, %v) 应因白名单拒绝，实际错误: %v", tt.executable, tt.args, err)
				}
			} else {
				// 不应被白名单拒绝（命令执行失败是允许的）
				if err != nil && contains(err.Error(), "not in scan whitelist") {
					t.Errorf("RunScanContext(%q, %v) 不应被白名单拒绝，但收到: %v", tt.executable, tt.args, err)
				}
			}
		})
	}
}

// TestRunDetached_NotAllowed 测试 RunDetached 拒绝非白名单可执行文件
func TestRunDetached_NotAllowed(t *testing.T) {
	tests := []struct {
		name       string
		executable string
		args       []string
	}{
		{"bash被拒绝", "bash", []string{"-c", "echo hacked"}},
		{"rm被拒绝", "rm", []string{"-rf", "/"}},
		{"python被拒绝", "python", []string{"-c", "print('hi')"}},
		{"curl被拒绝", "curl", []string{"http://evil.com"}},
		{"完整路径被拒绝", "/usr/bin/bash", []string{"-c", "echo"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RunDetached(tt.executable, tt.args...)
			if err == nil {
				t.Errorf("RunDetached(%q, %v) 应该返回错误", tt.executable, tt.args)
			}
			if err != nil && !contains(err.Error(), "not in whitelist") {
				t.Errorf("RunDetached(%q, %v) 错误应包含 'not in whitelist'，实际: %v", tt.executable, tt.args, err)
			}
		})
	}
}

// TestRunDetached_Allowed 测试 RunDetached 允许白名单内的可执行文件
func TestRunDetached_Allowed(t *testing.T) {
	tests := []struct {
		name       string
		executable string
		args       []string
	}{
		{"nginx直接名称", "nginx", []string{"-s", "reload"}},
		{"httpd直接名称", "httpd", nil},
		{"绝对路径提取basename", "/usr/sbin/nginx", []string{"-t"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RunDetached(tt.executable, tt.args...)
			// 不应因白名单拒绝（实际执行失败是预期的，如可执行文件不存在）
			if err != nil && contains(err.Error(), "not in whitelist") {
				t.Errorf("RunDetached(%q, %v) 不应被白名单拒绝，但收到: %v", tt.executable, tt.args, err)
			}
		})
	}
}

// TestRunContext_DynamicFallback 测试绝对路径动态回退到 RunScanContext
func TestRunContext_DynamicFallback(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name        string
		cmd         string
		shouldBlock bool // true 表示应被白名单拒绝
	}{
		{
			name:        "非标准路径nginx-t通过动态回退",
			cmd:         "/usr/local/nginx/sbin/nginx -t",
			shouldBlock: false,
		},
		{
			name:        "非标准路径nginx-T通过动态回退",
			cmd:         "/opt/nginx/sbin/nginx -T",
			shouldBlock: false,
		},
		{
			name:        "非标准路径httpd-t通过动态回退",
			cmd:         "/opt/apache/bin/httpd -t",
			shouldBlock: false,
		},
		{
			name:        "非白名单可执行文件被拒绝",
			cmd:         "/usr/bin/bash -c echo",
			shouldBlock: true,
		},
		{
			name:        "无参数的未知命令被拒绝",
			cmd:         "unknown-tool",
			shouldBlock: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RunContext(ctx, tt.cmd)
			if tt.shouldBlock {
				if err == nil {
					t.Errorf("RunContext(%q) 应该返回错误", tt.cmd)
				}
				// 对于白名单拒绝，检查错误信息
				if err != nil && !contains(err.Error(), "whitelist") && !contains(err.Error(), "not in scan whitelist") {
					t.Errorf("RunContext(%q) 应因白名单拒绝，实际错误: %v", tt.cmd, err)
				}
			} else {
				// 不应因白名单拒绝（命令执行失败是允许的）
				if err != nil && (contains(err.Error(), "not in whitelist") || contains(err.Error(), "not in scan whitelist")) {
					t.Errorf("RunContext(%q) 不应被白名单拒绝，但收到: %v", tt.cmd, err)
				}
			}
		})
	}
}

// TestDefaultTimeout 测试默认超时常量
func TestDefaultTimeout(t *testing.T) {
	if DefaultTimeout <= 0 {
		t.Error("DefaultTimeout 应大于 0")
	}
	if DefaultTimeout.Seconds() != 30 {
		t.Errorf("DefaultTimeout = %v, 期望 30s", DefaultTimeout)
	}
}

// contains 检查字符串是否包含子串
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && searchSubstring(s, substr)))
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
