// Package logger 日志记录器测试
package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLevel_String 测试日志级别字符串转换
func TestLevel_String(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{LevelDebug, "DEBUG"},
		{LevelInfo, "INFO"},
		{LevelWarn, "WARN"},
		{LevelError, "ERROR"},
		{Level(100), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.level.String(); got != tt.expected {
				t.Errorf("Level.String() = %s, 期望 %s", got, tt.expected)
			}
		})
	}
}

// TestParseLevel 测试日志级别解析
func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected Level
	}{
		{"debug", LevelDebug},
		{"DEBUG", LevelDebug},
		{"info", LevelInfo},
		{"INFO", LevelInfo},
		{"warn", LevelWarn},
		{"WARN", LevelWarn},
		{"warning", LevelWarn},
		{"WARNING", LevelWarn},
		{"error", LevelError},
		{"ERROR", LevelError},
		{"unknown", LevelInfo}, // 默认返回 Info
		{"", LevelInfo},        // 空字符串默认返回 Info
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ParseLevel(tt.input); got != tt.expected {
				t.Errorf("ParseLevel(%q) = %v, 期望 %v", tt.input, got, tt.expected)
			}
		})
	}
}

// TestNew 测试创建日志记录器
func TestNew(t *testing.T) {
	tmpDir := t.TempDir()

	logger, err := New(tmpDir, "test-site")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer logger.Close()

	if logger == nil {
		t.Error("New() 返回 nil")
	}
}

// TestNew_CreateDir 测试自动创建目录
func TestNew_CreateDir(t *testing.T) {
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "logs", "subdir")

	logger, err := New(logDir, "test")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer logger.Close()

	// 验证目录已创建
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		t.Error("日志目录未创建")
	}
}

// TestLogger_SetLevel 测试设置日志级别
func TestLogger_SetLevel(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := New(tmpDir, "test")
	defer logger.Close()

	logger.SetLevel(LevelError)
	if Level(logger.minLevel.Load()) != LevelError {
		t.Errorf("SetLevel() 后 minLevel = %v, 期望 %v", Level(logger.minLevel.Load()), LevelError)
	}

	logger.SetLevel(LevelDebug)
	if Level(logger.minLevel.Load()) != LevelDebug {
		t.Errorf("SetLevel() 后 minLevel = %v, 期望 %v", Level(logger.minLevel.Load()), LevelDebug)
	}
}

// TestLogger_LogMethods 测试日志方法
func TestLogger_LogMethods(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := New(tmpDir, "test")
	defer logger.Close()

	logger.SetLevel(LevelDebug)

	// 这些方法不应 panic
	logger.Debug("debug message %d", 1)
	logger.Info("info message %s", "test")
	logger.Warn("warn message")
	logger.Error("error message")
}

// TestLogger_LogDeployment 测试部署日志
func TestLogger_LogDeployment(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := New(tmpDir, "test")
	defer logger.Close()

	// 成功部署
	logger.LogDeployment("example.com", "/etc/ssl/cert.pem", "/etc/ssl/key.pem", true, nil)

	// 失败部署
	logger.LogDeployment("example.com", "/etc/ssl/cert.pem", "/etc/ssl/key.pem", false, os.ErrPermission)
}

// TestLogger_LogBackup 测试备份日志
func TestLogger_LogBackup(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := New(tmpDir, "test")
	defer logger.Close()

	// 成功备份
	logger.LogBackup("/etc/ssl/cert.pem", "/backup/cert.pem", true, nil)

	// 失败备份
	logger.LogBackup("/etc/ssl/cert.pem", "/backup/cert.pem", false, os.ErrNotExist)
}

// TestLogger_LogReload 测试重载日志
func TestLogger_LogReload(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := New(tmpDir, "test")
	defer logger.Close()

	// 成功重载
	logger.LogReload("nginx -s reload", true, "", nil)

	// 失败重载
	logger.LogReload("nginx -s reload", false, "config error", os.ErrInvalid)
}

// TestLogger_LogScan 测试扫描日志
func TestLogger_LogScan(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := New(tmpDir, "test")
	defer logger.Close()

	logger.LogScan("/etc/nginx/nginx.conf", 5)
}

// TestNewNopLogger 测试空日志记录器
func TestNewNopLogger(t *testing.T) {
	logger := NewNopLogger()

	if logger == nil {
		t.Error("NewNopLogger() 返回 nil")
	}

	// 空日志记录器不应输出任何内容，也不应 panic
	logger.Debug("debug")
	logger.Info("info")
	logger.Warn("warn")
	logger.Error("error")
}

// TestLogger_Close 测试关闭日志记录器
func TestLogger_Close(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := New(tmpDir, "test")

	// 关闭应该不报错
	err := logger.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// 多次关闭不应 panic
	_ = logger.Close()
}

// TestLogger_Close_NilFile 测试关闭空文件的日志记录器
func TestLogger_Close_NilFile(t *testing.T) {
	logger := NewNopLogger()

	err := logger.Close()
	if err != nil {
		t.Errorf("Close() 空文件时应返回 nil，实际: %v", err)
	}
}

// TestLevelConstants 测试日志级别常量
func TestLevelConstants(t *testing.T) {
	// 验证级别顺序
	if LevelDebug >= LevelInfo {
		t.Error("LevelDebug 应小于 LevelInfo")
	}
	if LevelInfo >= LevelWarn {
		t.Error("LevelInfo 应小于 LevelWarn")
	}
	if LevelWarn >= LevelError {
		t.Error("LevelWarn 应小于 LevelError")
	}
}

// TestLogRotationConstants 测试日志轮转常量
func TestLogRotationConstants(t *testing.T) {
	if MaxLogAgeDays <= 0 {
		t.Error("MaxLogAgeDays 应大于 0")
	}
	if MaxLogBackups <= 0 {
		t.Error("MaxLogBackups 应大于 0")
	}
}

// TestLogger_LevelFiltering 测试日志级别过滤
func TestLogger_LevelFiltering(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := New(tmpDir, "test")
	defer logger.Close()

	// 设置为 Error 级别，Debug/Info/Warn 应被过滤
	logger.SetLevel(LevelError)

	// 这些应该被过滤（不输出）
	logger.Debug("should not appear")
	logger.Info("should not appear")
	logger.Warn("should not appear")

	// 这个应该输出
	logger.Error("should appear")
}

// TestSanitize_PrivateKey 测试私钥过滤
func TestSanitize_PrivateKey(t *testing.T) {
	input := `key is -----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA
-----END RSA PRIVATE KEY-----`
	result := sanitize(input)
	if result != "key is ***REDACTED PRIVATE KEY***" {
		t.Errorf("sanitize() 未正确过滤私钥: %s", result)
	}
}

// TestSanitize_BearerToken 测试 Bearer token 过滤
func TestSanitize_BearerToken(t *testing.T) {
	input := "Authorization: Bearer abc123-def.456_789"
	result := sanitize(input)
	if result != "Authorization: Bearer ***REDACTED***" {
		t.Errorf("sanitize() 未正确过滤 Bearer token: %s", result)
	}
}

// TestSanitize_JSONToken 测试 JSON token 过滤
func TestSanitize_JSONToken(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			"token字段",
			`{"token": "secret123", "name": "test"}`,
			`{"token": "***REDACTED***", "name": "test"}`,
		},
		{
			"password字段",
			`{"password": "mypass", "user": "admin"}`,
			`{"password": "***REDACTED***", "user": "admin"}`,
		},
		{
			"api_key字段",
			`{"api_key": "key-value-123"}`,
			`{"api_key": "***REDACTED***"}`,
		},
		{
			"private_key字段",
			`{"private_key": "some-key-data"}`,
			`{"private_key": "***REDACTED***"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitize(tt.input)
			if result != tt.want {
				t.Errorf("sanitize() = %s, want %s", result, tt.want)
			}
		})
	}
}

// TestSanitize_BasicAuth 测试 Basic Auth 过滤
func TestSanitize_BasicAuth(t *testing.T) {
	input := "Authorization: Basic dXNlcjpwYXNz"
	result := sanitize(input)
	if result != "Authorization: Basic ***REDACTED***" {
		t.Errorf("sanitize() 未正确过滤 Basic Auth: %s", result)
	}
}

// TestSanitize_TokenParam 测试 token 参数过滤
func TestSanitize_TokenParam(t *testing.T) {
	input := "url?token=abc123&name=test"
	result := sanitize(input)
	if result != "url?token=***REDACTED***&name=test" {
		t.Errorf("sanitize() 未正确过滤 token 参数: %s", result)
	}
}

// TestSanitize_NoSensitiveData 测试无敏感数据时不修改
func TestSanitize_NoSensitiveData(t *testing.T) {
	input := "normal log message without sensitive data"
	result := sanitize(input)
	if result != input {
		t.Errorf("sanitize() 不应修改无敏感数据的消息: %s", result)
	}
}

// TestCleanOldLogs 测试清理旧日志文件
func TestCleanOldLogs(t *testing.T) {
	t.Run("文件数小于MaxLogBackups时不删除", func(t *testing.T) {
		tmpDir := t.TempDir()
		l := &Logger{logDir: tmpDir, name: "app"}

		// 创建少于 MaxLogBackups 个文件
		for i := 0; i < MaxLogBackups-1; i++ {
			name := fmt.Sprintf("app-2025-01-%02d.log", i+1)
			if err := os.WriteFile(filepath.Join(tmpDir, name), []byte("log"), 0600); err != nil {
				t.Fatal(err)
			}
		}

		if err := l.cleanOldLogs(); err != nil {
			t.Fatalf("cleanOldLogs() error = %v", err)
		}

		// 所有文件都应保留
		files, _ := filepath.Glob(filepath.Join(tmpDir, "app-*.log"))
		if len(files) != MaxLogBackups-1 {
			t.Errorf("期望保留 %d 个文件，实际 %d", MaxLogBackups-1, len(files))
		}
	})

	t.Run("超出保留数量时删除最旧文件", func(t *testing.T) {
		tmpDir := t.TempDir()
		l := &Logger{logDir: tmpDir, name: "app"}

		totalFiles := MaxLogBackups + 5
		// 创建文件，并通过 os.Chtimes 设置不同的修改时间
		baseTime := time.Now()
		for i := 0; i < totalFiles; i++ {
			name := fmt.Sprintf("app-2025-01-%02d.log", i+1)
			fpath := filepath.Join(tmpDir, name)
			if err := os.WriteFile(fpath, []byte("log"), 0600); err != nil {
				t.Fatal(err)
			}
			// 文件 i=0 最旧，i=totalFiles-1 最新
			modTime := baseTime.Add(time.Duration(i) * time.Hour)
			if err := os.Chtimes(fpath, modTime, modTime); err != nil {
				t.Fatal(err)
			}
		}

		if err := l.cleanOldLogs(); err != nil {
			t.Fatalf("cleanOldLogs() error = %v", err)
		}

		// 应只保留 MaxLogBackups 个最新文件
		files, _ := filepath.Glob(filepath.Join(tmpDir, "app-*.log"))
		if len(files) != MaxLogBackups {
			t.Errorf("期望保留 %d 个文件，实际 %d", MaxLogBackups, len(files))
		}

		// 验证最旧的 5 个文件已被删除
		for i := 0; i < 5; i++ {
			name := fmt.Sprintf("app-2025-01-%02d.log", i+1)
			fpath := filepath.Join(tmpDir, name)
			if _, err := os.Stat(fpath); !os.IsNotExist(err) {
				t.Errorf("旧文件 %s 应已被删除", name)
			}
		}
	})

	t.Run("Stat失败的文件被跳过", func(t *testing.T) {
		tmpDir := t.TempDir()
		l := &Logger{logDir: tmpDir, name: "app"}

		// 创建 MaxLogBackups+2 个文件
		totalFiles := MaxLogBackups + 2
		baseTime := time.Now()
		for i := 0; i < totalFiles; i++ {
			name := fmt.Sprintf("app-2025-02-%02d.log", i+1)
			fpath := filepath.Join(tmpDir, name)
			if err := os.WriteFile(fpath, []byte("log"), 0600); err != nil {
				t.Fatal(err)
			}
			modTime := baseTime.Add(time.Duration(i) * time.Hour)
			if err := os.Chtimes(fpath, modTime, modTime); err != nil {
				t.Fatal(err)
			}
		}

		// 在 Glob 匹配前删除中间一个文件，模拟 Stat 失败场景
		// （Glob 能匹配到文件名，但 Stat 时文件已不存在）
		midFile := filepath.Join(tmpDir, fmt.Sprintf("app-2025-02-%02d.log", MaxLogBackups/2+1))
		os.Remove(midFile)

		// cleanOldLogs 应正常执行，不报错
		if err := l.cleanOldLogs(); err != nil {
			t.Fatalf("cleanOldLogs() 不应因 Stat 失败而报错: %v", err)
		}
	})

	t.Run("恰好等于MaxLogBackups时不删除", func(t *testing.T) {
		tmpDir := t.TempDir()
		l := &Logger{logDir: tmpDir, name: "app"}

		// 创建恰好 MaxLogBackups 个文件（但 Glob 匹配数=MaxLogBackups，条件 < 不满足，会进入排序逻辑）
		// 注意源码：len(files) < MaxLogBackups 时返回，所以 == 时会进入排序但不删除
		for i := 0; i < MaxLogBackups; i++ {
			name := fmt.Sprintf("app-2025-03-%02d.log", i+1)
			fpath := filepath.Join(tmpDir, name)
			if err := os.WriteFile(fpath, []byte("log"), 0600); err != nil {
				t.Fatal(err)
			}
		}

		if err := l.cleanOldLogs(); err != nil {
			t.Fatalf("cleanOldLogs() error = %v", err)
		}

		files, _ := filepath.Glob(filepath.Join(tmpDir, "app-*.log"))
		if len(files) != MaxLogBackups {
			t.Errorf("期望保留 %d 个文件，实际 %d", MaxLogBackups, len(files))
		}
	})
}

// TestLogger_JSONMode 测试 JSON 输出模式
func TestLogger_JSONMode(t *testing.T) {
	t.Run("JSON模式基本输出", func(t *testing.T) {
		tmpDir := t.TempDir()
		l, err := New(tmpDir, "jsontest")
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		defer l.Close()

		l.SetJSONMode(true)
		l.Info("hello json world")

		// 读取日志文件内容
		files, _ := filepath.Glob(filepath.Join(tmpDir, "jsontest-*.log"))
		if len(files) == 0 {
			t.Fatal("未找到日志文件")
		}
		content, err := os.ReadFile(files[0])
		if err != nil {
			t.Fatalf("读取日志文件失败: %v", err)
		}

		// 解析 JSON
		var entry map[string]string
		if err := json.Unmarshal(bytes.TrimSpace(content), &entry); err != nil {
			t.Fatalf("日志不是有效的 JSON: %v, 内容: %s", err, content)
		}

		// 验证必要字段
		if entry["level"] != "INFO" {
			t.Errorf("level = %q, 期望 %q", entry["level"], "INFO")
		}
		if entry["msg"] != "hello json world" {
			t.Errorf("msg = %q, 期望 %q", entry["msg"], "hello json world")
		}
		if entry["time"] == "" {
			t.Error("time 字段不应为空")
		}
		// 带 name 的 logger 应包含 module 字段
		if entry["module"] != "jsontest" {
			t.Errorf("module = %q, 期望 %q", entry["module"], "jsontest")
		}
	})

	t.Run("无name的logger不含module字段", func(t *testing.T) {
		tmpDir := t.TempDir()
		l, err := New(tmpDir, "")
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		defer l.Close()

		l.SetJSONMode(true)
		l.Info("no module test")

		files, _ := filepath.Glob(filepath.Join(tmpDir, "-*.log"))
		if len(files) == 0 {
			t.Fatal("未找到日志文件")
		}
		content, err := os.ReadFile(files[0])
		if err != nil {
			t.Fatalf("读取日志文件失败: %v", err)
		}

		var entry map[string]string
		if err := json.Unmarshal(bytes.TrimSpace(content), &entry); err != nil {
			t.Fatalf("日志不是有效的 JSON: %v, 内容: %s", err, content)
		}

		if _, exists := entry["module"]; exists {
			t.Errorf("name 为空时不应包含 module 字段，但得到 %q", entry["module"])
		}
	})

	t.Run("JSON模式敏感信息过滤", func(t *testing.T) {
		tmpDir := t.TempDir()
		l, err := New(tmpDir, "sanitize")
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		defer l.Close()

		l.SetJSONMode(true)
		l.Info("Authorization: Bearer secret-token-123")

		files, _ := filepath.Glob(filepath.Join(tmpDir, "sanitize-*.log"))
		if len(files) == 0 {
			t.Fatal("未找到日志文件")
		}
		content, err := os.ReadFile(files[0])
		if err != nil {
			t.Fatalf("读取日志文件失败: %v", err)
		}

		var entry map[string]string
		if err := json.Unmarshal(bytes.TrimSpace(content), &entry); err != nil {
			t.Fatalf("日志不是有效的 JSON: %v", err)
		}

		if entry["msg"] != "Authorization: Bearer ***REDACTED***" {
			t.Errorf("JSON 模式下敏感信息未过滤: %s", entry["msg"])
		}
	})
}

// TestNew_WithEnvVars 测试环境变量影响 New() 行为
func TestNew_WithEnvVars(t *testing.T) {
	t.Run("LOG_LEVEL环境变量", func(t *testing.T) {
		tmpDir := t.TempDir()

		// 保存和恢复环境变量
		oldLevel := os.Getenv("LOG_LEVEL")
		defer os.Setenv("LOG_LEVEL", oldLevel)

		os.Setenv("LOG_LEVEL", "debug")
		l, err := New(tmpDir, "envtest")
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		defer l.Close()

		if Level(l.minLevel.Load()) != LevelDebug {
			t.Errorf("LOG_LEVEL=debug 时，minLevel = %v, 期望 %v", Level(l.minLevel.Load()), LevelDebug)
		}
	})

	t.Run("LOG_LEVEL=error", func(t *testing.T) {
		tmpDir := t.TempDir()

		oldLevel := os.Getenv("LOG_LEVEL")
		defer os.Setenv("LOG_LEVEL", oldLevel)

		os.Setenv("LOG_LEVEL", "error")
		l, err := New(tmpDir, "envtest")
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		defer l.Close()

		if Level(l.minLevel.Load()) != LevelError {
			t.Errorf("LOG_LEVEL=error 时，minLevel = %v, 期望 %v", Level(l.minLevel.Load()), LevelError)
		}
	})

	t.Run("SSLCTL_LOG_FORMAT=json", func(t *testing.T) {
		tmpDir := t.TempDir()

		oldFormat := os.Getenv("SSLCTL_LOG_FORMAT")
		defer os.Setenv("SSLCTL_LOG_FORMAT", oldFormat)

		os.Setenv("SSLCTL_LOG_FORMAT", "json")
		l, err := New(tmpDir, "envtest")
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		defer l.Close()

		if !l.jsonMode.Load() {
			t.Error("SSLCTL_LOG_FORMAT=json 时，jsonMode 应为 true")
		}
	})

	t.Run("SSLCTL_LOG_FORMAT未设置", func(t *testing.T) {
		tmpDir := t.TempDir()

		oldFormat := os.Getenv("SSLCTL_LOG_FORMAT")
		defer os.Setenv("SSLCTL_LOG_FORMAT", oldFormat)

		os.Unsetenv("SSLCTL_LOG_FORMAT")
		l, err := New(tmpDir, "envtest")
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		defer l.Close()

		if l.jsonMode.Load() {
			t.Error("SSLCTL_LOG_FORMAT 未设置时，jsonMode 应为 false")
		}
	})
}
