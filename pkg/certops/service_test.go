// Package certops 证书操作服务层测试
package certops

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

// TestNewService 测试服务创建
func TestNewService(t *testing.T) {
	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	if svc == nil {
		t.Fatal("NewService 返回 nil")
	}

	// 验证内部组件已正确初始化
	if svc.cfgManager != cm {
		t.Error("cfgManager 未正确初始化")
	}
	if svc.fetcher == nil {
		t.Error("fetcher 未正确初始化")
	}
	if svc.backupMgr == nil {
		t.Error("backupMgr 未正确初始化")
	}
	if svc.log != log {
		t.Error("log 未正确初始化")
	}
}

// TestGetRenewMode 测试获取续签模式
func TestGetRenewMode(t *testing.T) {
	tests := []struct {
		name     string
		schedule config.ScheduleConfig
		want     string
	}{
		{
			name:     "空模式默认为 pull",
			schedule: config.ScheduleConfig{},
			want:     config.RenewModePull,
		},
		{
			name:     "显式 pull 模式",
			schedule: config.ScheduleConfig{RenewMode: config.RenewModePull},
			want:     config.RenewModePull,
		},
		{
			name:     "显式 local 模式",
			schedule: config.ScheduleConfig{RenewMode: config.RenewModeLocal},
			want:     config.RenewModeLocal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getRenewMode(&tt.schedule)
			if got != tt.want {
				t.Errorf("getRenewMode() = %s, 期望 %s", got, tt.want)
			}
		})
	}
}

// writeTestConfig 写入测试配置文件
func writeTestConfig(t *testing.T, dir string, cfg *config.Config) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// captureLogger 创建一个可以捕获日志输出的 Logger（写入文件后读取）
func captureLogger(t *testing.T, dir string) (*logger.Logger, func() string) {
	t.Helper()
	logDir := filepath.Join(dir, "logs")
	log, err := logger.New(logDir, "test")
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}
	log.SetLevel(logger.LevelDebug)

	readLogs := func() string {
		_ = log.Close()
		entries, _ := os.ReadDir(logDir)
		var buf strings.Builder
		for _, e := range entries {
			data, _ := os.ReadFile(filepath.Join(logDir, e.Name()))
			buf.Write(data)
		}
		return buf.String()
	}
	return log, readLogs
}

// TestCheckExpiry 测试证书过期告警逻辑
func TestCheckExpiry(t *testing.T) {
	tests := []struct {
		name       string
		certs      []config.CertConfig
		wantLevel  string // "ERROR", "WARN", "" (无告警)
		wantAbsent string // 不应出现的内容
	}{
		{
			name:      "证书已过期",
			wantLevel: "ERROR",
			certs: []config.CertConfig{
				{
					CertName: "expired-cert",
					Enabled:  true,
					Metadata: config.CertMetadata{
						CertExpiresAt: time.Now().Add(-24 * time.Hour),
					},
				},
			},
		},
		{
			name:      "7天内过期",
			wantLevel: "ERROR",
			certs: []config.CertConfig{
				{
					CertName: "soon-cert",
					Enabled:  true,
					Metadata: config.CertMetadata{
						CertExpiresAt: time.Now().Add(3 * 24 * time.Hour),
					},
				},
			},
		},
		{
			name:      "7-13天过期",
			wantLevel: "WARN",
			certs: []config.CertConfig{
				{
					CertName: "warn-cert",
					Enabled:  true,
					Metadata: config.CertMetadata{
						CertExpiresAt: time.Now().Add(10 * 24 * time.Hour),
					},
				},
			},
		},
		{
			name:       "13天以上无告警",
			wantLevel:  "",
			wantAbsent: "warn-cert",
			certs: []config.CertConfig{
				{
					CertName: "ok-cert",
					Enabled:  true,
					Metadata: config.CertMetadata{
						CertExpiresAt: time.Now().Add(30 * 24 * time.Hour),
					},
				},
			},
		},
		{
			name:       "禁用证书跳过",
			wantLevel:  "",
			wantAbsent: "disabled-cert",
			certs: []config.CertConfig{
				{
					CertName: "disabled-cert",
					Enabled:  false,
					Metadata: config.CertMetadata{
						CertExpiresAt: time.Now().Add(1 * 24 * time.Hour),
					},
				},
			},
		},
		{
			// 到期时间未知不再静默跳过（原为告警盲区）：输出"到期时间未知" WARN
			name:      "CertExpiresAt零值输出未知告警",
			wantLevel: "WARN",
			certs: []config.CertConfig{
				{
					CertName: "zero-cert",
					Enabled:  true,
					Metadata: config.CertMetadata{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cm, err := config.NewConfigManagerWithDir(dir)
			if err != nil {
				t.Fatalf("创建配置管理器失败: %v", err)
			}

			cfg := &config.Config{
				Certificates: tt.certs,
			}
			writeTestConfig(t, dir, cfg)

			log, readLogs := captureLogger(t, dir)
			svc := NewService(cm, log)
			svc.CheckExpiry()

			output := readLogs()

			if tt.wantLevel == "ERROR" {
				if !strings.Contains(output, "[ERROR]") {
					t.Errorf("期望 ERROR 日志，实际输出:\n%s", output)
				}
			} else if tt.wantLevel == "WARN" {
				if !strings.Contains(output, "[WARN]") {
					t.Errorf("期望 WARN 日志，实际输出:\n%s", output)
				}
			}

			if tt.wantAbsent != "" && strings.Contains(output, tt.wantAbsent) {
				t.Errorf("不应出现 %q，实际输出:\n%s", tt.wantAbsent, output)
			}
		})
	}
}

// TestCheckExpiry_LoadFail 测试配置加载失败时不 panic
func TestCheckExpiry_LoadFail(t *testing.T) {
	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	// 写入无效 JSON
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("invalid json"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	log, readLogs := captureLogger(t, dir)
	svc := NewService(cm, log)

	// 不应 panic
	svc.CheckExpiry()

	output := readLogs()
	if !strings.Contains(output, "[WARN]") {
		t.Errorf("配置加载失败时应输出 WARN 日志，实际输出:\n%s", output)
	}
}

// TestCheckExpiry_ExpiredMessage 测试已过期证书输出"已过期 N 天"而非"剩余 -N 天"
func TestCheckExpiry_ExpiredMessage(t *testing.T) {
	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	cfg := &config.Config{
		Certificates: []config.CertConfig{
			{
				CertName: "long-expired",
				Enabled:  true,
				Metadata: config.CertMetadata{
					CertExpiresAt: time.Now().Add(-5 * 24 * time.Hour), // 过期 5 天
				},
			},
		},
	}
	writeTestConfig(t, dir, cfg)

	log, readLogs := captureLogger(t, dir)
	svc := NewService(cm, log)
	svc.CheckExpiry()

	output := readLogs()
	if !strings.Contains(output, "已过期") {
		t.Errorf("应输出'已过期'，实际输出:\n%s", output)
	}
	if strings.Contains(output, "剩余 -") {
		t.Errorf("不应出现'剩余 -'，实际输出:\n%s", output)
	}
}

// TestSyncOrderID 测试同步 API 返回的订单号到本地配置
func TestSyncOrderID(t *testing.T) {
	tests := []struct {
		name          string
		certOrderID   int
		certName      string
		apiOrderID    int
		wantOrderID   int
		wantCertName  string // 期望的 cert_name（fixCertName 可能修改）
		wantRenamed   bool   // 是否期望触发重命名
	}{
		{
			name:         "订单号变化时更新",
			certOrderID:  100,
			certName:     "example.com-100",
			apiOrderID:   200,
			wantOrderID:  200,
			wantCertName: "example.com-200",
			wantRenamed:  true,
		},
		{
			name:         "订单号为 0 时跳过不更新",
			certOrderID:  100,
			certName:     "example.com-100",
			apiOrderID:   0,
			wantOrderID:  100,
			wantCertName: "example.com-100",
			wantRenamed:  false,
		},
		{
			name:         "订单号相同时不更新",
			certOrderID:  100,
			certName:     "example.com-100",
			apiOrderID:   100,
			wantOrderID:  100,
			wantCertName: "example.com-100",
			wantRenamed:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cm, err := config.NewConfigManagerWithDir(dir)
			if err != nil {
				t.Fatalf("创建配置管理器失败: %v", err)
			}

			// 添加证书到配置
			origCert := &config.CertConfig{
				CertName: tt.certName,
				OrderID:  tt.certOrderID,
				Enabled:  true,
			}
			if err := cm.AddCert(origCert); err != nil {
				t.Fatalf("添加证书失败: %v", err)
			}

			log := logger.NewNopLogger()
			svc := NewService(cm, log)

			// 构造内存中的 cert（模拟从 GetCert 返回的深拷贝）
			cert := &config.CertConfig{
				CertName: tt.certName,
				OrderID:  tt.certOrderID,
				Enabled:  true,
			}

			certData := &fetcher.CertData{
				OrderID: tt.apiOrderID,
			}

			svc.syncOrderID(cert, certData)

			if cert.OrderID != tt.wantOrderID {
				t.Errorf("OrderID = %d, 期望 %d", cert.OrderID, tt.wantOrderID)
			}
			if cert.CertName != tt.wantCertName {
				t.Errorf("CertName = %s, 期望 %s", cert.CertName, tt.wantCertName)
			}
		})
	}
}

// TestFixCertName 测试修正 cert_name 中的订单号后缀
func TestFixCertName(t *testing.T) {
	tests := []struct {
		name        string
		certName    string
		orderID     int
		wantName    string
		wantRenamed bool
	}{
		{
			name:        "cert_name 不含 - 直接返回",
			certName:    "example.com",
			orderID:     123,
			wantName:    "example.com",
			wantRenamed: false,
		},
		{
			name:        "订单号需要修正",
			certName:    "example.com-100",
			orderID:     200,
			wantName:    "example.com-200",
			wantRenamed: true,
		},
		{
			name:        "订单号已正确不修改",
			certName:    "example.com-123",
			orderID:     123,
			wantName:    "example.com-123",
			wantRenamed: false,
		},
		{
			name:        "多个 - 时只修改最后一段",
			certName:    "sub-domain.example.com-100",
			orderID:     300,
			wantName:    "sub-domain.example.com-300",
			wantRenamed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cm, err := config.NewConfigManagerWithDir(dir)
			if err != nil {
				t.Fatalf("创建配置管理器失败: %v", err)
			}

			// 添加证书到配置（RenameCert 需要能找到旧名称）
			origCert := &config.CertConfig{
				CertName: tt.certName,
				OrderID:  tt.orderID,
				Enabled:  true,
			}
			if err := cm.AddCert(origCert); err != nil {
				t.Fatalf("添加证书失败: %v", err)
			}

			log := logger.NewNopLogger()
			svc := NewService(cm, log)

			cert := &config.CertConfig{
				CertName: tt.certName,
				OrderID:  tt.orderID,
				Enabled:  true,
			}

			svc.fixCertName(cert)

			if cert.CertName != tt.wantName {
				t.Errorf("CertName = %s, 期望 %s", cert.CertName, tt.wantName)
			}

			// 如果期望重命名，验证配置中的证书名已更新
			if tt.wantRenamed {
				// 旧名称应该找不到
				_, err := cm.GetCert(tt.certName)
				if err == nil {
					t.Error("旧名称应已不存在")
				}
				// 新名称应该能找到
				updated, err := cm.GetCert(tt.wantName)
				if err != nil {
					t.Errorf("新名称应能找到: %v", err)
				} else if updated.CertName != tt.wantName {
					t.Errorf("配置中的 CertName = %s, 期望 %s", updated.CertName, tt.wantName)
				}
			}
		})
	}
}

// TestFixCertName_RenameFail 测试重命名失败时不 panic
func TestFixCertName_RenameFail(t *testing.T) {
	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	// 不添加证书到配置，让 RenameCert 找不到旧名称而失败

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	cert := &config.CertConfig{
		CertName: "example.com-100",
		OrderID:  200,
		Enabled:  true,
	}

	// 不应 panic，只是记录 warn 日志
	svc.fixCertName(cert)

	// cert.CertName 仍然会被修改（内存中）
	if cert.CertName != "example.com-200" {
		t.Errorf("CertName = %s, 期望 example.com-200", cert.CertName)
	}
}

// TestPickKeyPath 测试选择私钥路径
func TestPickKeyPath(t *testing.T) {
	tests := []struct {
		name string
		cert config.CertConfig
		want string
	}{
		{
			name: "无绑定",
			cert: config.CertConfig{},
			want: "",
		},
		{
			name: "单个启用的绑定",
			cert: config.CertConfig{
				Bindings: []config.SiteBinding{
					{
						Enabled: true,
						Paths: config.BindingPaths{
							PrivateKey: "/path/to/key.pem",
						},
					},
				},
			},
			want: "/path/to/key.pem",
		},
		{
			name: "多个绑定，优先启用的",
			cert: config.CertConfig{
				Bindings: []config.SiteBinding{
					{
						Enabled: false,
						Paths: config.BindingPaths{
							PrivateKey: "/path/to/disabled.pem",
						},
					},
					{
						Enabled: true,
						Paths: config.BindingPaths{
							PrivateKey: "/path/to/enabled.pem",
						},
					},
				},
			},
			want: "/path/to/enabled.pem",
		},
		{
			name: "所有绑定禁用，使用第一个",
			cert: config.CertConfig{
				Bindings: []config.SiteBinding{
					{
						Enabled: false,
						Paths: config.BindingPaths{
							PrivateKey: "/path/to/first.pem",
						},
					},
					{
						Enabled: false,
						Paths: config.BindingPaths{
							PrivateKey: "/path/to/second.pem",
						},
					},
				},
			},
			want: "/path/to/first.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pickKeyPath(&tt.cert)
			if got != tt.want {
				t.Errorf("pickKeyPath() = %s, 期望 %s", got, tt.want)
			}
		})
	}
}

